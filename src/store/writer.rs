//! Bounded single-writer thread (guide §11.1 and §19 degradation policy).
//!
//! The daemon never touches SQLite on its sampling thread. Collectors submit
//! [`WriteItem`]s to a bounded channel; one thread batches them into transactions.
//! When the queue is full, low-priority records are dropped first and every drop is
//! counted, so reports can say evidence was lost instead of silently losing it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::model::WritePriority;

use super::{Store, WriteItem};

/// How long the writer waits before flushing a partially filled batch.
pub const FLUSH_INTERVAL: Duration = Duration::from_millis(200);
/// Maximum records accumulated into one transaction.
pub const MAX_BATCH_RECORDS: usize = 2048;
/// How long critical records may block the sampler while the queue is full.
pub const CRITICAL_BLOCK_LIMIT: Duration = Duration::from_millis(250);

/// A snapshot of writer counters for status output and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriterStats {
    /// Records submitted by producers.
    pub submitted: u64,
    /// Records committed to the database.
    pub persisted: u64,
    /// Low-priority records dropped because the queue was full.
    pub dropped_low: u64,
    /// Normal-priority records dropped after the queue stayed full.
    pub dropped_normal: u64,
    /// Transactions committed.
    pub batches: u64,
    /// Failed transactions/inserts.
    pub write_errors: u64,
    /// Highest observed queue depth in records.
    pub queue_high_water: u64,
    /// Current queue depth in records.
    pub queue_depth: u64,
}

#[derive(Debug, Default)]
struct Counters {
    submitted: AtomicU64,
    persisted: AtomicU64,
    dropped_low: AtomicU64,
    dropped_normal: AtomicU64,
    batches: AtomicU64,
    write_errors: AtomicU64,
    depth: AtomicU64,
    high_water: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> WriterStats {
        WriterStats {
            submitted: self.submitted.load(Ordering::Relaxed),
            persisted: self.persisted.load(Ordering::Relaxed),
            dropped_low: self.dropped_low.load(Ordering::Relaxed),
            dropped_normal: self.dropped_normal.load(Ordering::Relaxed),
            batches: self.batches.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
            queue_high_water: self.high_water.load(Ordering::Relaxed),
            queue_depth: self.depth.load(Ordering::Relaxed),
        }
    }
}

/// What happened to a submitted batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// All records were queued.
    Accepted,
    /// The batch lost records; the count is included in writer statistics.
    PartiallyDropped {
        /// Low-priority records dropped from this batch.
        low: u64,
        /// Normal-priority records dropped from this batch.
        normal: u64,
    },
    /// Nothing was queued (writer thread gone).
    WriterGone,
}

/// Bounded writer handle owned by the daemon.
pub struct Writer {
    tx: SyncSender<Message>,
    handle: Option<JoinHandle<()>>,
    counters: Arc<Counters>,
    capacity: u64,
}

enum Message {
    Batch(Vec<WriteItem>),
    Flush(SyncSender<()>),
    Shutdown(SyncSender<Result<()>>),
}

enum Enqueue {
    Queued,
    Full(Vec<WriteItem>),
    Gone,
}

impl std::fmt::Debug for Writer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Writer")
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl Writer {
    /// Spawn the writer thread with a queue bounded by `capacity` records.
    pub fn spawn(store: Store, capacity: usize) -> Result<Self> {
        let capacity = capacity.max(1);
        let (tx, rx) = mpsc::sync_channel(capacity);
        let counters = Arc::new(Counters::default());
        let thread_counters = Arc::clone(&counters);
        let handle = std::thread::Builder::new()
            .name("sarf-writer".to_string())
            .stack_size(256 * 1024)
            .spawn(move || writer_loop(store, rx, thread_counters))
            .map_err(|err| Error::Storage(format!("cannot spawn writer thread: {err}")))?;
        Ok(Self {
            tx,
            handle: Some(handle),
            counters,
            capacity: capacity as u64,
        })
    }

    /// Submit a batch of records, applying the documented drop policy on overflow.
    ///
    /// Degradation order (guide §19): low-priority records are dropped first, then
    /// normal records; critical records are preserved with a bounded wait.
    pub fn submit(&self, items: Vec<WriteItem>) -> SubmitOutcome {
        if items.is_empty() {
            return SubmitOutcome::Accepted;
        }
        let submitted = items.len() as u64;
        self.counters
            .submitted
            .fetch_add(submitted, Ordering::Relaxed);

        let mut dropped_low = 0u64;
        let mut dropped_normal = 0u64;
        let mut items = items;

        // Attempt 1: enqueue as-is.
        match self.enqueue(items) {
            Enqueue::Queued => {
                self.note_high_water();
                return SubmitOutcome::Accepted;
            }
            Enqueue::Gone => {
                self.counters
                    .dropped_normal
                    .fetch_add(submitted, Ordering::Relaxed);
                return SubmitOutcome::WriterGone;
            }
            Enqueue::Full(back) => {
                // Attempt 2: drop low-priority records only.
                let (keep, dropped) = split_by_priority(back, WritePriority::Normal);
                dropped_low += dropped;
                items = keep;
            }
        }

        if !items.is_empty() {
            let kept = items.len() as u64;
            match self.enqueue(items) {
                Enqueue::Queued => {
                    self.counters
                        .dropped_low
                        .fetch_add(dropped_low, Ordering::Relaxed);
                    self.note_high_water();
                    return SubmitOutcome::PartiallyDropped {
                        low: dropped_low,
                        normal: 0,
                    };
                }
                Enqueue::Gone => {
                    self.counters
                        .dropped_normal
                        .fetch_add(kept + dropped_low, Ordering::Relaxed);
                    return SubmitOutcome::WriterGone;
                }
                Enqueue::Full(back) => {
                    // Attempt 3: keep critical records only.
                    let (keep, dropped) = split_by_priority(back, WritePriority::Critical);
                    dropped_normal += dropped;
                    items = keep;
                }
            }
        }

        if !items.is_empty() {
            let deadline = Instant::now() + CRITICAL_BLOCK_LIMIT;
            let mut items = items;
            loop {
                match self.enqueue(items) {
                    Enqueue::Queued => {
                        self.counters
                            .dropped_low
                            .fetch_add(dropped_low, Ordering::Relaxed);
                        self.counters
                            .dropped_normal
                            .fetch_add(dropped_normal, Ordering::Relaxed);
                        self.note_high_water();
                        return SubmitOutcome::PartiallyDropped {
                            low: dropped_low,
                            normal: dropped_normal,
                        };
                    }
                    Enqueue::Gone => {
                        self.counters
                            .dropped_normal
                            .fetch_add(dropped_normal + dropped_low, Ordering::Relaxed);
                        return SubmitOutcome::WriterGone;
                    }
                    Enqueue::Full(back) => {
                        items = back;
                        if Instant::now() >= deadline {
                            let lost = items.len() as u64;
                            self.counters
                                .dropped_normal
                                .fetch_add(lost + dropped_normal, Ordering::Relaxed);
                            self.counters
                                .dropped_low
                                .fetch_add(dropped_low, Ordering::Relaxed);
                            return SubmitOutcome::PartiallyDropped {
                                low: dropped_low,
                                normal: lost + dropped_normal,
                            };
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                }
            }
        }

        // Everything was low priority and has been dropped.
        self.counters
            .dropped_low
            .fetch_add(dropped_low, Ordering::Relaxed);
        self.counters
            .dropped_normal
            .fetch_add(dropped_normal, Ordering::Relaxed);
        SubmitOutcome::PartiallyDropped {
            low: dropped_low,
            normal: dropped_normal,
        }
    }

    fn enqueue(&self, items: Vec<WriteItem>) -> Enqueue {
        let count = items.len() as u64;
        if !self.reserve(count) {
            return Enqueue::Full(items);
        }
        match self.tx.try_send(Message::Batch(items)) {
            Ok(()) => Enqueue::Queued,
            Err(TrySendError::Full(Message::Batch(back))) => {
                self.release(back.len() as u64);
                Enqueue::Full(back)
            }
            Err(TrySendError::Disconnected(Message::Batch(back))) => {
                self.release(back.len() as u64);
                Enqueue::Gone
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                unreachable!("only batches are submitted")
            }
        }
    }

    /// Reserve queue capacity in records, not messages.
    ///
    /// A batch can contain many records; without this reservation a single large
    /// submit would bypass the documented queue bound.
    fn reserve(&self, count: u64) -> bool {
        let mut current = self.counters.depth.load(Ordering::Relaxed);
        loop {
            if current.saturating_add(count) > self.capacity {
                return false;
            }
            match self.counters.depth.compare_exchange_weak(
                current,
                current + count,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    fn release(&self, count: u64) {
        if count > 0 {
            self.counters.depth.fetch_sub(count, Ordering::Relaxed);
        }
    }

    fn note_high_water(&self) {
        let depth = self.counters.depth.load(Ordering::Relaxed);
        let mut previous = self.counters.high_water.load(Ordering::Relaxed);
        while depth > previous {
            match self.counters.high_water.compare_exchange_weak(
                previous,
                depth,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => previous = observed,
            }
        }
    }

    /// Ask the writer to commit everything submitted so far and wait for it.
    pub fn flush(&self) -> Result<()> {
        let (ack_tx, ack_rx) = mpsc::sync_channel(0);
        self.tx
            .send(Message::Flush(ack_tx))
            .map_err(|_| Error::Storage("writer thread is gone".into()))?;
        ack_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| Error::Storage("writer flush timed out".into()))
    }

    /// Current counters.
    pub fn stats(&self) -> WriterStats {
        self.counters.snapshot()
    }

    /// Stop the writer, commit pending records and return final statistics.
    pub fn shutdown(mut self) -> Result<WriterStats> {
        let (ack_tx, ack_rx) = mpsc::sync_channel(0);
        let result = if self.tx.send(Message::Shutdown(ack_tx)).is_ok() {
            ack_rx
                .recv_timeout(Duration::from_secs(30))
                .unwrap_or_else(|_| Err(Error::Storage("writer shutdown timed out".into())))
        } else {
            Ok(())
        };
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        result.map(|()| self.counters.snapshot())
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        // Best-effort graceful shutdown if the daemon forgot to call `shutdown`.
        let (ack_tx, _ack_rx) = mpsc::sync_channel(0);
        let _ = self.tx.send(Message::Shutdown(ack_tx));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Split a batch by priority threshold: keep records with priority `>= keep_at`,
/// count the rest as dropped.
fn split_by_priority(items: Vec<WriteItem>, keep_at: WritePriority) -> (Vec<WriteItem>, u64) {
    let mut keep = Vec::with_capacity(items.len());
    let mut dropped = 0u64;
    for item in items {
        if item.priority >= keep_at {
            keep.push(item);
        } else {
            dropped += 1;
        }
    }
    (keep, dropped)
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the writer thread takes ownership of its Store and the shared counters; \
              both must live for the whole thread, so borrowing is impossible"
)]
fn writer_loop(mut store: Store, rx: Receiver<Message>, counters: Arc<Counters>) {
    let mut pending: Vec<WriteItem> = Vec::with_capacity(MAX_BATCH_RECORDS);
    loop {
        match rx.recv_timeout(FLUSH_INTERVAL) {
            Ok(Message::Batch(items)) => {
                pending.extend(items);
                if pending.len() >= MAX_BATCH_RECORDS {
                    commit(&mut store, &mut pending, &counters);
                }
            }
            Ok(Message::Flush(ack)) => {
                commit(&mut store, &mut pending, &counters);
                let _ = ack.send(());
            }
            Ok(Message::Shutdown(ack)) => {
                commit(&mut store, &mut pending, &counters);
                let _ = ack.send(Ok(()));
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !pending.is_empty() {
                    commit(&mut store, &mut pending, &counters);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                commit(&mut store, &mut pending, &counters);
                return;
            }
        }
    }
}

fn commit(store: &mut Store, pending: &mut Vec<WriteItem>, counters: &Counters) {
    if pending.is_empty() {
        return;
    }
    let records = pending.len() as u64;
    match store.write(pending) {
        Ok(written) => {
            counters
                .persisted
                .fetch_add(written as u64, Ordering::Relaxed);
            counters.batches.fetch_add(1, Ordering::Relaxed);
        }
        Err(_) => {
            counters.write_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
    counters.depth.fetch_sub(records, Ordering::Relaxed);
    pending.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Store, WriteItem, WriteRecord};

    fn meta(key: &str) -> WriteItem {
        WriteItem::normal(WriteRecord::Meta {
            key: key.to_string(),
            value: "v".to_string(),
        })
    }

    #[test]
    fn priority_drop_keeps_higher_priorities() {
        let items = vec![
            WriteItem::low(WriteRecord::Meta {
                key: "a".into(),
                value: "v".into(),
            }),
            WriteItem::normal(WriteRecord::Meta {
                key: "b".into(),
                value: "v".into(),
            }),
            WriteItem::critical(WriteRecord::Meta {
                key: "c".into(),
                value: "v".into(),
            }),
        ];
        let (keep, dropped) = split_by_priority(items, WritePriority::Normal);
        assert_eq!(keep.len(), 2, "normal+critical kept");
        assert_eq!(dropped, 1, "low dropped");
        assert!(keep
            .iter()
            .all(|item| item.priority >= WritePriority::Normal));

        let items = vec![
            WriteItem::normal(WriteRecord::Meta {
                key: "b".into(),
                value: "v".into(),
            }),
            WriteItem::critical(WriteRecord::Meta {
                key: "c".into(),
                value: "v".into(),
            }),
        ];
        let (keep, dropped) = split_by_priority(items, WritePriority::Critical);
        assert_eq!(keep.len(), 1);
        assert_eq!(dropped, 1);
    }

    #[test]
    fn writer_persists_submitted_batches() {
        let store = Store::open_in_memory().expect("store");
        let writer = Writer::spawn(store, 64).expect("writer");
        for index in 0..10 {
            writer.submit(vec![meta(&format!("k{index}"))]);
        }
        writer.flush().expect("flush");
        let stats = writer.stats();
        assert_eq!(stats.submitted, 10);
        assert_eq!(stats.persisted, 10);
        assert_eq!(stats.dropped_low, 0);
        assert_eq!(stats.write_errors, 0);
        assert!(stats.batches >= 1);
        let final_stats = writer.shutdown().expect("shutdown");
        assert_eq!(final_stats.persisted, 10);
    }

    #[test]
    fn empty_submissions_are_ignored() {
        let writer = Writer::spawn(Store::open_in_memory().expect("store"), 4).expect("writer");
        assert_eq!(writer.submit(vec![]), SubmitOutcome::Accepted);
        assert_eq!(writer.stats().submitted, 0);
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn shutdown_flushes_without_explicit_flush() {
        let store = Store::open_in_memory().expect("store");
        let writer = Writer::spawn(store, 8).expect("writer");
        for index in 0..5 {
            writer.submit(vec![meta(&format!("k{index}"))]);
        }
        let stats = writer.shutdown().expect("shutdown");
        assert_eq!(stats.persisted, 5);
    }

    #[test]
    fn queue_high_water_tracks_depth() {
        let writer = Writer::spawn(Store::open_in_memory().expect("store"), 64).expect("writer");
        for index in 0..20 {
            writer.submit(vec![meta(&format!("k{index}"))]);
        }
        let stats = writer.stats();
        assert_eq!(stats.queue_depth, 20);
        assert_eq!(stats.queue_high_water, 20);
        writer.flush().expect("flush");
        assert_eq!(writer.stats().queue_depth, 0);
        writer.shutdown().expect("shutdown");
    }
}
