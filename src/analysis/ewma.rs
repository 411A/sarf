//! Exponentially weighted mean/variance tracker used as a relative baseline.
//!
//! The tracker follows the guide (§10.2) formulas:
//!
//! ```text
//! variance = alpha * (x - old_mean)^2 + (1 - alpha) * variance
//! mean     = alpha * x + (1 - alpha) * old_mean
//! z        = (x - mean) / sqrt(variance + epsilon)
//! ```
//!
//! The deviation is taken from the *prior* mean and the z-score is reported
//! against the updated mean, which is the numerically stable ordering. The
//! tracker is startup-aware: it emits no z-score until it has seen enough samples,
//! and it ignores non-finite input instead of letting one `NaN` poison the state.
//! A z-score is an observation of relative change; it is not evidence of a cause.

/// Default smoothing factor when the caller supplies an invalid alpha.
const DEFAULT_ALPHA: f64 = 0.2;
/// Number of samples required before z-scores are reported.
const MIN_WARMUP_SAMPLES: u64 = 5;
/// Added under the square root so a zero variance cannot divide by zero.
const VARIANCE_EPSILON: f64 = 1e-9;
/// Magnitudes below this are treated as numerical noise around zero.
const NEAR_ZERO: f64 = 1e-6;

/// EWMA mean/variance tracker (numerically stable, startup-aware).
///
/// One tracker belongs to exactly one entity/metric pair. Values must be in the
/// metric's natural unit (percent of one core, bytes, load), because the tracker
/// never rescales and the z-score is only meaningful inside that unit.
#[derive(Debug, Clone)]
pub struct Ewma {
    /// Smoothing factor in `(0, 1]`.
    alpha: f64,
    /// Current weighted mean.
    mean: f64,
    /// Current weighted variance.
    variance: f64,
    /// Number of accepted (finite) observations.
    samples: u64,
    /// Samples required before [`Ewma::is_warmed_up`] is true.
    warmup: u64,
}

impl Ewma {
    /// Create a tracker with the given smoothing factor.
    ///
    /// `alpha` is clamped to `(0, 1]`; a non-finite or out-of-range value falls
    /// back to `0.2` so a misconfigured caller cannot silently disable smoothing.
    pub fn new(alpha: f64) -> Self {
        let alpha = if alpha.is_finite() && alpha > 0.0 && alpha <= 1.0 {
            alpha
        } else {
            DEFAULT_ALPHA
        };
        Self {
            alpha,
            mean: 0.0,
            variance: 0.0,
            samples: 0,
            warmup: MIN_WARMUP_SAMPLES,
        }
    }

    /// Feed one observation and return its z-score once the tracker is warmed up.
    ///
    /// The first accepted value initializes the mean. Non-finite values are
    /// ignored: they neither advance the sample count nor change the state, and
    /// `None` is returned. A warm tracker returns `None` instead of an infinite or
    /// `NaN` z-score when both the mean and the observation are numerically zero.
    pub fn update(&mut self, value: f64) -> Option<f64> {
        if !value.is_finite() {
            return None;
        }
        if self.samples == 0 {
            self.mean = value;
            self.variance = 0.0;
            self.samples = 1;
            return None;
        }
        let old_mean = self.mean;
        let deviation = value - old_mean;
        self.variance =
            (1.0 - self.alpha).mul_add(self.variance, self.alpha * deviation * deviation);
        self.mean = (1.0 - self.alpha).mul_add(old_mean, self.alpha * value);
        self.samples = self.samples.saturating_add(1);
        if !self.is_warmed_up() {
            return None;
        }
        Self::z_score(value, self.mean, self.variance)
    }

    /// Current weighted mean (zero before the first observation).
    pub const fn mean(&self) -> f64 {
        self.mean
    }

    /// Current weighted variance (zero before the first observation).
    pub const fn variance(&self) -> f64 {
        self.variance
    }

    /// Square root of the weighted variance, never negative.
    pub fn stddev(&self) -> f64 {
        self.variance.max(0.0).sqrt()
    }

    /// Number of accepted observations.
    pub const fn samples(&self) -> u64 {
        self.samples
    }

    /// Whether enough observations were seen to trust a z-score.
    pub const fn is_warmed_up(&self) -> bool {
        self.samples >= self.warmup
    }

    /// Compute the z-score of `value` without changing the tracker.
    ///
    /// Returns `None` before warmup and suppresses the noisy case where both the
    /// baseline and the observation are near zero.
    pub fn value_of(&self, value: f64) -> Option<f64> {
        if !self.is_warmed_up() {
            return None;
        }
        Self::z_score(value, self.mean, self.variance)
    }

    /// Forget all observations and return to the startup state.
    pub const fn reset(&mut self) {
        self.mean = 0.0;
        self.variance = 0.0;
        self.samples = 0;
    }

    /// Guarded z-score computation shared by [`Ewma::update`] and [`Ewma::value_of`].
    fn z_score(value: f64, mean: f64, variance: f64) -> Option<f64> {
        if !value.is_finite() || !mean.is_finite() || !variance.is_finite() {
            return None;
        }
        // A near-zero baseline makes relative ratios noisy; report nothing instead.
        if mean.abs() < NEAR_ZERO && value.abs() < NEAR_ZERO {
            return None;
        }
        let denominator = (variance.max(0.0) + VARIANCE_EPSILON).sqrt();
        if !denominator.is_finite() || denominator <= 0.0 {
            return None;
        }
        let z = (value - mean) / denominator;
        z.is_finite().then_some(z)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_returns_none_until_warmed_up() {
        let mut ewma = Ewma::new(0.2);
        for expected_samples in 1..MIN_WARMUP_SAMPLES {
            assert_eq!(ewma.update(10.0), None);
            assert_eq!(ewma.samples(), expected_samples);
            assert!(!ewma.is_warmed_up());
        }
        assert!(ewma.update(10.0).is_some());
        assert!(ewma.is_warmed_up());
        assert_eq!(ewma.samples(), MIN_WARMUP_SAMPLES);
    }

    #[test]
    fn constant_series_has_zero_variance_and_finite_z() {
        let mut ewma = Ewma::new(0.3);
        let mut last = None;
        for _ in 0..20 {
            last = ewma.update(42.0);
        }
        assert_eq!(ewma.mean(), 42.0);
        assert!(ewma.variance() < 1e-12);
        assert_eq!(ewma.stddev(), 0.0);
        let z = last.expect("warm z-score");
        assert_eq!(z, 0.0);
        assert!(z.is_finite());
    }

    #[test]
    fn step_change_is_detected_but_smoothed_by_the_update_rule() {
        let mut ewma = Ewma::new(0.2);
        for _ in 0..20 {
            ewma.update(10.0);
        }
        // Scored against the established baseline (no smoothing) the step is huge.
        let raw = ewma.value_of(100.0).expect("baseline deviation");
        assert!(raw > 1_000_000.0, "expected a large deviation, got {raw}");
        let z = ewma.update(100.0).expect("warm z-score");
        // The guide's update rule uses the prior mean for the variance but scores the
        // observation against the updated mean, so a single step is deliberately
        // smoothed. With a zero prior variance the score is exactly
        // (1 - alpha) * d / sqrt(alpha * d^2), i.e. (1 - alpha) / sqrt(alpha) = 1.7889
        // for alpha = 0.2. The test pins that mathematical value instead of pretending
        // the smoothing does not exist.
        assert!((z - 1.788_854_381_999_279_7).abs() < 1e-6, "got {z}");
        assert!(z.is_finite() && z > 1.5);
        assert!((ewma.mean() - 28.0).abs() < 1e-9, "mean {}", ewma.mean());
        assert!(
            (ewma.variance() - 1620.0).abs() < 1e-6,
            "variance {}",
            ewma.variance()
        );
    }

    #[test]
    fn alpha_is_clamped_to_a_sane_range() {
        assert_eq!(Ewma::new(0.0).alpha, DEFAULT_ALPHA);
        assert_eq!(Ewma::new(-0.5).alpha, DEFAULT_ALPHA);
        assert_eq!(Ewma::new(1.5).alpha, DEFAULT_ALPHA);
        assert_eq!(Ewma::new(f64::NAN).alpha, DEFAULT_ALPHA);
        assert_eq!(Ewma::new(f64::INFINITY).alpha, DEFAULT_ALPHA);
        assert_eq!(Ewma::new(1.0).alpha, 1.0);
        assert_eq!(Ewma::new(0.05).alpha, 0.05);
    }

    #[test]
    fn reset_returns_to_the_startup_state() {
        let mut ewma = Ewma::new(0.2);
        for value in [1.0, 2.0, 3.0, 4.0, 5.0, 6.0] {
            ewma.update(value);
        }
        assert!(ewma.is_warmed_up());
        ewma.reset();
        assert_eq!(ewma.samples(), 0);
        assert_eq!(ewma.mean(), 0.0);
        assert_eq!(ewma.variance(), 0.0);
        assert!(!ewma.is_warmed_up());
        assert_eq!(ewma.update(7.0), None, "fresh tracker restarts warmup");
    }

    #[test]
    fn non_finite_input_never_poisons_the_state() {
        let mut ewma = Ewma::new(0.2);
        for _ in 0..6 {
            ewma.update(10.0);
        }
        let samples = ewma.samples();
        let mean = ewma.mean();
        assert_eq!(ewma.update(f64::NAN), None);
        assert_eq!(ewma.update(f64::INFINITY), None);
        assert_eq!(ewma.update(f64::NEG_INFINITY), None);
        assert_eq!(ewma.samples(), samples);
        assert_eq!(ewma.mean(), mean);
        assert!(ewma.mean().is_finite() && ewma.variance().is_finite());
    }

    #[test]
    fn value_of_does_not_mutate_and_requires_warmup() {
        let mut ewma = Ewma::new(0.2);
        for _ in 0..4 {
            ewma.update(10.0);
        }
        assert_eq!(ewma.value_of(10.0), None, "not warmed up yet");
        for _ in 0..4 {
            ewma.update(10.0);
        }
        let samples = ewma.samples();
        let value = ewma.value_of(20.0).expect("warm z-score");
        assert!(value > 0.0 && value.is_finite());
        assert_eq!(ewma.samples(), samples, "value_of must not mutate");
        assert_eq!(ewma.value_of(f64::NAN), None);
    }

    #[test]
    fn near_zero_baseline_is_suppressed() {
        let mut ewma = Ewma::new(0.2);
        for _ in 0..10 {
            ewma.update(0.0);
        }
        assert_eq!(ewma.update(0.0), None, "zero/zero ratio is not meaningful");
        assert!(ewma.value_of(0.0).is_none());
        // A real observation from a zero baseline is still reportable.
        let z = ewma.update(1.0).expect("non-zero observation");
        assert!(z.is_finite() && z > 0.0);
    }
}
