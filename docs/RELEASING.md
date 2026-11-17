# Releasing SARF

The release pipeline produces **static musl binaries** and attaches them to a
GitHub Release. Operators download one file and run `sarf install`; no repository
checkout, build toolchain or separate installer script is needed.

CI and the release workflow pin Rust `1.100.0` so a new stable Clippy release
cannot turn an unrelated push red. Bump that version deliberately, run the full
verification, and keep `rust-version` in `Cargo.toml` as the source-compatibility
floor.

## Cutting a release

1. Update `version` in `Cargo.toml` and commit it.
2. Create and push a matching tag:

   ```bash
   git tag v0.1.12
   git push origin v0.1.12
   ```

3. `.github/workflows/release.yml` checks that the tag matches `Cargo.toml`, then
   builds:

   | Asset | Target |
   |---|---|
   | `sarf-x86_64-unknown-linux-musl` | x86_64 Linux, static musl |
   | `sarf-aarch64-unknown-linux-musl` | ARM64 Linux, static musl |

   It also publishes `SHA256SUMS` and, for public repositories, a build provenance
   attestation. A binary larger than 20 MiB fails the release job.

4. The workflow creates (or updates) the GitHub Release with generated notes.

`workflow_dispatch` runs the build without publishing, which is useful for
validating the pipeline before tagging.

## Local reproduction

The release profile is `dist` (fat LTO, `opt-level = "z"`, stripped):

```bash
rustup target add x86_64-unknown-linux-musl
sudo apt-get install musl-tools
CC=musl-gcc RUSTFLAGS="-C linker=musl-gcc" \
  cargo build --locked --profile dist --target x86_64-unknown-linux-musl
file target/x86_64-unknown-linux-musl/dist/sarf
```

The binary must be statically linked. Normal `cargo build --release` keeps the
faster thin-LTO profile used by the test/perf pyramid.

## Installing or upgrading on a VPS

```bash
curl -fsSL -o sarf \
  https://github.com/411A/sarf/releases/latest/download/sarf-x86_64-unknown-linux-musl
chmod +x sarf
sudo ./sarf install --docker-group --start
sudo sarf doctor --data-dir /var/lib/sarf
```

The same command upgrades an existing installation: it replaces the binary,
re-applies the systemd unit, refreshes Docker group membership when requested, and
restarts the service on `--start`. Data and configuration in `/var/lib/sarf` are
preserved.

Useful flags:

| Flag | Effect |
|---|---|
| `--docker-group` | Add the service user to `docker` and `SupplementaryGroups=docker` (root-equivalent) |
| `--start` | Enable and start `sarf.service` after installing |
| `--prefix PATH` | Binary prefix, default `/usr/local` |
| `--user NAME` | Service user/group, default `sarf` |
| `--data-dir PATH` | Global data directory, default `/var/lib/sarf` |
| `--no-systemd` | Install the binary/account/data only |

## Why musl

A static musl build has no glibc version dependency, so the same binary runs on
current and older VPS distributions. SQLite is compiled in (`rusqlite` bundled), so
there is no system `libsqlite3` requirement either.
