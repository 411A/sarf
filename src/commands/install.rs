//! System-wide install/update from the release binary.
//!
//! The installer logic lives in `scripts/install.sh` so the repository script and
//! the embedded release-binary path cannot drift. The binary passes its own path,
//! the embedded systemd unit and the user's options to that script through stdin.

#[cfg(unix)]
use std::fs::{self, OpenOptions};
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::InstallArgs;
use crate::error::{Error, Result};

#[cfg(unix)]
const INSTALLER: &str = include_str!("../../scripts/install.sh");
#[cfg(unix)]
const UNIT: &str = include_str!("../../deploy/sarf.service");
#[cfg(unix)]
const DEFAULT_DATA_DIR: &str = "/var/lib/sarf";

/// Install or update the system-wide service.
///
/// The system data directory defaults to `/var/lib/sarf`; an explicit global
/// `--data-dir` overrides it. The embedded installer is idempotent and also
/// re-applies Docker group membership and unit changes on an existing install.
#[cfg(unix)]
pub fn install(args: &InstallArgs, data_dir: Option<&Path>) -> Result<i32> {
    let exe = std::env::current_exe()
        .map_err(|err| Error::Config(format!("cannot resolve the current sarf binary: {err}")))?;
    let data_dir = data_dir
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("SARF_DATA_DIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));
    let data_dir = data_dir.as_path();
    let unit_path = temp_unit_path();
    write_unit(&unit_path)?;

    let result = run_installer(&exe, data_dir, &unit_path, args);
    let _ = fs::remove_file(&unit_path);
    result?;
    Ok(0)
}

/// `sarf install` is Linux-only; keep a typed, actionable error on Windows/macOS.
#[cfg(not(unix))]
pub fn install(_args: &InstallArgs, _data_dir: Option<&std::path::Path>) -> Result<i32> {
    Err(Error::unavailable(
        "install",
        "system-wide install is supported on Linux only",
    ))
}

#[cfg(unix)]
fn temp_unit_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!(
        "sarf-install-{}-{nanos}.service",
        std::process::id()
    ))
}

#[cfg(unix)]
fn write_unit(path: &Path) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| Error::io(path, err))?;
    file.write_all(UNIT.as_bytes())
        .map_err(|err| Error::io(path, err))?;
    file.sync_all().map_err(|err| Error::io(path, err))
}

#[cfg(unix)]
fn run_installer(exe: &Path, data_dir: &Path, unit_path: &Path, args: &InstallArgs) -> Result<()> {
    let mut child = Command::new("sh")
        .args(installer_arguments(exe, data_dir, unit_path, args))
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|err| Error::Config(format!("cannot start the installer shell: {err}")))?;

    if let Some(mut stdin) = child.stdin.take() {
        if let Err(err) = stdin.write_all(INSTALLER.as_bytes()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Config(format!("cannot feed the installer: {err}")));
        }
    }

    let status = child
        .wait()
        .map_err(|err| Error::Config(format!("installer did not finish: {err}")))?;
    if !status.success() {
        return Err(Error::Config(
            "system install failed; see the installer messages above".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn installer_arguments(
    exe: &Path,
    data_dir: &Path,
    unit_path: &Path,
    args: &InstallArgs,
) -> Vec<std::ffi::OsString> {
    let mut argv: Vec<std::ffi::OsString> =
        ["-s", "--"].iter().map(std::ffi::OsString::from).collect();
    for (flag, value) in [
        ("--binary", exe.as_os_str()),
        ("--prefix", args.prefix.as_os_str()),
        ("--data-dir", data_dir.as_os_str()),
        ("--user", std::ffi::OsStr::new(&args.user)),
        ("--unit", unit_path.as_os_str()),
    ] {
        argv.push(std::ffi::OsString::from(flag));
        argv.push(value.to_owned());
    }
    if args.docker_group {
        argv.push(std::ffi::OsString::from("--docker-group"));
    }
    if args.start {
        argv.push(std::ffi::OsString::from("--start"));
    }
    if args.no_systemd {
        argv.push(std::ffi::OsString::from("--no-systemd"));
    }
    argv
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn args(docker_group: bool, start: bool, no_systemd: bool) -> InstallArgs {
        InstallArgs {
            prefix: PathBuf::from("/opt/sarf"),
            user: "sarf".to_string(),
            docker_group,
            start,
            no_systemd,
        }
    }

    #[test]
    fn installer_arguments_map_options_to_the_script() {
        let argv = installer_arguments(
            Path::new("/tmp/sarf"),
            Path::new("/srv/sarf"),
            Path::new("/tmp/unit.service"),
            &args(true, true, false),
        );
        let text: Vec<String> = argv
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        assert_eq!(&text[..2], ["-s", "--"]);
        assert!(text.contains(&"--docker-group".to_string()));
        assert!(text.contains(&"--start".to_string()));
        assert!(!text.contains(&"--no-systemd".to_string()));
        for (flag, value) in [
            ("--binary", "/tmp/sarf"),
            ("--prefix", "/opt/sarf"),
            ("--data-dir", "/srv/sarf"),
            ("--user", "sarf"),
            ("--unit", "/tmp/unit.service"),
        ] {
            assert!(
                text.windows(2)
                    .any(|pair| pair[0] == flag && pair[1] == value),
                "missing {flag} {value}: {text:?}"
            );
        }
    }

    #[test]
    fn installer_arguments_can_disable_systemd() {
        let argv = installer_arguments(
            Path::new("/tmp/sarf"),
            Path::new("/srv/sarf"),
            Path::new("/tmp/unit.service"),
            &args(false, false, true),
        );
        let text: Vec<String> = argv
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        assert!(text.contains(&"--no-systemd".to_string()));
        assert!(!text.contains(&"--docker-group".to_string()));
        assert!(!text.contains(&"--start".to_string()));
    }
}
