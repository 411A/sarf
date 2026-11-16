//! SARF command-line entry point.

use std::process::ExitCode;

fn main() -> ExitCode {
    match sarf::commands::main() {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(err) => {
            eprintln!("sarf: {err}");
            ExitCode::from(1)
        }
    }
}
