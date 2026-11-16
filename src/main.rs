//! SARF command-line entry point.

use std::process::ExitCode;

fn main() -> ExitCode {
    // `println!` panics when a downstream consumer closes the pipe (for example
    // `sarf status | head`). Closing early is normal for CLI tools, so exit cleanly
    // instead of printing a panic. All other panics keep the default hook.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let broken_pipe = info
            .payload()
            .downcast_ref::<String>()
            .is_some_and(|message| message.contains("Broken pipe"))
            || info
                .payload()
                .downcast_ref::<&str>()
                .is_some_and(|message| message.contains("Broken pipe"));
        if broken_pipe {
            std::process::exit(0);
        }
        previous(info);
    }));
    match sarf::commands::main() {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(err) => {
            eprintln!("sarf: {err}");
            ExitCode::from(1)
        }
    }
}
