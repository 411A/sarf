//! SARF command-line entry point.

fn main() -> std::process::ExitCode {
    // The real CLI is installed by `src/cli.rs`; until then, keep the binary
    // honest about its state rather than pretending to work.
    println!(
        "{} {} — {} (foundation build)",
        sarf::PRODUCT,
        sarf::VERSION,
        sarf::PRODUCT_LONG
    );
    std::process::ExitCode::SUCCESS
}
