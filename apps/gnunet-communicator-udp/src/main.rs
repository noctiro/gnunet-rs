//! Official UDP PROGRAM entry point.
#![deny(unsafe_code)]

mod control;
mod early;
mod identity;
mod program;

type Cause = Box<dyn std::error::Error>;

fn main() -> std::process::ExitCode {
    program::main()
}
