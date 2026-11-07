//! Actual standalone standard Conversation record helper; no implicit worker.
#![forbid(unsafe_code)]
use std::{
    io::{self, Write},
    process::ExitCode,
};
fn main() -> ExitCode {
    if std::env::args_os().nth(1).is_some() {
        let _actual = writeln!(
            io::stderr().lock(),
            "gnunet-helper-audio-record takes no arguments"
        );
        return ExitCode::from(2);
    }
    #[cfg(unix)]
    let result = gnunet_conversation_audio_host::record(Default::default());
    #[cfg(not(unix))]
    {
        let _actual = writeln!(io::stderr().lock(), "Pulse profile requires Unix");
        return ExitCode::from(1);
    }
    #[cfg(unix)]
    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            let _actual = writeln!(io::stderr().lock(), "gnunet-helper-audio-record: {error}");
            ExitCode::from(1)
        }
    }
}
