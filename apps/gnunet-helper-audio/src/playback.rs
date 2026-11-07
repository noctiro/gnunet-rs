//! Actual standalone standard Conversation playback helper; no implicit worker.
#![forbid(unsafe_code)]
use std::{
    io::{self, Write},
    process::ExitCode,
};
fn main() -> ExitCode {
    if std::env::args_os().nth(1).is_some() {
        let _actual = writeln!(
            io::stderr().lock(),
            "gnunet-helper-audio-playback takes no arguments"
        );
        return ExitCode::from(2);
    }
    #[cfg(unix)]
    let result = gnunet_conversation_audio_host::playback(Default::default());
    #[cfg(not(unix))]
    {
        let _actual = writeln!(io::stderr().lock(), "Pulse profile requires Unix");
        return ExitCode::from(1);
    }
    #[cfg(unix)]
    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            let _actual = writeln!(io::stderr().lock(), "gnunet-helper-audio-playback: {error}");
            ExitCode::from(1)
        }
    }
}
