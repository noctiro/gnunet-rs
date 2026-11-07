//! Official two-input configuration diff rewrite command.
#![forbid(unsafe_code)]
use gnunet_config::{Configuration, Limits, ProjectData};
use std::{
    io::{self, Write},
    path::Path,
    process::ExitCode,
    sync::Arc,
};
fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments.len() != 3 {
        let mut stderr = io::stderr().lock();
        let printed = stderr
            .write_all(b"Invoke using `")
            .and_then(|()| {
                stderr.write_all(
                    arguments
                        .first()
                        .map(|s| s.as_encoded_bytes())
                        .unwrap_or(b"gnunet-config-diff"),
                )
            })
            .and_then(|()| stderr.write_all(b" DEFAULTS-IN DIFFS'\n"));
        match printed {
            Ok(()) | Err(_) => {}
        }
        return ExitCode::FAILURE;
    }
    let project = Arc::new(ProjectData::default());
    let loaded = (|| {
        let mut defaults = Configuration::create(Arc::clone(&project), Limits::default())?;
        let mut changed = Configuration::create(project, Limits::default())?;
        defaults.load(Some(Path::new(&arguments[1])))?;
        changed.load(Some(Path::new(&arguments[2])))?;
        Ok::<_, gnunet_config::Error>((defaults, changed))
    })();
    let Ok((defaults, changed)) = loaded else {
        return ExitCode::FAILURE;
    };
    if defaults
        .write_diffs(&changed, Path::new(&arguments[2]))
        .is_err()
    {
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}
