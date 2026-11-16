//! Windows startup probe over actual token SIDs and private process pipes.
use gnunet_config::{Configuration, ProjectData};
use gnunet_service_startup::{ReadyStatus, capture_from_environment, verify_configured_identity};
use std::{
    error::Error,
    future::poll_fn,
    io::{self, Write},
    process::ExitCode,
    sync::Arc,
};

fn run() -> Result<(), Box<dyn Error>> {
    #[expect(
        unsafe_code,
        reason = "First fresh-process operation before files/runtime/native ownership; inherited metadata is exclusively offered"
    )]
    // SAFETY: no competing owner exists; failure exits this probe.
    let captured = unsafe { capture_from_environment() }?;
    if let Some(incoming) = captured.activation {
        incoming.discard()?;
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let action = args
        .first()
        .and_then(|value| value.to_str())
        .ok_or("expected identity or control, followed by an output path")?;
    let output = args.get(1).ok_or("missing output path")?;
    match action {
        "identity" => {
            let mut config =
                Configuration::create(Arc::new(ProjectData::default()), Default::default())?;
            if let Some(user) = args.get(2) {
                let user = user.to_str().ok_or("username must be Unicode")?;
                config.set_value(b"probe", b"USERNAME", Some(user.as_bytes()))?;
            }
            let identity = verify_configured_identity(&config, b"probe")?;
            std::fs::write(output, format!("{identity:?}\n"))?;
            Ok(())
        }
        "control" => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                let mut parent = captured
                    .parent_control
                    .ok_or("missing private parent channel")?
                    .register()?;
                parent.ready.signal(ReadyStatus::AcceptRegistered).await?;
                let mut bytes = Vec::new();
                while let Some(byte) = poll_fn(|cx| parent.control.poll_signal(cx)).await? {
                    if bytes.len() == 256 {
                        return Err(io::Error::other("probe control limit exceeded").into());
                    }
                    bytes.push(byte as u8);
                }
                std::fs::write(output, bytes)?;
                Ok(())
            })
        }
        _ => Err("unknown native startup probe action".into()),
    }
}
pub(super) fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _diagnostic = writeln!(io::stderr().lock(), "{error}");
            ExitCode::FAILURE
        }
    }
}
