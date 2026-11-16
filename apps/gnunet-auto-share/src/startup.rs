//! First-operation native bootstrap ownership for this foreground PROGRAM.
use gnunet_service_startup::ParentControl;
use std::error::Error;
#[cfg(unix)]
use std::io::{self, Write};

/// Capture the original process declarations before constructing any host owner.
///
/// # Safety
/// Call once at fresh single-threaded entry, before runtime, logging or native
/// resource initialization; terminate startup after any failure.
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "The sole entry caller establishes fresh single-threaded startup before transferring inherited native ownership"
)]
pub(super) unsafe fn capture() -> Result<Option<ParentControl>, Box<dyn Error>> {
    use gnunet_service_startup::{InheritedMode, InheritedResources};
    // SAFETY: the sole entry caller supplies this function's startup contract.
    let captured = unsafe {
        gnunet_service_startup::capture_from_environment(InheritedMode::CloseAfterConfiguredBind)?
    };
    if let Some(notice) = captured.control_notice {
        writeln!(
            io::stderr().lock(),
            "gnunet-auto-share parent-control declaration: {notice:?}"
        )?;
    }
    match captured.inherited {
        InheritedResources::CloseAfterBind(hold) => {
            let nonempty = !hold.is_empty();
            let report = hold.abort();
            if nonempty {
                return Err(format!("automatic sharing has no SERVICE listener; inherited descriptors refused: {report:?}").into());
            }
        }
        InheritedResources::Listeners(_) => {
            return Err("unexpected automatic sharing descriptor mode".into());
        }
    }
    Ok(captured.parent_control)
}

/// Capture original Windows declarations without listener import or detachment.
///
/// # Safety
/// Call once at fresh single-threaded entry, before runtime, logging or native
/// resource initialization; terminate startup after any failure.
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "The sole entry caller establishes fresh single-threaded startup before capturing Windows activation and parent-control declarations"
)]
pub(super) unsafe fn capture() -> Result<Option<ParentControl>, Box<dyn Error>> {
    // SAFETY: the sole entry caller supplies this function's startup contract.
    let captured = unsafe { gnunet_service_startup::capture_from_environment()? };
    if captured.activation.is_some() {
        return Err("automatic sharing has no SERVICE listener; socket activation refused".into());
    }
    if captured
        .parent_control
        .as_ref()
        .is_some_and(|parent| parent.role() == gnunet_service_startup::ParentRole::DetachLauncher)
    {
        return Err(
            "automatic sharing is a foreground PROGRAM; detached SERVICE bootstrap refused".into(),
        );
    }
    Ok(captured.parent_control)
}
