//! Dedicated Linux privileged helpers with official type185/PI framing.
//! This library owns no service, cryptography, async runtime or legacy FFI.
#![deny(unsafe_code)]
#[cfg(target_os = "linux")]
#[expect(
    clippy::result_large_err,
    reason = "Bounded by-value original and independent cleanup causes avoid a fallible error-path allocation"
)]
mod commands;
mod failure;
#[cfg(target_os = "linux")]
#[expect(
    clippy::result_large_err,
    reason = "Bounded by-value original and independent cleanup causes avoid a fallible error-path allocation"
)]
mod native;
#[cfg(target_os = "linux")]
#[expect(
    clippy::result_large_err,
    reason = "Bounded by-value original and independent cleanup causes avoid a fallible error-path allocation"
)]
mod options;
#[cfg(target_os = "linux")]
#[expect(
    clippy::result_large_err,
    reason = "Bounded by-value original and independent cleanup causes avoid a fallible error-path allocation"
)]
mod pump;
pub use failure::Failure;
/// The selected installed argument contract, not a privilege or readiness proof.
#[derive(Clone, Copy, Debug)]
pub enum Profile {
    /// Five positional arguments: TUN, IPv6, prefix, IPv4, mask.
    Vpn,
    /// Six positional arguments: TUN, egress, IPv6, prefix, IPv4, mask.
    Exit,
}
/// Run only in a dedicated, fresh, single-threaded helper process. All actual
/// configuration precedes permanent credential reduction and packet pumping.
/// Exit0 is controlled local termination, never a remote or kernel delivery ACK.
///
/// # Safety
/// Call exactly once from the entry of a dedicated, fresh, single-threaded
/// helper process. Any open fd0/fd1 must be the original inherited streams with
/// no other Rust owner, borrow or stdio use. This call takes their ownership and
/// may close them even on error; the caller must treat those streams as consumed.
#[expect(
    unsafe_code,
    reason = "The public boundary explicitly requires exclusive original inherited stdio ownership before private FromRawFd adoption"
)]
#[expect(
    clippy::result_large_err,
    reason = "Keep bounded original and independent native causes inline in this privileged process"
)]
pub unsafe fn run(profile: Profile) -> Result<(), Failure> {
    #[cfg(target_os = "linux")]
    {
        run_linux(profile)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _profile = profile;
        Err(Failure::invalid("platform", "Linux TUN ABI required"))
    }
}
/// Attempt one bounded terminal diagnostic after the real drop attempt. Packet
/// bytes never enter this diagnostic or the helper stdout framing stream.
pub fn diagnostic(error: &Failure) {
    #[cfg(target_os = "linux")]
    {
        native::diagnostic(error);
    }
    #[cfg(not(target_os = "linux"))]
    {
        use std::io::Write;
        let _written = writeln!(std::io::stderr().lock(), "gnunet-tun-helper: {error}");
    }
}
#[cfg(target_os = "linux")]
#[expect(
    clippy::result_large_err,
    reason = "Bounded by-value errors retain original and independent close causes without a fallible error-path heap allocation in this privileged helper"
)]
fn run_linux(profile: Profile) -> Result<(), failure::Failure> {
    use failure::{Failure, Report};
    use gnunet_native::nat_helper::{self, Signals};
    // The inherited streams are captured once before any native open can reuse
    // a closed standard number. This helper never creates Rust stdin/stdout owners.
    let (mut streams, mut error) = match native::Streams::capture() {
        Ok(streams) => (Some(streams), None),
        Err(cause) => (None, Some(Failure::new("stdio capture", cause))),
    };
    let parent = native::parent();
    // A single signal owner spans setup and pumping. In particular a stop seen
    // during privileged child cleanup is never reset by a second installation.
    let mut signals = None;
    if error.is_none() {
        match Signals::install() {
            Ok(owner) => signals = Some(owner),
            Err(cause) => retain(&mut error, "signal install", cause),
        }
    }
    let mut tun = None;
    if error.is_none() {
        match options::Options::parse(profile).and_then(|options| {
            let signals = signals
                .as_ref()
                .ok_or_else(|| Failure::invalid("signal owner", "missing original signal owner"))?;
            commands::configure(&options, parent, signals)?;
            if signals.stopped() || parent <= 1 || native::parent() != parent {
                return Err(Failure::new(
                    "setup stopped",
                    std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "original parent or stop retired setup",
                    ),
                ));
            }
            native::create(&options)
        }) {
            Ok(created) => tun = Some(created),
            Err(cause) => error = Some(cause),
        }
    }
    // The official order requires real TUN/address/link configuration first.
    // Every error path still attempts permanent reduction before diagnostics.
    if let Err(cause) = nat_helper::drop_to_real_ids() {
        if let Some(error) = &mut error {
            error.add("credential drop", cause);
            error.code = 2;
        } else {
            let mut original = Failure::new("credential drop", cause);
            original.code = 2;
            error = Some(original);
        }
    }
    let mut report = Report::default();
    if error.is_none() {
        match nat_helper::watch_parent(parent) {
            Ok(false) => report.stopped = Some("original parent retired"),
            Err(cause) => retain(&mut error, "parent lifetime", cause),
            Ok(true) => {
                if let (Some(tun), Some(streams), Some(signals)) = (&tun, &streams, &signals)
                    && let Err(cause) = pump::run(tun, streams, signals, parent, &mut report)
                {
                    error = Some(cause);
                }
            }
        }
    }
    if let Some(original) = tun.take()
        && let Err(cause) = native::close(original.fd)
    {
        retain(&mut error, "original TUN close", cause);
    }
    if let Some(original) = streams.take() {
        if let Err(cause) = native::close(original.input) {
            retain(&mut error, "original stdin close", cause);
        }
        if let Err(cause) = native::close(original.output) {
            retain(&mut error, "original stdout close", cause);
        }
    }
    if let Some(signals) = &mut signals
        && let Err(cause) = signals.restore()
    {
        retain(&mut error, "signal restore", cause);
    }
    match error {
        Some(mut error) => {
            error.report = report;
            Err(error)
        }
        None => Ok(()),
    }
}
#[cfg(target_os = "linux")]
fn retain(error: &mut Option<failure::Failure>, stage: &'static str, cause: std::io::Error) {
    match error {
        Some(original) => original.add(stage, cause),
        None => *error = Some(failure::Failure::new(stage, cause)),
    }
}
