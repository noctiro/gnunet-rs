use crate::Failure;
use gnunet_core_client_host::KxState;
use gnunet_types::AbsoluteTime;
use std::io::Write;
pub(super) fn state_name(state: KxState) -> &'static str {
    match state.0 {
        0 => "idle",
        1 => "Hello sent (I)",
        2 => "Awaiting initiation (R)",
        3 => "Hello received (R)",
        4 => "Hello sent (R)",
        5 => "Hello received (I)",
        6 => "Done sent (I)",
        7 => "Connected (I)",
        8 => "Connected (R)",
        9 => "Rekey sent",
        10 => "disconnected",
        11 => "Initial iteration finished",
        12 => "CORE service disconnected",
        _ => "unknown state",
    }
}
pub(super) fn update(
    out: &mut impl Write,
    now: AbsoluteTime,
    peer: &[u8; 32],
    state: KxState,
    timeout: u64,
) -> Result<(), Failure> {
    let now = now.as_micros();
    let stamp = gnunet_program_host::logging::Stamp::controlled_utc(
        i64::try_from(now / 1_000_000)?,
        u32::try_from(now % 1_000_000)?,
    )?;
    let date = std::str::from_utf8(stamp.date())?;
    let peer = gnunet_program_host::diagnostics::peer_short(Some(peer));
    let peer = std::str::from_utf8(&peer)?;
    let remaining = if timeout == u64::MAX {
        u64::MAX
    } else {
        timeout.saturating_sub(now)
    };
    let duration = gnunet_program_host::diagnostics::relative_time(remaining, true);
    let duration = std::str::from_utf8(&duration)?;
    // The current observation's exact numeric code is always retained, including
    // REKEY_SENT and future values the C frontend prints only as "unknown".
    writeln!(
        out,
        "{date:>24}: {:<30} {peer:>4} (state={}, timeout in {duration:>6})",
        state_name(state),
        state.0
    )?;
    Ok(())
}
