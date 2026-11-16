//! Wide locale-aware Windows dates with original native conversion errors.
use gnunet_native::{
    calendar::{DateParser, Zone},
    os_bytes,
};
use std::io;
pub(crate) fn absolute_calendar(input: &[u8]) -> io::Result<u64> {
    let input = &input[..input
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(input.len())];
    let input = os_bytes::decode(input)?;
    #[expect(
        unsafe_code,
        reason = "PROGRAM's native-locale capability excludes foreign mutation during bounded LC_TIME snapshot/name capture, as required by all native option conversions"
    )]
    // SAFETY: no user callback runs inside capture. The snapshot owns its locale
    // after return and subsequent parsing does not install or borrow a selector.
    let parser = unsafe { DateParser::capture_current_thread()? };
    let seconds = u64::try_from(parser.parse(&input, Zone::Local)?)
        .map_err(|_| io::ErrorKind::InvalidInput)?;
    Ok(seconds.saturating_mul(1_000_000))
}
