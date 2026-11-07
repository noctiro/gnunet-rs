//! Prepared source cases only; no native source, entropy or key is accessed.
use crate::{Error, Limits, Request};
use gnunet_types::Error as Fault;
use gnunet_wire::official::secretsharing::Generate;
fn check(value: bool) -> Result<(), Error> {
    if value {
        Ok(())
    } else {
        Err(Fault::Malformed.into())
    }
}
fn frame(threshold: u16) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0; 120];
    Generate {
        session: &[2; 64],
        start: 10,
        deadline: 20,
        threshold,
        peers: &[3; 32],
    }
    .encode(&mut bytes)?;
    Ok(bytes)
}
#[test]
fn exact780_keeps_original_intent_and_does_not_claim_round1_done() -> Result<(), Error> {
    let request = Request::from_frame(frame(1)?, Limits::default())?;
    check(
        request.session == [2; 64]
            && request.start == 10
            && request.deadline == 20
            && request.threshold == 1,
    )
}
#[test]
fn zero_threshold_and_trailing_original_bytes_refuse_admission() -> Result<(), Error> {
    check(matches!(
        Request::from_frame(frame(0)?, Limits::default()),
        Err(Error::Protocol(Fault::InvalidInput))
    ))?;
    let mut bytes = frame(1)?;
    bytes.push(0);
    check(Request::from_frame(bytes, Limits::default()).is_err())
}
