use super::*;

struct FixedEntropy;
impl Entropy for FixedEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        output.fill(17);
        Ok(())
    }
}
struct NoSigning;
impl Signer for NoSigning {
    fn identity(&self) -> PeerId {
        PeerId([1; 32])
    }
    fn sign_validation(&mut self, _: &[u8; 48]) -> Result<[u8; 64], Error> {
        Err(Error::Unsupported)
    }
}
fn check(condition: bool) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}
fn queue_request(kind: u16, credit: u64) -> Result<Vec<u8>, Error> {
    let address = b"tcp-127.0.0.1:1";
    let mut frame = message(kind, if kind == 1204 { 65 + address.len() } else { 64 })?;
    frame[4..8].copy_from_slice(&1u32.to_be_bytes());
    frame[8..40].copy_from_slice(&[2; 32]);
    frame[44..48].copy_from_slice(&1024u32.to_be_bytes());
    frame[48..56].copy_from_slice(&credit.to_be_bytes());
    if kind == 1204 {
        frame[64..64 + address.len()].copy_from_slice(address);
    }
    Ok(frame)
}
fn setup(credit: u64) -> Result<(Engine, ClientId), Error> {
    let mut engine = Engine::new(PeerId([1; 32]), Limits::default())?;
    let owner = engine.accept()?;
    let mut registration = message(1211, 16)?;
    registration[4..8].copy_from_slice(&1u32.to_be_bytes());
    registration[12..16].copy_from_slice(b"tcp\0");
    let _registration =
        engine.receive(&owner, &registration, 0, &mut NoSigning, &mut FixedEntropy)?;
    let _setup = engine.receive(
        &owner,
        &queue_request(1204, credit)?,
        0,
        &mut NoSigning,
        &mut FixedEntropy,
    )?;
    Ok((engine, owner))
}
fn take_challenges(engine: &mut Engine) -> Result<usize, Error> {
    let mut count = 0;
    while let Some(output) = engine.output() {
        if let Output::Frame { bytes, .. } = output
            && Frame::decode(&bytes)?.header().message_type().value() == 1209
            && Frame::decode(bytes.get(48..).ok_or(Error::Truncated)?)?
                .header()
                .message_type()
                .value()
                == 1303
        {
            count += 1;
        }
    }
    Ok(count)
}

#[test]
fn ordinary_credit_replenishment_cannot_restart_challenge_each_turn() -> Result<(), Error> {
    let (mut engine, owner) = setup(1)?;
    check(take_challenges(&mut engine)? == 1)?;
    let nonce = engine.routes[0].nonce;
    for now in 1..=4 {
        let _credit = engine.receive(
            &owner,
            &queue_request(1222, 1)?,
            now,
            &mut NoSigning,
            &mut FixedEntropy,
        )?;
        let _tick = engine.tick(now, &mut FixedEntropy)?;
        check(take_challenges(&mut engine)? == 0)?;
        check(engine.routes[0].challenge_next == RETRY)?;
        check(engine.routes[0].challenge_last == 0)?;
    }
    let _tick = engine.tick(RETRY, &mut FixedEntropy)?;
    check(take_challenges(&mut engine)? == 1)?;
    check(engine.routes[0].nonce == nonce)?;
    check(engine.routes[0].challenge_first == 0)?;
    check(engine.routes[0].challenge_last == RETRY)
}

#[test]
fn first_usable_credit_is_immediate_but_short_requested_retry_keeps_floor() -> Result<(), Error> {
    let (mut engine, owner) = setup(0)?;
    check(take_challenges(&mut engine)? == 0)?;
    let first = 10;
    let _credit = engine.receive(
        &owner,
        &queue_request(1222, 1)?,
        first,
        &mut NoSigning,
        &mut FixedEntropy,
    )?;
    let _tick = engine.tick(first, &mut FixedEntropy)?;
    check(take_challenges(&mut engine)? == 1)?;
    let floor = first + RETRY;
    check(engine.routes[0].challenge_not_before == floor)?;
    // The same production scheduler is used after a verified short-TTL
    // response and liveness/credit recovery. These inputs are clock values,
    // not a fabricated signature or validation/physical-write receipt.
    let time = Times::new(MonoInstant(first + 1), AbsoluteTime::from_micros(800_000));
    engine.routes[0].schedule_challenge(time, first + 2);
    check(engine.routes[0].challenge_next == floor)?;
    check(engine.routes[0].monitor_next_validation == 800_000 + RETRY - 1)?;
    engine.close(&owner)?;
    check(engine.routes.is_empty())
}
