//! Transfer one opaque received BOX to its original forwarding child. No
//! signer, decryptor, provider, clock sample or physical receipt is created here.
use super::*;

pub(super) fn start<'source, 'id, 'pils, 'out, J>(
    input: &mut InputRow<'source, 'id, 'pils, 'out, J>,
    outputs: &mut Vec<OutputRow<'source, 'id, 'pils, J>>,
    neighbours: &[Neighbour<'id>],
    instance: &'id Instance,
    local: PeerId,
    now: u64,
    output_limit: usize,
) -> Result<Option<Token<'id>>, Protocol> {
    input.bounds.check(now)?;
    let packet = dv::BoxPacket::decode(&input.bytes)?;
    let selected = packet
        .shortcut(local, |peer| neighbours.iter().any(|n| n.peer == peer))?
        .ok_or(Protocol::NotReady)?;
    let next = packet.hop(selected)?;
    let neighbour = neighbours
        .iter()
        .find(|n| n.peer == next)
        .ok_or(Protocol::Stale)?
        .clone();
    // Official routing bypasses flow control only for GNUNET_YES (1).
    let without_fc = packet.without_fc()? == 1;
    // A full bounded output directory is temporary local backpressure. Keep
    // the same complete input, its FC owner and both original targets. The
    // unchanged caller scan creates no progress or new wake debt on this path.
    if outputs.len() >= output_limit {
        return Ok(None);
    }
    // Runtime reserves this metadata capacity at construction. Keep the last
    // fallible reservation before any payload mutation even for private users.
    outputs.try_reserve(1).map_err(|_| Protocol::Capacity)?;
    let token = Token {
        domain: instance,
        serial: instance.next()?,
    };
    // Codec preflights all layout checks before its first write. Until it
    // succeeds the original received bytes remain available on every error.
    let size = dv::BoxPacket::forward_in_place(&mut input.bytes, selected)?;
    input.bytes.truncate(size);
    let bytes = core::mem::take(&mut input.bytes);
    // No fallible work follows the ownership transfer. The same retained
    // allocation remains charged once, now to this exact child, even though
    // the compacted packet's length shrinks.
    outputs.push(OutputRow {
        token,
        neighbour,
        origin: None,
        parent: Some(input.token),
        bounds: Bound {
            until: input.bounds.until,
            hard: input.bounds.hard,
        },
        state: OutputState::Ready,
        bytes,
        without_fc,
        ordered_target: None,
        exposed: false,
        queued: false,
        probe: None,
    });
    input.forwards = 1;
    input.planning = false;
    input.state = InputState::Forwarding;
    input.disposition = Disposition::Forwarded(WriteOutcome::Unsent);
    Ok(Some(token))
}

#[cfg(test)]
#[path = "forward/tests.rs"]
mod tests;
