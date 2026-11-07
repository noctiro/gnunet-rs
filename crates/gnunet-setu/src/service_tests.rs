//! Actual service/codec/peer ownership transitions with explicit modeled host
//! completions; these cases do not claim native or C interoperability evidence.
use super::*;
use crate::{union::Phase, zlib::Zlib};

fn check(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(Error::Conflict) }
}
fn request(
    service: &mut Service,
    client: &Client,
    value: Request<'_>,
) -> Result<Option<Operation>, Error> {
    let mut bytes = alloc::vec![0; value.encoded_len(service.abi)?];
    value.encode(service.abi, &mut bytes)?;
    service.receive_client(client, &bytes, 1, 100)
}
fn peer(value: Peer<'_>, abi: Abi) -> Result<Vec<u8>, Error> {
    let mut bytes = alloc::vec![0; value.encoded_len()?];
    value.encode(abi, &mut bytes)?;
    Ok(bytes)
}
fn incoming(service: &mut Service) -> Result<(Client, Client, Operation, u32), Error> {
    let listener = service.connect()?;
    let client = service.connect()?;
    let _operation = request(
        service,
        &listener,
        Request::Listen {
            reserved: 0,
            app: [4; 64],
        },
    )?;
    check(
        matches!(service.next_effect(), Some(Effect::Listen { client: original, .. }) if original == listener),
    )?;
    service.listener_ready(&listener, Ok(()))?;
    let _operation = request(service, &client, Request::Create)?;
    let _operation = request(
        service,
        &client,
        Request::Add(wire::Element {
            kind: 7,
            data: b"original",
        }),
    )?;
    let first = peer(
        Peer::Operation {
            count: 17,
            app: [4; 64],
            context: None,
        },
        service.abi,
    )?;
    let operation = service.incoming(&listener, [5; 32], &first, 1, 100)?;
    let notice = service.next_incoming()?.ok_or(Error::NotReady)?;
    check(notice.operation == operation)?;
    Ok((listener, client, operation, notice.incoming))
}
fn close_sources(service: &mut Service, listener: &Client, client: &Client) -> Result<(), Error> {
    service.client_closed(client)?;
    service.client_closed(listener)?;
    check(
        matches!(service.next_effect(), Some(Effect::Unlisten { client: original, .. }) if original == *listener),
    )?;
    service.listener_closed(listener)?;
    check(service.is_quiescent())
}

#[test]
fn conflicting_force_options_preserve_request_and_original_incoming_admission() -> Result<(), Error>
{
    let mut service = Service::new(Limits::default(), Abi::native())?;
    let (listener, client, operation, incoming) = incoming(&mut service)?;
    let options = Options {
        force_delta: 1,
        force_full: 1,
        ..Options::default()
    };
    let before = service.next_operation;
    check(
        request(
            &mut service,
            &client,
            Request::Evaluate {
                request: 23,
                peer: [5; 32],
                app: [4; 64],
                options,
                context: None,
            },
        ) == Err(Error::InvalidInput),
    )?;
    for id in [incoming, incoming + 1] {
        check(
            request(
                &mut service,
                &client,
                Request::Accept {
                    incoming: id,
                    request: 23,
                    options,
                },
            ) == Err(Error::InvalidInput),
        )?;
    }
    check(service.next_operation == before && service.operations.iter().flatten().count() == 1)?;
    let entry = service.operations[service.op_index(&operation)?]
        .as_ref()
        .ok_or(Error::Stale)?;
    check(entry.client == listener && entry.request == 0 && entry.expires == 100)?;
    check(matches!(
        entry.state,
        State::Incoming {
            count: 17,
            reported: true,
            ..
        }
    ))?;
    check(service.next_effect().is_none())?;
    check(
        request(
            &mut service,
            &client,
            Request::Accept {
                incoming,
                request: 23,
                options: Options::default(),
            },
        )? == Some(operation.clone()),
    )?;
    service.cancel(&operation)?;
    check(
        matches!(service.next_effect(), Some(Effect::Close { operation: original }) if original == operation),
    )?;
    service.retired(&operation)?;
    check(service.next_result().is_none() && service.op_index(&operation) == Err(Error::Stale))?;
    close_sources(&mut service, &listener, &client)?;

    // Actual empty-set wire exchange must obey the same local forced-delta
    // option, including the chooser's otherwise unconditional empty shortcut.
    let abi = Abi::native();
    let empty = Set::new(set::Limits::default(), abi)?;
    let options = Options {
        force_delta: 1,
        ..Options::default()
    };
    let mut left = Union::initiate(
        empty.snapshot()?,
        options,
        union::Limits::default(),
        [4; 64],
        None,
    )?;
    let first = left.outbound().ok_or(Error::NotReady)?;
    let token = first.transmission;
    let Peer::Operation { count, .. } = Peer::decode(first.bytes, abi)? else {
        return Err(Error::Conflict);
    };
    check(count == 0)?;
    left.sent(&token)?;
    let mut right = Union::accept(empty.snapshot()?, options, union::Limits::default(), count)?;
    let mut codec = Zlib::new();
    let mut saw_ibf = false;
    for _ in 0..256 {
        left.advance(&mut codec, 1)?;
        right.advance(&mut codec, 1)?;
        for left_first in [true, false] {
            let (source, target) = if left_first {
                (&mut left, &mut right)
            } else {
                (&mut right, &mut left)
            };
            if let Some(output) = source.outbound() {
                let token = output.transmission;
                let bytes = output.bytes.to_vec();
                let message = Peer::decode(&bytes, abi)?;
                check(!matches!(
                    message,
                    Peer::Full { .. } | Peer::FullElement(_) | Peer::FullDone
                ))?;
                saw_ibf |= matches!(message, Peer::Ibf { .. });
                source.sent(&token)?;
                target.receive(&bytes, &mut codec)?;
            }
        }
        if left.close_needed() || right.close_needed() {
            break;
        }
    }
    check(saw_ibf && (left.close_needed() || right.close_needed()))?;
    check(left.phase() != Phase::Failed && right.phase() != Phase::Failed)?;
    left.retired();
    right.retired();
    for union in [&mut left, &mut right] {
        let result = union.next_result().ok_or(Error::NotReady)?;
        check(
            result.status == Status::Done && result.current_size == 0 && result.element.is_none(),
        )?;
        check(union.next_result().is_none() && union.outbound().is_none())?;
    }
    Ok(())
}

#[test]
fn forced_peer_mode_conflicts_preserve_leased_strata_and_cancel_original_scope() -> Result<(), Error>
{
    let padding = [0; 16];
    let buckets = [0; 20];
    for incompatible in [
        Peer::Full {
            request: false,
            remote_difference: 9,
            remote_size: u32::MAX,
            local_difference: 11,
            padding: &padding,
        },
        Peer::Full {
            request: true,
            remote_difference: 9,
            remote_size: u32::MAX,
            local_difference: 11,
            padding: &padding,
        },
        Peer::Ibf {
            size: 37,
            offset: 0,
            salt_field: 0,
            counter_bits: 1,
            data: &buckets,
        },
    ] {
        let mut service = Service::new(
            Limits {
                union: union::Limits {
                    output_frames: 1,
                    ..union::Limits::default()
                },
                ..Limits::default()
            },
            Abi::native(),
        )?;
        let (listener, client, operation, incoming) = incoming(&mut service)?;
        let full = matches!(incompatible, Peer::Ibf { .. });
        let options = Options {
            force_full: u8::from(full),
            force_delta: u8::from(!full),
            ..Options::default()
        };
        let _operation = request(
            &mut service,
            &client,
            Request::Accept {
                incoming,
                request: 23,
                options,
            },
        )?;
        service.advance(&mut Zlib::new(), 8)?;
        let abi = service.abi;
        let (transmission, original) = match service.next_effect().ok_or(Error::NotReady)? {
            Effect::Send {
                operation: actual,
                transmission,
                bytes,
            } => {
                check(
                    actual == operation && matches!(Peer::decode(bytes, abi)?, Peer::Strata { .. }),
                )?;
                (transmission, bytes.to_vec())
            }
            _ => return Err(Error::Conflict),
        };
        let bytes = peer(incompatible, service.abi)?;
        check(service.receive(&operation, &bytes, &mut Zlib::new()) == Err(Error::Unsupported))?;
        let index = service.op_index(&operation)?;
        let entry = service.operations[index].as_mut().ok_or(Error::Stale)?;
        check(entry.expires == 100 && entry.request == 23)?;
        let State::Running(union) = &mut entry.state else {
            return Err(Error::Conflict);
        };
        check(union.phase() == Phase::Failed && union.size() == 1 && union.rounds() == 0)?;
        let retained = union.outbound().ok_or(Error::NotReady)?;
        check(retained.transmission == transmission && retained.bytes == original)?;
        service.cancel(&operation)?;
        check(service.next_result().is_none())?;
        check(
            matches!(service.next_effect(), Some(Effect::Close { operation: original }) if original == operation),
        )?;
        service.sent(&operation, &transmission)?;
        service.retired(&operation)?;
        check(
            service.next_result().is_none() && service.op_index(&operation) == Err(Error::Stale),
        )?;
        close_sources(&mut service, &listener, &client)?;
    }
    Ok(())
}
