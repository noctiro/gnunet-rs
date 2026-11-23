use super::*;

extern crate std;

#[cfg(all(not(feature = "fixed-zlib"), feature = "zlib"))]
use crate::zlib::Zlib as TestCodec;
#[cfg(feature = "fixed-zlib")]
use gnunet_compression::FixedZlib as TestCodec;

const PORT: [u8; 64] = [37; 64];
const CONFIG: Config = Config {
    abi: Abi::native(),
    options: Options {
        force_delta: 0,
        force_full: 1,
        byzantine: 0,
        symmetric: 0,
        lower_bound: 0,
        upper_bound: u64::MAX,
        bandwidth_latency_tradeoff: 0,
        bucket_factor: 2,
        hashes: 3,
    },
    limits: Limits {
        remote_elements: 4,
        element_bytes: 64,
    },
};

struct Arena {
    local: [LocalEntry; 4],
    remote: [RemoteEntry; 4],
    frame: [u8; 2048],
    estimator: [Cell; ESTIMATOR_CELLS],
    peel: [Cell; PEEL_CELLS],
    raw: [u8; ESTIMATOR_BYTES],
    compressed: [u8; 2048],
    differential: Differential,
}

impl Arena {
    const EMPTY: Self = Self {
        local: [LocalEntry::EMPTY; 4],
        remote: [RemoteEntry::EMPTY; 4],
        frame: [0; 2048],
        estimator: [Cell::EMPTY; ESTIMATOR_CELLS],
        peel: [Cell::EMPTY; PEEL_CELLS],
        raw: [0; ESTIMATOR_BYTES],
        compressed: [0; 2048],
        differential: Differential::new(ESTIMATOR_CELLS, 8),
    };
    fn lend(&mut self) -> Buffers<'_> {
        Buffers {
            local: &mut self.local,
            remote: &mut self.remote,
            frame: &mut self.frame,
            element: &mut [],
            estimator: &mut self.estimator,
            peel: &mut self.peel,
            raw: &mut self.raw,
            compressed: &mut self.compressed,
            differential: Some(&mut self.differential),
        }
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "compares the fixed receiver with the canonical all-rotations estimator"
)]
fn receives_official_estimator_prefixes_with_one_rotation_of_storage() -> Result<(), Error> {
    let scope = Instance::new();
    let mut arena = Arena::EMPTY;
    let mut codec = TestCodec::new();
    let mut peer_cells = std::vec![Cell::EMPTY; strata::ALL_CELLS];
    let mut local_cells = std::vec![Cell::EMPTY; strata::ALL_CELLS];
    let mut raw = std::vec![0; ESTIMATOR_BYTES * strata::ESTIMATORS];
    let mut packed = std::vec![0; 8192];
    let mut frame = std::vec![0; ESTIMATOR_BYTES + 13];
    let mut outgoing = std::vec![0; frame.len()];
    let local = [Element {
        kind: 7,
        data: b"local original",
    }];
    let remote = Element {
        kind: 7,
        data: b"remote original",
    };
    let order = match CONFIG.abi.order {
        wire::Order::Little => Order::Little,
        wire::Order::Big => Order::Big,
    };
    let mut peer_estimator = Strata::clear(&mut peer_cells, order)?;
    peer_estimator.insert(Key::from_element_hash(
        &element_hash(remote, CONFIG.abi)?,
        order,
    )?)?;
    let mut local_estimator = Strata::clear(&mut local_cells, order)?;
    local_estimator.insert(Key::from_element_hash(
        &element_hash(local[0], CONFIG.abi)?,
        order,
    )?)?;
    for (count, compressed) in [(1, false), (2, true), (4, true), (8, true)] {
        let raw_len = peer_estimator.write_raw(count, &mut raw)?;
        let expected =
            local_estimator.estimate_remote_raw(count, &raw[..raw_len], &mut arena.peel)?;
        let data = if compressed {
            let length = codec.compress(&raw[..raw_len], &mut packed)?;
            &packed[..length]
        } else {
            &raw[..raw_len]
        };
        let length = Peer::Strata {
            count,
            compressed,
            set_size: 1,
            data,
        }
        .encode(CONFIG.abi, &mut frame)?;
        let mut buffers = arena.lend();
        buffers.frame = &mut outgoing;
        let mut session = Session::initiate(&scope, &local[..], buffers, CONFIG, PORT, None)
            .map_err(|rejected| rejected.error)?;
        let original = session
            .outbound(&mut codec)?
            .ok_or(Error::NotReady)?
            .transmission;
        session.sent(original)?;
        session.receive(&frame[..length], &mut codec, |_| Err(Error::Conflict))?;
        let selection = session.outbound(&mut codec)?.ok_or(Error::NotReady)?;
        assert!(matches!(
            Peer::decode(selection.bytes, CONFIG.abi)?,
            Peer::Full { remote_difference, local_difference, .. }
                if u64::from(remote_difference) == expected.negative
                    && u64::from(local_difference) == expected.positive
        ));
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "validates leased filter fragments and peer controls across a differential exchange"
)]
fn differential_reconciles_both_directions_across_filter_fragments() -> Result<(), Error> {
    let left_scope = Instance::new();
    let right_scope = Instance::new();
    let mut lhs = Arena::EMPTY;
    let mut rhs = Arena::EMPTY;
    let mut codec = TestCodec::new();
    let mut left_frame = [0; 640];
    let mut right_frame = [0; 640];
    let common = Element {
        kind: 1,
        data: b"x",
    };
    let left_only = Element {
        kind: 7,
        data: b"l",
    };
    let right_only = Element {
        kind: 7,
        data: b"r",
    };
    let left_elements = [common, left_only];
    let right_elements = [common, right_only];
    let mut config = CONFIG;
    config.options.force_delta = 1;
    config.options.force_full = 0;
    config.options.symmetric = 1;
    let mut left_arena = lhs.lend();
    left_arena.frame = &mut left_frame;
    let mut left = Session::initiate(
        &left_scope,
        &left_elements[..],
        left_arena,
        config,
        PORT,
        None,
    )
    .map_err(|rejected| rejected.error)?;
    let opening = left.outbound(&mut codec)?.ok_or(Error::NotReady)?;
    let original = opening.transmission;
    let incoming = Incoming::decode(opening.bytes, config.abi, &PORT)?;
    let mut right_arena = rhs.lend();
    right_arena.frame = &mut right_frame;
    let mut right = Session::accept(
        &right_scope,
        &right_elements[..],
        right_arena,
        config,
        incoming,
    )
    .map_err(|rejected| rejected.error)?;
    left.sent(original)?;

    let mut seen = [0; 2];
    let mut reported = [0; 2];
    let mut fragments = 0;
    let mut inquiries = 0;
    let mut output = [0; 640];
    let mut first_refusal = true;
    for _ in 0..40 {
        if let Some(frame) = left.outbound(&mut codec)? {
            let id = frame.transmission;
            let len = frame.bytes.len();
            output[..len].copy_from_slice(frame.bytes);
            let kept = left.outbound(&mut codec)?.ok_or(Error::NotReady)?;
            assert_eq!(kept.bytes, &output[..len]);
            assert!(kept.transmission == id);
            match Peer::decode(kept.bytes, config.abi)? {
                Peer::Ibf { .. } => fragments += 1,
                Peer::Element(_) => {
                    assert_eq!(kept.add_remote, Some(left_only));
                    reported[0] += 1;
                }
                _ => assert!(kept.add_remote.is_none()),
            }
            left.sent(id)?;
            let accept = right.receive(&output[..len], &mut codec, |item| {
                assert_eq!(item, left_only);
                if first_refusal {
                    first_refusal = false;
                    return Err(Error::WouldBlock);
                }
                seen[0] += 1;
                Ok(())
            });
            if accept == Err(Error::WouldBlock) {
                right.receive(&output[..len], &mut codec, |item| {
                    assert_eq!(item, left_only);
                    seen[0] += 1;
                    Ok(())
                })?;
            } else {
                accept?;
            }
        }
        if let Some(frame) = right.outbound(&mut codec)? {
            let id = frame.transmission;
            let len = frame.bytes.len();
            output[..len].copy_from_slice(frame.bytes);
            match Peer::decode(frame.bytes, config.abi)? {
                Peer::Inquiry { .. } => inquiries += 1,
                Peer::Element(_) => {
                    assert_eq!(frame.add_remote, Some(right_only));
                    reported[1] += 1;
                }
                _ => assert!(frame.add_remote.is_none()),
            }
            right.sent(id)?;
            left.receive(&output[..len], &mut codec, |item| {
                assert_eq!(item, right_only);
                seen[1] += 1;
                Ok(())
            })?;
        }
        if right.close_needed() {
            break;
        }
    }
    assert_eq!(seen, [1, 1]);
    assert_eq!(reported, [1, 1]);
    assert!(fragments >= 2);
    assert!(inquiries >= 1);
    assert!(!first_refusal);
    assert!(right.close_needed());
    assert!(left.outcome().is_none());
    assert!(right.outcome().is_none());
    left.retired(Ok(()));
    right.retired(Ok(()));
    assert_eq!(left.outcome(), Some(Outcome::Complete));
    assert_eq!(right.outcome(), Some(Outcome::Complete));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "checks a stalled filter emits a larger official IBF and obeys the round budget"
)]
fn differential_stalled_filter_grows_once_within_admitted_rounds() -> Result<(), Error> {
    let scope = Instance::new();
    let mut arena = Arena::EMPTY;
    arena.differential = Differential::new(75, 2);
    let mut codec = TestCodec::new();
    let mut config = CONFIG;
    config.options.force_full = 0;
    let mut incoming = [0; 2048];
    let size = Peer::Operation {
        count: 1,
        app: PORT,
        context: None,
    }
    .encode(config.abi, &mut incoming)?;
    let opening = Incoming::decode(&incoming[..size], config.abi, &PORT)?;
    let empty: &[Element<'_>] = &[];
    let mut session = Session::accept(&scope, empty, arena.lend(), config, opening)
        .map_err(|rejected| rejected.error)?;
    let estimator = session
        .outbound(&mut codec)?
        .ok_or(Error::NotReady)?
        .transmission;
    session.sent(estimator)?;

    let mut cells = [Cell::EMPTY; 37];
    cells[0].count = 2;
    let order = session.order;
    let filter = crate::ibf::Ibf::view(&mut cells, 3, order)?;
    let mut buckets = [0; 37 * crate::ibf::BUCKET_WIRE_BYTES];
    filter.encode_slice(0, 37, 2, &mut buckets)?;
    let size = Peer::Ibf {
        size: 37,
        offset: 0,
        salt_field: 0,
        counter_bits: 2,
        data: &buckets,
    }
    .encode(config.abi, &mut incoming)?;
    session.receive(&incoming[..size], &mut codec, |_| Err(Error::Conflict))?;
    let outbound = session.outbound(&mut codec)?.ok_or(Error::NotReady)?;
    assert!(matches!(
        Peer::decode(outbound.bytes, config.abi)?,
        Peer::Ibf {
            size: 75,
            offset: 0,
            ..
        }
    ));
    let original = outbound.transmission;
    session.sent(original)?;
    assert_eq!(
        session.receive(&incoming[..size], &mut codec, |_| Err(Error::Conflict)),
        Err(Error::Capacity)
    );
    assert!(session.close_needed());
    session.retired(Ok(()));
    assert_eq!(session.outcome(), Some(Outcome::Failed(Error::Capacity)));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "checks compact staging and exact original send gating"
)]
fn initial_frame_uses_caller_storage_until_admission() -> Result<(), Error> {
    assert!(core::mem::size_of::<Session<'static, 'static, &'static [Element<'static>]>>() <= 328);
    let scope = Instance::new();
    let mut arena = Arena::EMPTY;
    let mut codec = TestCodec::new();
    let empty: &[Element<'_>] = &[];
    let mut context = [0, 4, 0, 1];
    let mut session = Session::initiate(&scope, empty, arena.lend(), CONFIG, PORT, Some(&context))
        .map_err(|rejected| rejected.error)?;
    context.fill(0);
    let original = session.outbound(&mut codec)?.ok_or(Error::NotReady)?;
    let id = original.transmission;
    assert_eq!(
        Incoming::decode(original.bytes, CONFIG.abi, &PORT)?.context(),
        Some([0, 4, 0, 1].as_slice())
    );
    assert_eq!(context, [0; 4]);
    assert!(matches!(session.phase, Phase::Opening));
    session.sent(id)?;
    assert!(matches!(session.phase, Phase::ExpectEstimator));
    session.retired(Ok(()));
    let buffers = session.into_buffers();
    let mut session = Session::initiate(&scope, empty, buffers, CONFIG, PORT, None)
        .map_err(|rejected| rejected.error)?;
    session.cancel();
    assert!(session.outbound(&mut codec)?.is_none());
    assert_eq!(session.sent(id), Err(Error::Stale));
    session.retired(Ok(()));
    assert_eq!(session.outcome(), Some(Outcome::Cancelled));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "checks exact original SEC and two directional full phase transitions"
)]
fn complete_full_exchange_preserves_exact_backpressure_and_native_retirement() -> Result<(), Error>
{
    let overlap = Element {
        kind: 1,
        data: b"same",
    };
    let left_only = Element {
        kind: 7,
        data: b"left",
    };
    let right_only = Element {
        kind: 7,
        data: b"right",
    };
    let ([left_scope, right_scope], [mut lhs, mut rhs]) = (
        [Instance::new(), Instance::new()],
        [Arena::EMPTY, Arena::EMPTY],
    );
    let (left, right) = ([overlap, left_only], [overlap, right_only]);
    let mut config = CONFIG;
    config.options.symmetric = 1;
    let mut codec = TestCodec::new();
    let mut left = Session::initiate(&left_scope, &left[..], lhs.lend(), config, PORT, None)
        .map_err(|r| r.error)?;
    let start = left.outbound(&mut codec)?.ok_or(Error::NotReady)?;
    let incoming = Incoming::decode(start.bytes, CONFIG.abi, &PORT)?;
    let id = start.transmission;
    let mut right = Session::accept(&right_scope, &right[..], rhs.lend(), config, incoming)
        .map_err(|r| r.error)?;
    left.sent(id)?;
    let sec = right.outbound(&mut codec)?.ok_or(Error::NotReady)?;
    assert!(matches!(
        Peer::decode(sec.bytes, CONFIG.abi)?,
        Peer::Strata {
            compressed: true,
            count: 1,
            set_size: 2,
            ..
        }
    ));
    left.receive(sec.bytes, &mut codec, |_| Err(Error::Conflict))?;
    let sec = sec.transmission;
    right.sent(sec)?;
    let mut reported = [0; 2];
    let mut remote_adds = 0;
    let mut first_refusal = true;
    for _ in 0..12 {
        if let Some(out) = left.outbound(&mut codec)? {
            let id = out.transmission;
            let outcome = right.receive(out.bytes, &mut codec, |element| {
                assert_eq!(element, left_only);
                if first_refusal {
                    first_refusal = false;
                    return Err(Error::WouldBlock);
                }
                reported[1] += 1;
                Ok(())
            });
            if outcome == Err(Error::WouldBlock) {
                assert_eq!(
                    left.outbound(&mut codec)?
                        .ok_or(Error::NotReady)?
                        .transmission,
                    id
                );
            } else {
                outcome?;
                if let Some(element) = out.add_remote {
                    assert_eq!(element, left_only);
                    remote_adds += 1;
                }
                left.sent(id)?;
            }
        }
        if let Some(out) = right.outbound(&mut codec)? {
            let id = out.transmission;
            if let Some(element) = out.add_remote {
                assert_eq!(element, right_only);
                remote_adds += 1;
            }
            left.receive(out.bytes, &mut codec, |element| {
                assert_eq!(element, right_only);
                reported[0] += 1;
                Ok(())
            })?;
            right.sent(id)?;
        }
    }
    assert_eq!(reported, [1, 1]);
    assert_eq!(remote_adds, 1);
    assert!(!first_refusal);
    assert_ne!(left.close_needed(), right.close_needed());
    assert_eq!(left.outcome(), None);
    assert_eq!(right.outcome(), None);
    left.retired(Ok(()));
    right.retired(Ok(()));
    assert_eq!(left.outcome(), Some(Outcome::Complete));
    assert_eq!(right.outcome(), Some(Outcome::Complete));
    let left_buffers = left.into_buffers();
    let mut replacement = Session::initiate(
        &left_scope,
        &[] as &[Element<'_>],
        left_buffers,
        CONFIG,
        PORT,
        None,
    )
    .map_err(|r| r.error)?;
    let out = replacement.outbound(&mut codec)?.ok_or(Error::NotReady)?;
    assert_ne!(out.transmission, id);
    assert_eq!(replacement.sent(id), Err(Error::Stale));
    Ok(())
}
