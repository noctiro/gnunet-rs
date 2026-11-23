use super::*;
use core::num::{NonZeroU16, NonZeroU64};
use gnunet_core::{session::Identity, wire::WordOrder};
use gnunet_crypto::hash512;
use gnunet_transport::{PeerId, direct_discovery as discovery, dv, p2p::Fragment};
use gnunet_types::RelativeTime;

extern crate std;

const WIDE_APPLICATION_BYTES: usize = 62_540;
const WIDE_BOX_BYTES: usize = 1536;
const TRANSPORT_BYTES: usize =
    MAX_RECORD_BYTES + dv::BOX_PREFIX + dv::PAYLOAD_PREFIX + dv::MAX_HOPS * 32;
static WIDE_PAYLOAD: [u8; WIDE_APPLICATION_BYTES] = {
    let mut bytes = [0x5a; WIDE_APPLICATION_BYTES];
    let length = (WIDE_APPLICATION_BYTES as u16).to_be_bytes();
    let kind = 158_u16.to_be_bytes(); // Official DHT_CORE application envelope.
    bytes[0] = length[0];
    bytes[1] = length[1];
    bytes[2] = kind[0];
    bytes[3] = kind[1];
    bytes
};

const PAYLOAD: [u8; 192] = {
    let mut bytes = [9; 192];
    bytes[0] = 0;
    bytes[1] = 192;
    bytes[2] = 0;
    bytes[3] = 42;
    bytes
};

const HELLO_ADDRESS: &[u8] = b"tcp://192.0.2.1:2086\0";
const HELLO_LEN: usize = 112 + HELLO_ADDRESS.len();
const HELLO_LIMITS: discovery::Limits = discovery::Limits {
    maximum_input_bytes: 256,
    maximum_address_bytes: 96,
    maximum_addresses: 4,
};

#[derive(Debug, Eq, PartialEq)]
struct Discovered {
    peer: EddsaPublicKey,
    expiration: AbsoluteTime,
    proof: discovery::AddressProof,
    expected_address: bool,
}

struct Route {
    id: NonZeroU64,
    wire: [u8; dv::LEARN_PREFIX],
    receipt: RoutingReceipt,
}

#[derive(Default)]
struct App {
    confirmed: bool,
    offer: bool,
    wide_offer: Option<&'static [u8]>,
    delivered: bool,
    wide_deliveries: usize,
    sent: Option<Result<(), Error>>,
    hello: Option<[u8; HELLO_LEN]>,
    discovered: Option<Discovered>,
    publications: usize,
    expiration: Option<AbsoluteTime>,
    expirations: usize,
    withdrawal: Option<AbsoluteTime>,
    reachability: Option<Reachability>,
    reachability_changes: usize,
    route: Option<Route>,
    route_admitted: Option<(NonZeroU64, Result<(), Error>)>,
    route_written: Option<(NonZeroU64, Result<(), Error>, MonoInstant)>,
    route_received: Option<[u8; dv::LEARN_PREFIX]>,
    route_received_bytes: usize,
}

impl Application for App {
    fn readiness(&mut self, confirmed: bool) {
        self.confirmed = confirmed;
    }

    fn reachability(&mut self, lease: Option<Reachability>) {
        self.reachability = lease;
        self.reachability_changes += 1;
    }

    fn received(&mut self, message: &[u8]) {
        self.delivered = message == PAYLOAD;
        if message == WIDE_PAYLOAD {
            self.wide_deliveries += 1;
        }
    }

    fn discovered(&mut self, change: DiscoveryChange<'_>) {
        match change {
            DiscoveryChange::Published(snapshot) => {
                self.discovered = Some(Discovered {
                    peer: snapshot.peer(),
                    expiration: snapshot.expiration(),
                    proof: snapshot.proof(),
                    expected_address: snapshot.address_bytes() == HELLO_ADDRESS,
                });
                self.publications += 1;
            }
            DiscoveryChange::Withdrawn(floor) => {
                self.discovered = None;
                self.withdrawal = Some(floor);
            }
            DiscoveryChange::Expired(floor) => {
                self.discovered = None;
                self.expiration = Some(floor);
                self.expirations += 1;
            }
        }
    }

    fn routed(&mut self, frame: RoutingFrame<'_>, _sample: Sample) -> Delivery {
        self.route_received_bytes = frame.bytes().len();
        self.route_received = frame.bytes().try_into().ok();
        Delivery::Consumed
    }

    fn routing_offer(&mut self, _: MonoInstant) -> Result<Option<RoutingOffer<'_>>, Error> {
        self.route
            .as_ref()
            .map(|route| {
                Ok(RoutingOffer {
                    id: route.id,
                    receipt: route.receipt,
                    frame: RoutingFrame::decode(&route.wire)?,
                })
            })
            .transpose()
    }

    fn routing_admitted(&mut self, id: NonZeroU64, outcome: Result<(), Error>) {
        self.route = None;
        self.route_admitted = Some((id, outcome));
    }

    fn routing_written(
        &mut self,
        id: NonZeroU64,
        outcome: Result<(), Error>,
        elapsed: MonoInstant,
    ) {
        self.route_written = Some((id, outcome, elapsed));
    }

    fn outgoing(&mut self) -> Option<&[u8]> {
        if let Some(hello) = &self.hello {
            Some(hello)
        } else if let Some(offer) = self.wide_offer {
            Some(offer)
        } else {
            self.offer.then_some(&PAYLOAD)
        }
    }

    fn outgoing_complete(&mut self, result: Result<(), Error>) {
        self.offer = false;
        self.wide_offer = None;
        self.hello = None;
        self.sent = Some(result);
    }
}

struct TestEntropy(u32);

impl Entropy for TestEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        for byte in output {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 17;
            self.0 ^= self.0 << 5;
            *byte = self.0 as u8;
        }
        Ok(())
    }
}

struct Arena {
    scope: Scope,
    output: [u8; 512],
    plain: [u8; 512],
    pending: [u8; 512],
    fragments: [u8; 512 * direct::DEFAULT_REASSEMBLIES],
    coverage: [u8; 64 * direct::DEFAULT_REASSEMBLIES],
    fragment_box: [u8; 128],
    discovery_retained: [u8; HELLO_LIMITS.maximum_address_bytes],
    discovery_scratch: [u8; HELLO_LIMITS.maximum_address_bytes],
}

impl Arena {
    fn new() -> Self {
        Self {
            scope: Scope::new(),
            output: [0; 512],
            plain: [0; 512],
            pending: [0; 512],
            fragments: [0; 512 * direct::DEFAULT_REASSEMBLIES],
            coverage: [0; 64 * direct::DEFAULT_REASSEMBLIES],
            fragment_box: [0; 128],
            discovery_retained: [0; HELLO_LIMITS.maximum_address_bytes],
            discovery_scratch: [0; HELLO_LIMITS.maximum_address_bytes],
        }
    }

    fn peer<'key, 'buf>(
        &'buf mut self,
        signing: &'key EddsaPrivateKey,
        identity: &'key Identity,
        remote: EddsaPublicKey,
        offer: bool,
    ) -> Result<Peer<'key, 'buf, App, 512>, Error> {
        Peer::new(
            &mut self.scope,
            Settings {
                transport_signing: signing,
                core: Local {
                    identity,
                    order: WordOrder::Little,
                    services: &[],
                    class: 0,
                },
                remote,
                link: direct::Limits {
                    max_payload: NonZeroU16::new(512).ok_or(Error::InvalidInput)?,
                    max_box: NonZeroU16::new(128).ok_or(Error::InvalidInput)?,
                    response_timeout: RelativeTime::from_micros(2_000_000),
                    offered_validity: RelativeTime::from_micros(2_000_000),
                },
            },
            Buffers {
                outbound: &mut self.output,
                plaintext: &mut self.plain,
                pending_input: &mut self.pending,
                fragments: direct::FragmentBuffers {
                    receive: direct::FragmentLane::partition(
                        512,
                        &mut self.fragments,
                        &mut self.coverage,
                    )?,
                    transmit: &mut self.fragment_box,
                },
                discovery: DiscoveryBuffers {
                    retained: &mut self.discovery_retained,
                    scratch: &mut self.discovery_scratch,
                    limits: HELLO_LIMITS,
                },
            },
            App {
                offer,
                ..App::default()
            },
        )
    }
}

fn exchange(
    sender: &mut Peer<'_, '_, App, 512>,
    receiver: &mut Peer<'_, '_, App, 512>,
    stamp: NonZeroU64,
    entropy: &mut TestEntropy,
) -> Result<(), Error> {
    exchange_with(
        sender,
        receiver,
        stamp,
        entropy,
        |outgoing| match outgoing {
            Outgoing::Buffered(_) => Ok(()),
            Outgoing::ObserveNative { .. } => Err(Error::Conflict),
        },
    )
}

fn exchange_with(
    sender: &mut Peer<'_, '_, App, 512>,
    receiver: &mut Peer<'_, '_, App, 512>,
    stamp: NonZeroU64,
    entropy: &mut TestEntropy,
    admit: impl FnOnce(Outgoing<'_>) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut context = TransportContext {
        sample: Sample {
            absolute: AbsoluteTime::from_micros(stamp.get()),
            elapsed: MonoInstant(stamp.get()),
        },
        signed: stamp,
        entropy,
    };
    let mut wire = [0; WIDE_BOX_BYTES];
    let mut length = 0;
    let previous = sender.application.sent;
    sender.poll_send(&mut context, |outgoing| {
        admit(outgoing)?;
        let frame = match outgoing {
            Outgoing::Buffered(frame) | Outgoing::ObserveNative { message: frame, .. } => frame,
        };
        wire.get_mut(..frame.len())
            .ok_or(Error::Capacity)?
            .copy_from_slice(frame);
        length = frame.len();
        Ok(())
    })?;
    if length != 0 {
        if let Ok(fragment) = Fragment::decode(&wire[..length])
            && usize::from(fragment.offset) + fragment.body.len() < usize::from(fragment.total)
            && sender.application.sent != previous
        {
            return Err(Error::Conflict);
        }
        sender.outgoing_complete(Ok(()));
        let _delivery = receiver.receive(sender.local, &wire[..length], &mut context)?;
    }
    Ok(())
}

#[test]
fn fragmented_carrier_confirms_core_delivers_and_expires_blocked_output() -> Result<(), Error> {
    let a_signer = EddsaPrivateKey::from_seed([21; 32]);
    let b_signer = EddsaPrivateKey::from_seed([55; 32]);
    let a_identity = Identity::from_seed([21; 32]);
    let b_identity = Identity::from_seed([55; 32]);
    let mut a_storage = Arena::new();
    let mut b_storage = Arena::new();
    let mut a = a_storage.peer(&a_signer, &a_identity, b_signer.public_key(), true)?;
    let mut b = b_storage.peer(&b_signer, &b_identity, a_signer.public_key(), false)?;
    if a.add_queue(b.local, b.local, Role::Outbound) != Err(Error::Authentication) {
        return Err(Error::Conflict);
    }
    a.add_queue(a.local, b.local, Role::Outbound)?;
    b.add_queue(b.local, a.local, Role::Inbound)?;
    let mut entropy = TestEntropy(2718);
    for turn in 1..145 {
        let stamp = NonZeroU64::new(turn * 10_000).ok_or(Error::InvalidInput)?;
        exchange(&mut a, &mut b, stamp, &mut entropy)?;
        exchange(&mut b, &mut a, stamp, &mut entropy)?;
        if b.application.delivered {
            break;
        }
    }
    if !a.established()
        || !b.established()
        || !b.application.delivered
        || a.application.sent != Some(Ok(()))
    {
        return Err(Error::NotReady);
    }
    let deadline = a.maintenance_deadlines();
    let expires = deadline.elapsed.ok_or(Error::NotReady)?;
    let core_expires = deadline.absolute.ok_or(Error::NotReady)?;
    a.core.send(core_expires.as_micros() - 1, &PAYLOAD)?;
    a.application.sent = None;
    a.application_pending = true;
    a.maintain(Sample {
        absolute: core_expires,
        elapsed: MonoInstant(expires.0 - 1),
    })?;
    if a.established()
        || a.application.confirmed
        || a.core.has_pending()
        || a.application.sent != Some(Err(Error::Deadline))
    {
        return Err(Error::Conflict);
    }
    a.maintain(Sample {
        absolute: core_expires,
        elapsed: expires,
    })?;
    if a.maintenance_deadlines().elapsed.is_some() {
        return Err(Error::Conflict);
    }
    a.remove_queue();
    if a.established()
        || a.application.confirmed
        || a.add_queue(a.local, b.local, Role::Outbound).is_ok()
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[test]
fn wide_core_original_crosses_bounded_direct_fragments() -> Result<(), Error> {
    const SMALL: usize = 4096;
    const RUN_TIME: u64 = 2_000_000;

    let a_signer = EddsaPrivateKey::from_seed([21; 32]);
    let b_signer = EddsaPrivateKey::from_seed([55; 32]);
    let a_identity = Identity::from_seed([21; 32]);
    let b_identity = Identity::from_seed([55; 32]);
    let mut a_scope = Scope::new();
    let mut b_scope = Scope::new();
    let mut a_memory = std::vec![0; 3 * MAX_RECORD_BYTES - RECORD_PREFIX
        + TRANSPORT_BYTES + TRANSPORT_BYTES.div_ceil(8) + 3 * (SMALL + SMALL / 8)
        + WIDE_BOX_BYTES + 2 * HELLO_LIMITS.maximum_address_bytes];
    let mut b_memory = std::vec![0; a_memory.len()];

    fn peer<'key, 'buf>(
        scope: &'buf mut Scope,
        signing: &'key EddsaPrivateKey,
        identity: &'key Identity,
        remote: EddsaPublicKey,
        memory: &'buf mut [u8],
        wide_offer: Option<&'static [u8]>,
    ) -> Result<Peer<'key, 'buf, App, 512>, Error> {
        let (outbound, memory) = memory.split_at_mut(MAX_RECORD_BYTES);
        let (plaintext, memory) = memory.split_at_mut(MAX_RECORD_BYTES - RECORD_PREFIX);
        let (pending_input, memory) = memory.split_at_mut(MAX_RECORD_BYTES);
        let (wide, memory) = memory.split_at_mut(TRANSPORT_BYTES);
        let (wide_coverage, memory) = memory.split_at_mut(TRANSPORT_BYTES.div_ceil(8));
        let (small, memory) = memory.split_at_mut(SMALL * 3);
        let (small_coverage, memory) = memory.split_at_mut(SMALL / 8 * 3);
        let (transmit, memory) = memory.split_at_mut(WIDE_BOX_BYTES);
        let (retained, scratch) = memory.split_at_mut(HELLO_LIMITS.maximum_address_bytes);
        let [first, second, third] = direct::FragmentLane::partition(SMALL, small, small_coverage)?;
        Peer::new(
            scope,
            Settings {
                transport_signing: signing,
                core: Local {
                    identity,
                    order: WordOrder::Little,
                    services: &[],
                    class: 0,
                },
                remote,
                link: direct::Limits {
                    max_payload: NonZeroU16::new(TRANSPORT_BYTES as u16)
                        .ok_or(Error::InvalidInput)?,
                    max_box: NonZeroU16::new(WIDE_BOX_BYTES as u16).ok_or(Error::InvalidInput)?,
                    response_timeout: RelativeTime::from_micros(RUN_TIME),
                    offered_validity: RelativeTime::from_micros(RUN_TIME),
                },
            },
            Buffers {
                outbound,
                plaintext,
                pending_input,
                fragments: direct::FragmentBuffers {
                    receive: [
                        first,
                        second,
                        third,
                        direct::FragmentLane::new(wide, wide_coverage)?,
                    ],
                    transmit,
                },
                discovery: DiscoveryBuffers {
                    retained,
                    scratch,
                    limits: HELLO_LIMITS,
                },
            },
            App {
                wide_offer,
                ..App::default()
            },
        )
    }

    let mut a = peer(
        &mut a_scope,
        &a_signer,
        &a_identity,
        b_signer.public_key(),
        &mut a_memory,
        Some(&WIDE_PAYLOAD),
    )?;
    let mut b = peer(
        &mut b_scope,
        &b_signer,
        &b_identity,
        a_signer.public_key(),
        &mut b_memory,
        None,
    )?;
    a.add_queue(a.local, b.local, Role::Outbound)?;
    b.add_queue(b.local, a.local, Role::Inbound)?;
    let mut entropy = TestEntropy(2718);
    for turn in 1..100 {
        let stamp = NonZeroU64::new(turn * 1000).ok_or(Error::InvalidInput)?;
        exchange(&mut a, &mut b, stamp, &mut entropy)?;
        exchange(&mut b, &mut a, stamp, &mut entropy)?;
    }
    if !a.established() || !b.established() || b.application.wide_deliveries != 1 {
        return Err(Error::NotReady);
    }
    if a.application.sent != Some(Ok(())) {
        return Err(Error::Conflict);
    }
    check_core_budget(&mut a, &mut b, &mut entropy)
}

fn check_core_budget(
    a: &mut Peer<'_, '_, App, 512>,
    b: &mut Peer<'_, '_, App, 512>,
    entropy: &mut TestEntropy,
) -> Result<(), Error> {
    const OVERSIZED_APPLICATION: &[u8] = &[0; MAX_RECORD_BYTES - RECORD_PREFIX + 1];
    let stamp = NonZeroU64::new(100_000).ok_or(Error::InvalidInput)?;
    a.application.wide_offer = Some(OVERSIZED_APPLICATION);
    for _ in 0..8 {
        exchange(a, b, stamp, entropy)?;
        if a.application.sent == Some(Err(Error::TooLarge)) {
            break;
        }
    }
    if a.application.sent != Some(Err(Error::TooLarge)) {
        return Err(Error::Conflict);
    }

    {
        let mut context = TransportContext {
            sample: Sample {
                absolute: AbsoluteTime::from_micros(stamp.get()),
                elapsed: MonoInstant(stamp.get()),
            },
            signed: stamp,
            entropy,
        };
        let mut oversized = std::vec![0; MAX_RECORD_BYTES + 1];
        let total = u16::try_from(oversized.len()).map_err(|_| Error::TooLarge)?;
        gnunet_core::wire::header(&mut oversized, usize::from(total), 83)?;
        if b.receive(a.local, &oversized, &mut context)? != Delivery::Dropped {
            return Err(Error::Conflict);
        }
        let mut encoded = [0; WIDE_BOX_BYTES];
        for (index, body) in oversized.chunks(1400).enumerate() {
            let offset = u16::try_from(index * 1400).map_err(|_| Error::Overflow)?;
            let fragment = Fragment {
                offset,
                total,
                ack: [index as u8; 16],
                message_id: [42; 8],
                body,
            };
            let size = fragment.encode(&mut encoded)?;
            let expected = if usize::from(offset) + body.len() == oversized.len() {
                Delivery::Dropped
            } else {
                Delivery::Consumed
            };
            if b.receive(a.local, &encoded[..size], &mut context)? != expected {
                return Err(Error::Conflict);
            }
        }
        // A wider DV BOX still reaches its own original consumer.
        let mut dv_box = std::vec![0; TRANSPORT_BYTES];
        oversized.resize(TRANSPORT_BYTES - dv::BOX_PREFIX - dv::MAX_HOPS * 32, 0);
        let size = dv::BoxHeader {
            without_fc: false,
            encapsulation: [1; 32],
            nonce: [2; 24],
            mac: [3; 16],
        }
        .encode(&[PeerId([4; 32]); dv::MAX_HOPS], &oversized, &mut dv_box)?;
        if b.receive(a.local, &dv_box[..size], &mut context)? != Delivery::Consumed
            || b.application.route_received_bytes != TRANSPORT_BYTES
        {
            return Err(Error::Conflict);
        }
    }

    a.application.offer = true;
    for _ in 0..16 {
        exchange(a, b, stamp, entropy)?;
        exchange(b, a, stamp, entropy)?;
        if b.application.delivered {
            break;
        }
    }
    if !b.application.delivered || !a.established() || !b.established() {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn signed_hello(key: &EddsaPrivateKey, expiration: AbsoluteTime) -> Result<[u8; HELLO_LEN], Error> {
    // Official HELLO_URI (16) and purpose 7. The normal GNUnet 0.29.1
    // signature hashes the empty address set, so CORE must bind the addresses.
    const PURPOSE: u32 = 7;
    let mut region = [0; 80];
    region[..4].copy_from_slice(&80_u32.to_be_bytes());
    region[4..8].copy_from_slice(&PURPOSE.to_be_bytes());
    region[8..16].copy_from_slice(&expiration.to_be_bytes());
    region[16..].copy_from_slice(&hash512(&[]));
    let signature = key.sign(PURPOSE, &region)?;

    let mut wire = [0; HELLO_LEN];
    wire[..2].copy_from_slice(&(HELLO_LEN as u16).to_be_bytes());
    wire[2..4].copy_from_slice(&16_u16.to_be_bytes());
    wire[6..8].copy_from_slice(&1_u16.to_be_bytes());
    wire[8..40].copy_from_slice(key.public_key().as_bytes());
    wire[40..104].copy_from_slice(signature.as_bytes());
    wire[104..112].copy_from_slice(&expiration.to_be_bytes());
    wire[112..].copy_from_slice(HELLO_ADDRESS);
    Ok(wire)
}

fn exchange_hello(
    sender: &mut Peer<'_, '_, App, 512>,
    receiver: &mut Peer<'_, '_, App, 512>,
    hello: [u8; HELLO_LEN],
    elapsed: &mut u64,
    entropy: &mut TestEntropy,
) -> Result<(), Error> {
    sender.application.hello = Some(hello);
    sender.application.sent = None;
    for _ in 0..144 {
        *elapsed += 10_000;
        let stamp = NonZeroU64::new(*elapsed).ok_or(Error::InvalidInput)?;
        exchange(sender, receiver, stamp, entropy)?;
        exchange(receiver, sender, stamp, entropy)?;
        if let Some(outcome) = sender.application.sent {
            return outcome;
        }
    }
    Err(Error::NotReady)
}

#[test]
fn authenticated_core_hello_publishes_once_and_expires() -> Result<(), Error> {
    let a_signer = EddsaPrivateKey::from_seed([21; 32]);
    let b_signer = EddsaPrivateKey::from_seed([55; 32]);
    let a_identity = Identity::from_seed([21; 32]);
    let b_identity = Identity::from_seed([55; 32]);
    let mut a_storage = Arena::new();
    let mut b_storage = Arena::new();
    let mut a = a_storage.peer(&a_signer, &a_identity, b_signer.public_key(), false)?;
    let mut b = b_storage.peer(&b_signer, &b_identity, a_signer.public_key(), false)?;
    a.add_queue(a.local, b.local, Role::Outbound)?;
    b.add_queue(b.local, a.local, Role::Inbound)?;
    let mut entropy = TestEntropy(2718);
    let mut elapsed = 0;
    let expiration = AbsoluteTime::from_micros(5_000_000);

    exchange_hello(
        &mut a,
        &mut b,
        signed_hello(&b_signer, expiration)?,
        &mut elapsed,
        &mut entropy,
    )?;
    if !a.established() || !b.established() || b.application.publications != 0 {
        return Err(Error::Conflict);
    }
    let own_hello = signed_hello(&a_signer, expiration)?;
    exchange_hello(&mut a, &mut b, own_hello, &mut elapsed, &mut entropy)?;
    exchange_hello(&mut a, &mut b, own_hello, &mut elapsed, &mut entropy)?;
    let expected = Discovered {
        peer: a.local,
        expiration,
        proof: discovery::AddressProof::AuthenticatedCore,
        expected_address: true,
    };
    if b.application.discovered.as_ref() != Some(&expected)
        || b.application.publications != 1
        || b.application.withdrawal.is_some()
        || b.application.expiration.is_some()
        || b.maintenance_deadlines().absolute != Some(expiration)
    {
        return Err(Error::Conflict);
    }

    let at = MonoInstant(elapsed);
    b.maintain(Sample {
        absolute: AbsoluteTime::from_micros(expiration.as_micros() - 1),
        elapsed: at,
    })?;
    if b.application.discovered.as_ref() != Some(&expected) {
        return Err(Error::Deadline);
    }
    let expiry = Sample {
        absolute: expiration,
        elapsed: at,
    };
    b.maintain(expiry)?;
    b.maintain(expiry)?;
    if b.application.discovered.is_some()
        || b.application.publications != 1
        || b.application.expiration != Some(expiration)
        || b.application.expirations != 1
        || b.application.withdrawal.is_some()
        || b.maintenance_deadlines().absolute == Some(expiration)
        || !b.established()
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[test]
fn routed_original_retries_final_span_and_reports_distinct_receipts() -> Result<(), Error> {
    let a_signer = EddsaPrivateKey::from_seed([21; 32]);
    let b_signer = EddsaPrivateKey::from_seed([55; 32]);
    let a_identity = Identity::from_seed([21; 32]);
    let b_identity = Identity::from_seed([55; 32]);
    let mut a_storage = Arena::new();
    let mut b_storage = Arena::new();
    let mut a = a_storage.peer(&a_signer, &a_identity, b_signer.public_key(), false)?;
    let mut b = b_storage.peer(&b_signer, &b_identity, a_signer.public_key(), false)?;
    a.add_queue(a.local, b.local, Role::Outbound)?;
    b.add_queue(b.local, a.local, Role::Inbound)?;
    let mut entropy = TestEntropy(2718);
    let mut elapsed = 0;
    for _ in 0..144 {
        elapsed += 10_000;
        let stamp = NonZeroU64::new(elapsed).ok_or(Error::InvalidInput)?;
        exchange(&mut a, &mut b, stamp, &mut entropy)?;
        exchange(&mut b, &mut a, stamp, &mut entropy)?;
        if a.established() && b.established() {
            break;
        }
    }
    if !a.established()
        || !b.established()
        || !a
            .application
            .reachability
            .is_some_and(|lease| lease.peer == b.local && lease.until > MonoInstant(elapsed))
    {
        return Err(Error::NotReady);
    }

    let original = NonZeroU64::new(11).ok_or(Error::InvalidInput)?;
    let cancelled = NonZeroU64::new(12).ok_or(Error::InvalidInput)?;
    let nonce = [17; 32];
    let signature = a_signer.sign(dv::INIT_PURPOSE, &dv::init_region(100, &nonce))?;
    let learn = dv::initiate(
        PeerId(*a.local.as_bytes()),
        100,
        &nonce,
        signature.as_bytes(),
    );
    a.application.route = Some(Route {
        id: original,
        wire: learn,
        receipt: RoutingReceipt::NativeWrite,
    });
    a.application.offer = true;
    let mut saw_partial = false;
    let mut refused = [0; 128];
    let mut refused_len = 0;
    let mut final_attempts = 0;
    for _ in 0..96 {
        elapsed += 10_000;
        let stamp = NonZeroU64::new(elapsed).ok_or(Error::InvalidInput)?;
        let previous = a.application.route_admitted;
        let result = exchange_with(
            &mut a,
            &mut b,
            stamp,
            &mut entropy,
            |outgoing| match outgoing {
                Outgoing::Buffered(wire) => {
                    if let Ok(fragment) = Fragment::decode(wire)
                        && usize::from(fragment.total) == learn.len()
                    {
                        if usize::from(fragment.offset) + fragment.body.len() == learn.len() {
                            return Err(Error::Conflict);
                        }
                        saw_partial = true;
                    }
                    Ok(())
                }
                Outgoing::ObserveNative { message, id } => {
                    let span = Fragment::decode(message)?;
                    if id != original || usize::from(span.offset) + span.body.len() != learn.len() {
                        return Err(Error::Conflict);
                    }
                    final_attempts += 1;
                    if final_attempts == 1 {
                        refused_len = message.len();
                        refused
                            .get_mut(..refused_len)
                            .ok_or(Error::Capacity)?
                            .copy_from_slice(message);
                        return Err(Error::WouldBlock);
                    }
                    if message != &refused[..refused_len] {
                        return Err(Error::Conflict);
                    }
                    Ok(())
                }
            },
        );
        if result == Err(Error::WouldBlock) {
            if a.application.route_admitted != previous {
                return Err(Error::Conflict);
            }
        } else {
            result?;
        }
        exchange(&mut b, &mut a, stamp, &mut entropy)?;
        if b.application.route_received == Some(learn) && b.application.delivered {
            break;
        }
    }
    if !saw_partial
        || final_attempts != 2
        || b.application.route_received != Some(learn)
        || !b.application.delivered
        || a.application.route_admitted != Some((original, Ok(())))
        || a.application.route_written.is_some()
    {
        return Err(Error::Conflict);
    }
    let written = MonoInstant(elapsed + 1);
    a.outgoing_written(cancelled, Ok(()), written);
    if a.application.route_written.is_some() {
        return Err(Error::Conflict);
    }
    a.outgoing_written(original, Ok(()), written);
    if a.application.route_written != Some((original, Ok(()), written)) {
        return Err(Error::Conflict);
    }

    a.application.route = Some(Route {
        id: cancelled,
        wire: learn,
        receipt: RoutingReceipt::NativeWrite,
    });
    a.application.route_admitted = None;
    for _ in 0..16 {
        elapsed += 10_000;
        let stamp = NonZeroU64::new(elapsed).ok_or(Error::InvalidInput)?;
        exchange(&mut a, &mut b, stamp, &mut entropy)?;
        if a.routing.fragmented() {
            break;
        }
    }
    if !a.routing.fragmented() || a.application.route_admitted.is_some() {
        return Err(Error::NotReady);
    }
    let reachability_changes = a.application.reachability_changes;
    a.remove_queue();
    a.remove_queue();
    if a.application.route_admitted != Some((cancelled, Err(Error::Closed)))
        || a.application.route_written != Some((original, Ok(()), written))
        || a.application.reachability.is_some()
        || a.application.reachability_changes != reachability_changes + 1
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
