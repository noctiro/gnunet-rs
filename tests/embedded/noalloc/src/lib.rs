//! Compile the official protocol foundation without an allocator or host runtime.
//!
//! This is a library build proof. It does not claim to measure firmware RAM,
//! stack use or a whole-node deployment on physical microcontrollers.
#![no_std]
#![forbid(unsafe_code)]

use gnunet::{
    clients::{resolver, resolver_handle, statistics},
    crypto, gnscrypto, gnsrecord, hello,
    types::{AbsoluteTime, Duration, Error, MonoInstant},
    wire,
};

/// Compile actual shared packet parsing/checksums without alloc or platform IO.
pub fn exercise_vpn_packet(raw: &[u8]) -> Result<u16, Error> {
    let packet = gnunet::vpn::packet::Packet::parse(raw)?;
    packet.validate_checksums()?;
    Ok(gnunet::vpn::packet::checksum(packet.segment()))
}

/// Compile actual EXIT prefix policy with borrowed fixed-width address storage.
pub fn exercise_exit_prefix(
    prefix: gnunet::exit::policy::Prefix,
    address: gnunet::vpn::Address,
) -> Result<bool, Error> {
    prefix.validate()?;
    Ok(prefix.contains(address))
}

/// Compile PEERSTORE admission and original source cleanup with caller storage.
pub fn exercise_peerstore_service<'bytes>(
    instance: &mut gnunet::peerstore::Instance,
    clients: &mut [gnunet::peerstore::ClientSlot],
    operations: &mut [gnunet::peerstore::OperationSlot<'bytes>],
    messages: &mut [gnunet::peerstore::MessageSlot<'bytes>],
    limits: gnunet::peerstore::Limits,
) -> Result<(), Error> {
    let mut service =
        gnunet::peerstore::Service::new(instance, clients, operations, messages, limits)?;
    let client = service.attach()?;
    let _loss = service.detach(client)?;
    Ok(())
}

/// Compile the actual DATASTORE service with caller-provided connection storage.
pub fn datastore_accounting<B: gnunet::datastore::backend::Backend>(
    instance: &mut gnunet::datastore::Instance,
    clients: &mut [gnunet::datastore::ClientSlot],
    reservations: &mut [gnunet::datastore::ReservationSlot],
    backend: &B,
) -> Result<gnunet::datastore::Accounting, Error> {
    gnunet::datastore::Service::new(
        instance,
        clients,
        reservations,
        gnunet::datastore::Config::default(),
    )?
    .accounting(backend)
}

/// Compile FS query admission and original local lookup ownership without alloc.
pub fn exercise_fs_service<'id>(
    instance: &'id mut gnunet::fs::service::Instance,
    clients: &mut [gnunet::fs::service::ClientSlot],
    queries: &mut [gnunet::fs::service::QuerySlot<'_>],
    search: gnunet::wire::fs::Search<'_>,
) -> Result<(), Error> {
    let mut service =
        gnunet::fs::service::Service::new(instance, clients, queries, Default::default())?;
    let client = service.connect()?;
    service.admit(client, search)?;
    if let Some(lookup) = service.next_local()? {
        service.local_unavailable(lookup)?;
    }
    service.disconnect(client)
}

/// Parse and encode actual FS public artifacts without an allocator or OS port.
/// Signature verification authenticates an artifact; it does not establish expiry.
pub fn exercise_fs_uri(input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    gnunet::fs::Uri::parse(input, gnunet::fs::Limits::default())?.encode(output)
}

/// Compile actual FS content encryption/authentication and empty-file ownership
/// with caller storage. This is no allocator proof, not a physical RAM benchmark.
pub fn exercise_fs_content(output: &mut [u8; 16]) -> Result<gnunet::fs::Content, Error> {
    let mut keys = [];
    let mut encoder = gnunet::fs::content::FileEncoder::new(0, &mut keys)?;
    let encoded = encoder.push_data(&[], output)?;
    gnunet::fs::content::open_data(encoded.block().key(), encoded.block().bytes(), &mut [])?;
    let content = encoder.content().ok_or(Error::NotReady)?;
    gnunet::fs::content::NodeRef::root(content).open(output, &mut [])?;
    Ok(content)
}

/// Compile the actual noalloc metadata planner/parser and pure Rust inflater.
/// This library proof is not a physical-device stack/RAM or compression claim.
pub fn exercise_fs_metadata(output: &mut [u8; 12]) -> Result<(), gnunet::fs::metadata::Error> {
    use gnunet::fs::metadata::{self, Decoded, Limits, Mode, Options};
    let plan =
        metadata::plan_uncompressed(&[], &mut [], &mut [], Limits::default(), Options::default())?;
    plan.write(output)?;
    let parsed = metadata::decode_uncompressed(output, Limits::default(), Mode::Strict)?;
    if !matches!(parsed, Decoded::Present(value) if value.is_complete() && value.accepted_entries() == 0)
    {
        return Err(metadata::Error::Invalid);
    }
    // A complete zlib empty-body member: no allocation or native codec backend.
    let compressed = [
        0x80, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0x78, 0x9c, 0x03, 0, 0, 0, 0, 1,
    ];
    let parsed = metadata::decode(
        &compressed,
        &mut [],
        &mut gnunet::fs_codec::Inflate::new(),
        Limits::default(),
        Mode::Strict,
    )?;
    if !matches!(parsed, Decoded::Present(value) if value.is_complete() && value.was_compressed()) {
        return Err(metadata::Error::Invalid);
    }
    Ok(())
}

/// Compile real directory plans/lending parse/inline encoding without allocation.
/// This library check grants no source-chain, filesystem or physical RAM proof.
pub fn exercise_fs_directory(output: &mut [u8; 24]) -> Result<(), gnunet::fs::directory::Error> {
    use gnunet::fs::{directory as dir, metadata as md};
    let mut metadata_bytes = [0; 12];
    let metadata_plan = md::plan_uncompressed(
        &[],
        &mut [],
        &mut [],
        md::Limits::default(),
        md::Options::default(),
    )
    .map_err(dir::Error::Metadata)?;
    let root = dir::PreparedMetadata::materialize(&metadata_plan, &mut metadata_bytes)?;
    let plan = dir::plan(root, &[], &mut [], dir::BuildOptions::default())?;
    plan.write(output)?;
    let mut carry = [0; 24];
    let mut parser = dir::Parser::new(&mut carry, dir::Limits::default(), dir::Policy::default());
    let mut inflater = gnunet::fs_codec::Inflate::new();
    let event = parser
        .feed(
            dir::Segment {
                base: 0,
                bytes: output,
                final_extent: Some(24),
            },
            &mut [],
            &mut inflater,
        )
        .map_err(|failure| failure.error)?;
    if !matches!(
        event.status,
        dir::Status::Event(dir::Event::Directory { .. })
    ) {
        return Err(dir::Error::Input);
    }
    let final_state = parser
        .feed(
            dir::Segment {
                base: 24,
                bytes: &[],
                final_extent: None,
            },
            &mut [],
            &mut inflater,
        )
        .map_err(|failure| failure.error)?;
    if !matches!(final_state.status, dir::Status::Complete(_)) {
        return Err(dir::Error::Input);
    }
    let mut encoded = [0; 16];
    let content = gnunet::fs::content::encode_data(&[], &mut encoded)
        .map_err(dir::Error::Content)?
        .key()
        .content(0);
    let hint = dir::InlineHint {
        index: 0,
        item: md::Item {
            kind: 174,
            format: md::Format::Binary,
            data: &[],
            plugin: None,
            mime: None,
        },
    };
    dir::verify_inline(
        hint,
        content.uri(),
        dir::InlineBuffers {
            keys: &mut [],
            index: &mut [],
            encoded: &mut encoded,
        },
        16,
    )?;
    Ok(())
}

/// Encode the actual TRANSPORT challenge using caller-supplied public inputs.
/// The allocation-backed service engine and native host remain separate profiles.
pub fn exercise_transport(nonce: [u8; 32], origin: u64) -> [u8; 48] {
    gnunet::transport::p2p::Challenge { nonce, origin }.encode()
}

/// Instantiate actual PILS identity/signature ownership without an allocator.
/// This is a library build proof, with no service/node or stack measurement claim.
pub fn exercise_pils(seed: [u8; 32]) -> Result<[u8; 32], Error> {
    let service = gnunet::pils::Service::<176>::new(
        gnunet::pils::MasterKey::from_seed(seed),
        gnunet::pils::Profile::Reference029,
        0,
        gnunet::pils::HelloLimits {
            maximum_input_bytes: 176,
            maximum_address_bytes: 0,
            maximum_addresses: 0,
        },
    )?;
    Ok(*service.identity().public_key().as_bytes())
}

/// Instantiate the public typed PILS client and encode caller public material.
/// This exercises ownership without native I/O or a remote completion claim.
pub fn exercise_pils_client(public: [u8; 32], output: &mut [u8; 128]) -> Result<usize, Error> {
    use gnunet::pils::client::{Client, Instance, KeyTarget};
    let mut instance = Instance::new();
    let mut client = Client::<2, 128, 176>::new(
        &mut instance,
        gnunet::pils::Profile::Reference029,
        gnunet::pils::HelloLimits {
            maximum_input_bytes: 176,
            maximum_address_bytes: 0,
            maximum_addresses: 0,
        },
    )?;
    let operation = client.ecdh(public, KeyTarget::ServiceCurrent)?;
    let epoch = client.begin_connection(AbsoluteTime::UNIX_EPOCH)?;
    let request = client.next_request(epoch, output)?.ok_or(Error::NotReady)?;
    client.written(epoch, request.transmit)?;
    client.cancel(operation)?;
    let _closed = client.close();
    Ok(request.len)
}

/// Construct the actual CAKE owner and encode a first flight using caller entropy.
/// This compile fixture has no native I/O and makes no established-peer claim.
pub fn exercise_core(
    seed: [u8; 32],
    peer: [u8; 32],
    entropy: &mut impl crypto::Entropy,
    output: &mut [u8; 256],
) -> Result<usize, Error> {
    let identity = gnunet::core::session::Identity::from_seed(seed);
    let mut owner = gnunet::core::session::Session::<256>::new(
        &identity,
        crypto::EddsaPublicKey::from_bytes(peer),
        gnunet::core::wire::WordOrder::Little,
        &[],
    )?;
    match owner.tick(0, entropy, output)? {
        gnunet::core::session::Event::Send(size) => Ok(size),
        gnunet::core::session::Event::None => Ok(0),
        _ => Err(Error::Malformed),
    }
}

/// Instantiate the resolver FIFO, encode its original request and cancel/drain
/// its owner without an allocator, native calls or a runtime. The explicit Linux
/// family profile is a codec input; no host ABI is inferred on a microcontroller.
pub fn exercise_resolver(output: &mut [u8; 128]) -> Result<usize, Error> {
    let mut owner =
        resolver_handle::ResolverHandle::<2, 32>::new(resolver::FamilyProfile::LINUX, true)?;
    let id = owner.ip_get(
        b"example.invalid",
        resolver::Family::Any,
        Duration(50_000),
        AbsoluteTime::from_micros(0),
    )?;
    let epoch = owner.begin_connection(AbsoluteTime::from_micros(1_000))?;
    let outgoing = owner.next_request(epoch, output, AbsoluteTime::from_micros(1_000))?;
    let decoded = resolver::Request::decode(
        wire::Frame::decode(&output[..outgoing.len])?,
        resolver::FamilyProfile::LINUX,
    )?;
    if decoded.id() != outgoing.wire_id {
        return Err(Error::Malformed);
    }
    owner.request_cancel(id, AbsoluteTime::from_micros(1_000))?;
    if owner.disconnect()? != Some(epoch) || owner.pending_requests() != 0 {
        return Err(Error::Malformed);
    }
    Ok(outgoing.len)
}

/// Encode a real GET, inspect its frame, serialize one GNS A record, and sign
/// a purpose region with a caller-provided seed using only caller/stack buffers.
pub fn exercise(seed: [u8; 32], output: &mut [u8; 128]) -> Result<[u8; 32], Error> {
    let len = statistics::Selector {
        subsystem: b"core",
        name: b"peers",
    }
    .encode_get(output)?;
    let frame = wire::Frame::decode(&output[..len])?;
    if frame.header().message_type() != wire::message_type::STATISTICS_GET {
        return Err(Error::Malformed);
    }
    let record = gnsrecord::RecordData {
        expiration_time: 1_000_000,
        record_type: gnsrecord::RecordType::new(1),
        flags: gnsrecord::RecordFlags::from_bits_preserve(0),
        data: &[192, 0, 2, 1],
    };
    let len = gnsrecord::serialize(&[record], output)?;
    let records = gnsrecord::RecordSet::parse(&output[..len], 1, 1)?;
    if records.len() != 1 {
        return Err(Error::Malformed);
    }
    let mut region = [0; 8];
    wire::SignaturePurpose::new(7, 0)?.encode(&mut region)?;
    let key = crypto::EddsaPrivateKey::from_seed(seed);
    let signature = key.sign(7, &region)?;
    key.public_key().verify(7, &region, &signature)?;
    let mut statistics = gnunet::statistics::Statistics::<2, 32, 1, 1, 2>::new();
    let client = statistics.connect()?;
    statistics.set(
        client,
        statistics::Set {
            selector: statistics::Selector {
                subsystem: b"app",
                name: b"counter",
            },
            flags: 0,
            value: 7,
        },
    )?;
    statistics.disconnect(client)?;
    Ok(crypto::hash256(&output[..len]))
}

/// Normalize a GNS label and seal, verify and open an EDKEY record block using
/// caller and stack storage. This includes the actual GNS cryptographic graph.
pub fn exercise_gns(seed: [u8; 32], output: &mut [u8; 512]) -> Result<[u8; 64], Error> {
    let mut scalars = ['\0'; 16];
    let mut text = [0; 32];
    let label = gnscrypto::Label::normalize("e\u{301}", &mut scalars, &mut text)?;
    let zone = gnscrypto::ZoneSecret::Edkey(crypto::gns::EdkeySecret::from_seed(seed));
    let records = [gnsrecord::RecordData {
        expiration_time: 1_000_000,
        record_type: gnsrecord::RecordType::A,
        flags: gnsrecord::RecordFlags::from_bits_preserve(0),
        data: &[192, 0, 2, 1],
    }];
    let mut serialized = [0; 64];
    let length = gnsrecord::serialize(&records, &mut serialized)?;
    let block = zone.seal(label, 1_000_000, &serialized[..length], output)?;
    let verified = block.verify_for(zone.public_key(), label)?;
    let mut plaintext = [0; 64];
    let opened = verified.open_at(0, &mut plaintext)?;
    if opened.iter().next().ok_or(Error::NotFound)??.data != records[0].data {
        return Err(Error::Malformed);
    }
    gnscrypto::query(zone.public_key(), label)
}

/// Build, encode and verify an official HELLO without an allocator. The normal
/// reference profile authenticates metadata only; the result must retain that
/// distinction rather than authorize its carried addresses.
pub fn exercise_hello(seed: [u8; 32], output: &mut [u8; 512]) -> Result<[u8; 32], Error> {
    let limits = hello::Limits {
        maximum_input_bytes: 512,
        maximum_address_bytes: 128,
        maximum_addresses: 4,
    };
    let mut addresses = [0; 128];
    let mut builder = hello::HelloBuilder::new(&mut addresses, limits);
    builder.add_address(b"tcp://127.0.0.1:2086")?;
    let key = crypto::EddsaPrivateKey::from_seed(seed);
    let value = builder.sign(
        &key,
        hello::AbsoluteTime::from_micros(1_000_000),
        hello::SignatureProfile::Gnunet029,
    )?;
    let size = value.encode_message(output)?;
    let mut parsed = [0; 128];
    let value = hello::Hello::parse_message(&output[..size], None, &mut parsed, limits)?;
    let verified = value.verify_at(
        hello::SignatureProfile::Gnunet029,
        hello::AbsoluteTime::UNIX_EPOCH,
    )?;
    if verified.coverage() != hello::SignatureCoverage::MetadataOnly {
        return Err(Error::Authentication);
    }
    Ok(*verified.hello().peer().as_bytes())
}

/// Encode and parse a DNS query with separate caller slots/arena, then expose
/// one lazy DNSSTUB open effect. This compiles the real cores without a heap;
/// it does not claim that a host socket was opened or that a response arrived.
pub fn exercise_dns(output: &mut [u8; 128]) -> Result<usize, Error> {
    use gnunet::{dns, dnsstub};
    let mut names = [0; 64];
    let mut names = dns::Arena::new(&mut names);
    let name = dns::Name::from_dotted(b"example.invalid", &mut names)?;
    let queries = [dns::Query {
        name,
        kind: dns::Type::A,
        class: 1,
    }];
    let packet = dns::Packet::new([0x12, 0x34], 0x0100, &queries, &[], &[], &[]);
    let n = packet.encode(dns::AbsoluteTime::UNIX_EPOCH, output)?;
    let mut storage = [0; 64];
    let mut arena = dns::Arena::new(&mut storage);
    let mut query_slots = [dns::Query::EMPTY; 1];
    let mut record_slots = [];
    let parsed = dns::Packet::parse(
        &output[..n],
        dns::AbsoluteTime::UNIX_EPOCH,
        &mut arena,
        &mut query_slots,
        &mut record_slots,
        dns::Limits::DNS,
    )?;
    if parsed.id != [0x12, 0x34] || parsed.queries != queries {
        return Err(Error::Malformed);
    }
    let mut stub = dnsstub::DnsStub::<1, 64, 1>::new()?;
    stub.add_dns_ip("127.0.0.1")?;
    let admission = stub.resolve(&output[..n], MonoInstant(0), |_| Ok(0))?;
    if admission.evicted.is_some() || stub.query(admission.request)? != &output[..n] {
        return Err(Error::Malformed);
    }
    if !matches!(
        stub.next_action(MonoInstant(0))?,
        Some(dnsstub::Action::OpenSocket { .. })
    ) {
        return Err(Error::Malformed);
    }
    stub.resolve_cancel(admission.request)?;
    let _stopped = stub.stop();
    Ok(n)
}

/// Exercise complete native IDNA and DNS text composition with explicit Unicode
/// profiles and caller scratch; no locale, allocation, native FFI or DNS is used.
pub fn exercise_idna(output: &mut [u8; 128]) -> Result<usize, Error> {
    use gnunet::{dns, idna};
    let mut native = idna::Workspace::new();
    let backend = idna::Backend::new(
        &mut native,
        idna::Limits::GNUNET,
        idna::NativeProfile::Libunistring1_5Unicode18_0,
    );
    let mut storage = [0; 64];
    let mut arena = dns::Arena::new(&mut storage);
    let mut work = [0; 255];
    let name = dns::Name::from_native_text(
        "bücher.invalid".as_bytes(),
        &backend,
        &mut work,
        &mut arena,
        dns::Limits::DNS,
    )?;
    if name.wire() != b"\x0dxn--bcher-kva\x07invalid\0" {
        return Err(Error::Malformed);
    }
    name.write_native_text(&backend, &mut work, output)
}

/// Compose native IDNA graph staging and conservative prefix packing without an allocator.
pub fn exercise_native_pack(output: &mut [u8; 128]) -> Result<usize, Error> {
    use gnunet::{dns, idna};
    let mut native = idna::Workspace::new();
    let backend = idna::Backend::new(
        &mut native,
        idna::Limits::GNUNET,
        idna::NativeProfile::Libunistring1_5Unicode18_0,
    );
    let mut source = [0; 64];
    let mut arena = dns::Arena::new(&mut source);
    let query = [dns::Query {
        name: dns::Name::from_dotted(b"EXAMPLE", &mut arena)?,
        kind: dns::Type::A,
        class: dns::class::INTERNET,
    }];
    let packet = dns::Packet::new([1, 2], 0x0100, &query, &[], &[], &[]);
    let mut work = [0; 255];
    let mut text = [0; 255];
    let mut scratch = dns::NativeScratch::new(&mut work, &mut text, dns::Limits::DNS);
    let mut copied = [0; 64];
    let mut arena = dns::Arena::new(&mut copied);
    let mut queries = [dns::Query::EMPTY; 1];
    let mut records = [];
    let result = packet.pack_native(
        dns::AbsoluteTime::UNIX_EPOCH,
        &backend,
        &mut scratch,
        &mut arena,
        &mut queries,
        &mut records,
        output,
        128,
    )?;
    if result.truncated || &output[12..21] != b"\x07example\0" {
        return Err(Error::Malformed);
    }
    Ok(result.written)
}

/// Construct and retire a resolver owner using only caller arrays and transaction storage.
pub fn exercise_resolver_service() -> Result<(), Error> {
    use gnunet::resolver_service::{
        cache::CacheBuffers,
        owner::{Buffers, ClientSlot, Effect, EffectSlot, LookupSlot, Resolver},
        pool::BlobSlot,
        storage::Limits,
    };
    struct Storage {
        clients: [ClientSlot; 1],
        lookups: [LookupSlot; 1],
        effects: [EffectSlot; 1],
        cleanups: [Option<gnunet::dnsstub::RequestId>; 1],
        blobs: [BlobSlot; 8],
        bytes: [u8; 256],
    }
    impl Storage {
        const fn new() -> Self {
            Self {
                clients: [ClientSlot::EMPTY; 1],
                lookups: [LookupSlot::EMPTY; 1],
                effects: [EffectSlot::EMPTY; 1],
                cleanups: [None; 1],
                blobs: [BlobSlot::EMPTY; 8],
                bytes: [0; 256],
            }
        }
        fn buffers(&mut self) -> Buffers<'_> {
            Buffers {
                clients: &mut self.clients,
                lookups: &mut self.lookups,
                cache: CacheBuffers {
                    hosts: &mut [],
                    buckets: &mut [],
                    records: &mut [],
                },
                effects: &mut self.effects,
                cleanups: &mut self.cleanups,
                blobs: &mut self.blobs,
                bytes: &mut self.bytes,
            }
        }
    }
    let mut backing = Storage::new();
    let mut staging = Storage::new();
    let mut owner = Resolver::new(
        backing.buffers(),
        Limits {
            max_name_bytes: 255,
            max_record_bytes: 65535,
            cname_hops: 4,
        },
        1,
    )?;
    let mut scratch = owner.make_scratch(staging.buffers())?;
    let _client = owner.connect()?;
    owner.shutdown(&mut scratch)?;
    let ticket = owner.take_effect()?.ok_or(Error::NotReady)?;
    if owner.effect(ticket)? != Effect::Stop {
        return Err(Error::Malformed);
    }
    owner.release_effect(ticket)?;
    Ok(())
}

/// Drive the ARM TEST/LIST/cancel queue using explicit peer ABI and caller arrays.
pub fn exercise_arm(output: &mut [u8; 128]) -> Result<usize, Error> {
    use gnunet::arm::{
        FrameSlot,
        client::{Client, Effect, OperationSlot},
        wire::ArmAbi,
    };
    let mut operations = [OperationSlot::EMPTY; 2];
    let mut frames = [FrameSlot::EMPTY; 2];
    let mut bytes = [0; 128];
    let mut client = Client::new(
        &mut operations,
        &mut frames,
        &mut bytes,
        1,
        ArmAbi::U64Align8,
    )?;
    let Some(Effect::Connect(connection)) =
        client.take_effect(gnunet::types::AbsoluteTime::from_micros(0))?
    else {
        return Err(Error::NotReady);
    };
    client.connection_admitted(connection)?;
    let test = client.take_frame()?.ok_or(Error::NotReady)?;
    if client.frame(test)? != [0, 4, 0, 15] {
        return Err(Error::Malformed);
    }
    client.frame_written(test)?;
    let operation = client.request_service_list()?;
    client.operation_cancel(operation)?;
    let ticket = client.take_frame()?.ok_or(Error::NotReady)?;
    let frame = client.frame(ticket)?;
    let length = frame.len();
    output
        .get_mut(..length)
        .ok_or(Error::Capacity)?
        .copy_from_slice(frame);
    client.frame_written(ticket)?;
    let _connection = client.disconnect();
    Ok(length)
}

/// Instantiate erased X25519/KDF/CAKE record owners and authenticate without allocation.
pub fn exercise_session_crypto(output: &mut [u8; 128]) -> Result<(), Error> {
    use gnunet::session_crypto::{exchange::EcdheSecret, hpke, session, udp};
    let private = EcdheSecret::from_bytes([7; 32]);
    let public = private.public_key();
    let dh = private.exchange_raw(public)?;
    let prk = dh.extract(b"embedded-witness");
    let traffic = session::application_traffic(&prk, &[0; 64], session::Role::Initiator)?;
    output[..16].fill(0x35);
    let (tag, sequence) = session::seal_record(&traffic, 1, &mut output[..16])?;
    if session::open_record(&traffic, &tag, &sequence, &mut output[..16])? != 1
        || output[..16] != [0x35; 16]
    {
        return Err(Error::Authentication);
    }
    let key = udp::DatagramKey::derive(&prk, 1)?;
    let length = key.seal_box(b"embedded", output)?;
    let mut plaintext = [0; 8];
    if key.open_box(&output[..length], &mut plaintext)? != 8 || &plaintext != b"embedded" {
        return Err(Error::Authentication);
    }
    let ephemeral = EcdheSecret::from_bytes([9; 32]);
    let info = b"embedded-context";
    let (enc, mut sender) =
        hpke::sender_setup2(&ephemeral, None, public, &hpke::Parameters::base(info))?;
    let mut receiver = hpke::receiver_setup(enc, &private, info)?;
    let length = sender.seal(&[], b"embedded", output)?;
    if receiver.open(&[], &output[..length], &mut plaintext)? != 8 || &plaintext != b"embedded" {
        return Err(Error::Authentication);
    }
    Ok(())
}

/// Instantiate ARM server storage and inspect its explicit shutdown request.
/// No actual listener/process/timer admission or native shutdown is acknowledged.
pub fn exercise_arm_service() -> Result<(), gnunet::arm_service::Error> {
    use gnunet::arm::wire::ArmAbi;
    use gnunet::arm_service::{ClientSlot, Error, FrameSlot, Owner, OwnerScope};
    let mut scope = OwnerScope::new();
    let mut services = [];
    let mut listeners = [];
    let mut clients = [ClientSlot::new()];
    let mut bytes = [0; 4];
    let mut frames = [FrameSlot::new(&mut bytes)];
    let mut owner = Owner::new(
        &mut scope,
        &[],
        &mut services,
        &mut clients,
        &mut listeners,
        &mut frames,
        ArmAbi::U64Align8,
    )?;
    if owner.startup_next()? {
        return Err(Error::Malformed);
    }
    let client = owner.connect()?;
    owner.test(client)?;
    let frame = owner.frame().ok_or(Error::Malformed)?;
    if frame.bytes != [0, 4, 0, 15] {
        return Err(Error::Malformed);
    }
    let ticket = frame.ticket;
    owner.release_frame(ticket)?;
    owner.begin_shutdown(0);
    if owner.take_runtime_shutdown().is_none() {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// Invoke the installed BLOCK callback path with caller-owned storage and no heap.
pub fn exercise_block(storage: &mut [u8; 8], output: &mut [u8; 12]) -> Result<usize, Error> {
    use gnunet::block::{
        BlockType,
        bloom::NativeEndian,
        callbacks::CallbackContext,
        plugins::{GroupSizing, Plugin},
    };
    let context = CallbackContext::new([Plugin::Test], NativeEndian::native());
    let group = context.create_group(
        BlockType::TEST,
        GroupSizing::FilterBytes(8),
        None,
        17,
        storage,
    )?;
    gnunet::block::group_serialize(group.as_ref(), output)?.ok_or(Error::NotReady)
}

/// Exercise the public allocation-free NSE client and binary64 wire values.
pub fn exercise_nse_client() -> Result<(), gnunet::types::Error> {
    use gnunet::clients::nse::{Client, Double, Estimate, Instance};
    let mut instance = Instance::new();
    let mut client = Client::new(&mut instance);
    let epoch = client.begin_connection()?;
    let start = client.prepare_start(epoch)?;
    client.written(&start)?;
    let estimate = Estimate {
        timestamp: gnunet::wire::AbsoluteTime::from_micros(1),
        log2_size: Double::from_bits(0),
        deviation: Double::from_bits(0x7ff8_0000_0000_0000),
    };
    let mut frame = [0; 32];
    estimate.encode(&mut frame)?;
    let _ = client.receive(epoch, &frame)?;
    client.retire(epoch)?;
    Ok(())
}

/// Encode and borrow an official NSE flood without heap storage or crypto credit.
pub fn exercise_nse_flood(output: &mut [u8; 132]) -> Result<(), gnunet::types::Error> {
    use gnunet::wire::nse::flood::{Fields, Message};
    let fields = Fields {
        hops: 0,
        timestamp: gnunet::wire::AbsoluteTime::from_micros(1),
        matching_bits: 0,
        origin: [0; 32],
        proof: [0; 8],
        signature: [0; 64],
    };
    fields.encode(output)?;
    if Message::decode(output)?.fields()? != fields {
        return Err(gnunet::types::Error::Malformed);
    }
    Ok(())
}

/// Instantiate shared PoW without owning a large buffer or selecting a host.
pub fn exercise_crypto_pow(
    salt: &[u8; 16],
    input: &[u8],
    output: &mut [u8; 64],
    memory: &mut [gnunet::crypto::pow::Block],
) -> Result<(), Error> {
    gnunet::crypto::pow::hash(salt, input, output, memory)
}

/// Instantiate pure NSE ownership with caller-provided storage and no native service.
pub fn exercise_nse_service(instance: &mut gnunet::nse::owner::Instance) -> Result<(), Error> {
    let mut owner =
        gnunet::nse::owner::Service::<2, 2>::new(instance, gnunet::nse::owner::Config::default())?;
    let mut start = [0; 4];
    gnunet::wire::nse::encode_start(&mut start)?;
    let subscriber = owner.subscribe(&start)?;
    if let Some(notification) = owner.next_notification(0)? {
        owner.notified(&notification)?;
    }
    owner.unsubscribe(subscriber)?;
    owner.close();
    Ok(())
}

/// Compile actual official UDP codec/transcript boundaries without heap storage.
pub fn exercise_udp(output: &mut [u8; 72]) -> Result<[u8; 112], Error> {
    let ack = gnunet::udp::wire::Ack {
        allowed: 128,
        cmac: [0; 64],
    };
    ack.encode(output)?;
    if gnunet::udp::wire::Ack::decode_backchannel(output)? != ack {
        return Err(Error::Malformed);
    }
    Ok(gnunet::udp::wire::handshake_region(
        [1; 32], [2; 32], &[3; 32], 1,
    ))
}

/// Discover a configured GNS Start Zone without an allocator or native runtime.
pub fn exercise_gns_start_zone(zone: gnunet::gnsrecord::ZoneKey) -> Result<bool, Error> {
    let mappings = [gnunet::gns::Mapping {
        suffix: "gns.alt",
        zone,
    }];
    let found = gnunet::gns::select_start_zone("host.gns.alt", &mappings)?;
    Ok(found.zone == zone && found.name == "host")
}

/// Compile actual SETU IBF caller storage without enabling alloc/zlib/service.
pub fn exercise_setu_ibf(cells: &mut [gnunet::setu::ibf::Cell]) -> Result<bool, Error> {
    Ok(gnunet::setu::ibf::Ibf::clear(cells, 3, gnunet::setu::ibf::Order::native())?.is_empty())
}

/// Construct an official REGEX block using only caller storage.
pub fn exercise_regex(output: &mut [u8]) -> Result<usize, Error> {
    let (_, destination) = gnunet::regex::first_key(b"prefix");
    let edges = [gnunet::regex::BlockEdge {
        destination,
        label: b"prefix",
    }];
    gnunet::regex::encode_state(b"", false, edges.as_slice(), output)
}

/// Compile the official IDENTITY wire/core without allocating or opening a store.
pub fn exercise_identity(output: &mut [u8; 4]) -> Result<u32, Error> {
    gnunet::wire::identity::Request::Start.encode(output)?;
    Ok(gnunet::identity::Code::NONE.value())
}

/// Verify public NAMECACHE responses with caller-owned encrypted block storage.
pub fn exercise_namecache(query: &[u8; 64], body: &[u8]) -> Result<bool, Error> {
    Ok(
        gnunet::namecache::verify_lookup(query, gnunet::wire::AbsoluteTime::from_micros(1), body)?
            .is_some(),
    )
}

/// Encode active NAMESTORE control IPC without heap storage or zone secrets.
pub fn exercise_namestore(output: &mut [u8; 8]) -> Result<usize, Error> {
    gnunet::wire::namestore::Request::IterateStop { rid: 1 }.encode(output)
}

/// Normalize NAMESTORE labels using only explicitly provided scalar storage.
pub fn exercise_namestore_label(
    input: &[u8],
    output: &mut [u8],
    scalars: &mut [u32],
    normalized: &mut [u32],
    ordering: &mut [u32],
) -> Result<usize, Error> {
    gnunet::namestore::normalize_label(input, output, scalars, normalized, ordering, 255)
}

/// Instantiate the borrowed DATACACHE storage contract without a memory backend.
pub fn exercise_datacache<S: gnunet::datacache::Storage>(
    cache: &gnunet::datacache::Cache<S>,
) -> usize {
    cache.stats().entries
}

/// Compile the RECLAIM structural parser without allocator, credentials or IO.
pub fn exercise_reclaim_attribute(input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    gnunet::reclaim::Attribute::decode(input)?.encode(output)
}

/// Compile all MESSENGER typed body paths without allocator or cryptography.
pub fn exercise_messenger_body(kind: u32, input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    use gnunet::messenger::wire::{body::Body, envelope::Kind, profile::Profile};
    Body::decode(Kind::new(kind), input, Profile::LITTLE_255)?.encode(Profile::LITTLE_255, output)
}

/// Compile state limits without enabling allocated rooms or runtime owners.
pub fn exercise_messenger_state_limits(
    limits: gnunet::messenger_core::Limits,
) -> Result<(), gnunet::messenger_core::Error> {
    limits.validate()
}

/// Compile credential text conversion with caller memory and no trust assertion.
pub fn exercise_reclaim_credential_string(
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, gnunet::reclaim_credentials::Failure> {
    gnunet::reclaim_credentials::credential_from_string(
        gnunet::reclaim::CredentialType::JWT,
        input,
        output,
    )
}

/// Compile bounded complete JSON parsing through caller-owned metadata buffers.
pub fn exercise_json(
    input: &[u8],
    payload: &mut [u8],
    tokens: &mut [gnunet::json::Token],
    stack: &mut [gnunet::json::Nest],
) -> Result<usize, Error> {
    let mut workspace = gnunet::json::Workspace::new(payload, tokens, stack);
    Ok(workspace
        .parse(input, gnunet::json::Limits::default())?
        .expose_json()
        .len())
}

/// Compile the shared noalloc record text port with an explicit IDNA provider.
pub fn exercise_record_text(
    idna: &impl gnunet::gnsrecord_text::Idna,
    workspace: gnunet::gnsrecord_text::Workspace<'_>,
    kind: gnunet::gnsrecord_text::RecordType,
    text: &str,
    output: &mut [u8],
) -> Result<usize, Error> {
    use gnunet::gnsrecord_text::{Codec, Limits, Profile};
    Codec::new(idna, workspace, Profile::LITTLE_255, Limits::default())?
        .string_to_value(kind, text, output)
}

/// Compile the shared HTTP request parser without runtime or allocator.
pub fn exercise_rest_request(input: &[u8]) -> Result<usize, Error> {
    Ok(
        gnunet::rest::http::Request::parse(input, gnunet::rest::http::Limits::default())?
            .consumed(),
    )
}

/// Compile typed DID formatting without allocator, key derivation or native IO.
pub fn exercise_did(input: &str, output: &mut [u8]) -> Result<usize, Error> {
    Ok(gnunet::did::Did::parse(input)?.write(output)?.len())
}

/// Compile revocation structural IPC without executing signatures or PoW.
pub fn exercise_revocation(input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    gnunet::revocation::ipc::Request::decode(input)?.encode(output)
}

/// Compile the noalloc topology limits without executing HELLO verification.
pub fn exercise_topology_limits() -> Result<(), Error> {
    gnunet::topology::Limits::default().validate()
}

/// Compile the borrowed STUN grammar without allocating or issuing a packet.
pub fn exercise_nat_stun(input: &[u8]) -> Result<(), Error> {
    gnunet::nat::stun::Message::decode(input).map(|_| ())
}

/// Compile the fixed public burst codec without sockets, allocation or cryptography.
pub fn exercise_nat_burst(input: &[u8]) -> Result<(), Error> {
    gnunet::nat::burst::BurstSync::decode(input, gnunet::nat::burst::Endian::Little).map(|_| ())
}

/// Compile actual PT DNS parsing without allocation or native interception.
pub fn exercise_pt_packet(input: &[u8], scratch: &mut [u8]) -> Result<(), Error> {
    gnunet::pt::packet::validate(input, scratch, gnunet::dns::Limits::DNS)
}

/// Compile TESTBED resource ownership with fixed caller slots and no native IO.
pub fn exercise_testbed_scope() -> Result<u64, Error> {
    let instance = gnunet::testbed::Instance::new();
    let mut slots = [gnunet::testbed::PortSlot::empty()];
    let mut system = gnunet::testbed::System::new(&instance, &mut slots, 12000, 12001, 0)?;
    Ok(system.allocate_path()?.number())
}

/// Compile actual HOSTLIST advertisement framing with caller-provided storage.
pub fn exercise_hostlist(uri: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    gnunet::hostlist::Advertisement::new(uri)?.encode(output)
}

/// Compile official helper framing using borrowed IP packets and caller output.
pub fn exercise_dns_helper(ip: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    gnunet::dns_interception::encode_helper(ip, output)
}

/// Compile exact DV learn parsing without allocation, signatures or native IO.
pub fn exercise_transport_dv(input: &[u8]) -> Result<usize, Error> {
    Ok(gnunet::transport::dv::Learn::decode(input)?.hop_count())
}

/// Compile the noalloc UNIX datagram decoder without creating a socket or key.
pub fn exercise_unix_communicator(input: &[u8]) -> usize {
    gnunet::unix_communicator::Datagram::decode(input, 65447)
        .map(|packet| packet.message.len())
        .unwrap_or(0)
}

/// Compile the actual fixed-storage DV crypto cache types without running crypto.
pub const fn transport_dv_material_slot_bytes() -> usize {
    core::mem::size_of::<gnunet::transport_dv_crypto::cache::SendSlot<'static, 'static>>()
        + core::mem::size_of::<gnunet::transport_dv_crypto::cache::ReceiveSlot<'static, 'static>>()
}

/// Compile actual QUIC application framing with caller storage and no runtime.
pub fn exercise_quic_frame(input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let limit = output.len().min(65535);
    let mut decoder = gnunet::transport_quic::frame::Decoder::new(output, limit)?;
    Ok(decoder.push(input)?.consumed)
}
