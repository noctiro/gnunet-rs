//! Standalone Owner over real Unix IPC, genuine PILS signatures and controlled
//! PEERSTORE API outcomes. STORE_RESULT is not a durable backend receipt.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Original leases, physical sources and exact wire submissions are observable regression outcomes"
)]

use gnunet_client_host::EndpointSource;
use gnunet_crypto::Entropy;
use gnunet_pils::{Action, MasterKey, Profile, Service, client as pc};
use gnunet_service_runtime::{
    clock::{RuntimeClock, SystemClock},
    connection::Connection,
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, ReadStep},
};
use gnunet_transport::{ClientId, PeerId, addresses::AddressLease};
use gnunet_transport_service_host::{
    Failure,
    generation::Reservations,
    owner::{Event, Instances, Owner, Sources},
    settings::Settings,
    time::Clock,
    writer,
};
use gnunet_wire::official::{nat, peerstore as ps, pils};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::OsStr,
    fs,
    future::poll_fn,
    io,
    path::PathBuf,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
    time::Instant,
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Failure> {
        let base = if cfg!(target_os = "macos") {
            PathBuf::from("/private/tmp")
        } else {
            fs::canonicalize(std::env::temp_dir())?
        };
        let mut nonce = [0; 8];
        gnunet_native::entropy::fill(&mut nonce)?;
        let name = format!("gts-{:016x}", u64::from_ne_bytes(nonce));
        gnunet_native::filesystem::Directory::open(&base)?
            .create_private_directory(OsStr::new(&name))?;
        Ok(Self(base.join(name)))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

struct Random;
impl Entropy for Random {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), gnunet_types::Error> {
        gnunet_native::entropy::fill(bytes).map_err(|_| gnunet_types::Error::Unavailable)
    }
}

#[derive(Clone, Eq, PartialEq)]
struct Stored {
    peer: [u8; 32],
    expiry: u64,
    subsystem: Option<Vec<u8>>,
    key: Option<Vec<u8>>,
    value: Vec<u8>,
}
impl Stored {
    fn copy(record: ps::Record<'_>) -> Self {
        Self {
            peer: record.peer,
            expiry: record.expiry,
            subsystem: record.subsystem.map(<[u8]>::to_vec),
            key: record.key.map(<[u8]>::to_vec),
            value: record.value.to_vec(),
        }
    }
    fn record(&self) -> ps::Record<'_> {
        ps::Record {
            peer: self.peer,
            expiry: self.expiry,
            subsystem: self.subsystem.as_deref(),
            key: self.key.as_deref(),
            value: &self.value,
        }
    }
    fn matches(&self, filter: ps::Filter<'_>) -> bool {
        filter.peer.is_none_or(|peer| self.peer == peer)
            && filter
                .subsystem
                .is_none_or(|name| self.subsystem.as_deref() == Some(name))
            && filter
                .key
                .is_none_or(|name| self.key.as_deref() == Some(name))
    }
    fn own_address(&self) -> bool {
        self.subsystem.as_deref() == Some(gnunet_transport::own_wire::SUBSYSTEM)
            && self.key.as_deref() == Some(gnunet_transport::own_wire::KEY)
    }
}

struct Endpoint {
    listener: UnixListener,
    clients: Vec<Option<Framed<()>>>,
}
impl Endpoint {
    fn bind(path: PathBuf) -> io::Result<Self> {
        Ok(Self {
            listener: UnixListener::bind(path)?,
            clients: Vec::new(),
        })
    }
    fn queue(&mut self, client: usize, bytes: &[u8]) -> Result<(), Failure> {
        self.clients
            .get_mut(client)
            .and_then(Option::as_mut)
            .ok_or("original fixture MQ disappeared")?
            .enqueue_copy(bytes, (), Class::Ordinary)?;
        Ok(())
    }
}

/// One caller-polled protocol model; no service task or test thread is detached.
struct Services {
    endpoints: [Endpoint; 3],
    pils: Service<4096>,
    scratch: Vec<u8>,
    store_rids: BTreeSet<(usize, u32)>,
    sign_rids: BTreeSet<(usize, u32)>,
    records: Vec<Stored>,
    submitted: Vec<Stored>,
    iterators: BTreeMap<(usize, u32), VecDeque<Stored>>,
    held_store: Option<(usize, u32, Stored)>,
    hold_first: bool,
    feeds: usize,
    nat_registrations: usize,
}
impl Services {
    fn new(directory: &Directory) -> Result<Self, Failure> {
        Ok(Self {
            endpoints: [
                Endpoint::bind(directory.0.join("pils"))?,
                Endpoint::bind(directory.0.join("ps"))?,
                Endpoint::bind(directory.0.join("nat"))?,
            ],
            pils: Service::new(
                MasterKey::from_seed([37; 32]),
                Profile::ReferenceDeterministic,
                SystemClock.sample()?.now.as_micros(),
                hello_limits(),
            )?,
            scratch: vec![0; 4096],
            store_rids: BTreeSet::new(),
            sign_rids: BTreeSet::new(),
            records: Vec::new(),
            submitted: Vec::new(),
            iterators: BTreeMap::new(),
            held_store: None,
            hold_first: true,
            feeds: 0,
            nat_registrations: 0,
        })
    }
    fn response(&mut self, client: usize, response: ps::Response<'_>) -> Result<(), Failure> {
        let mut bytes = vec![0; response.encoded_len()?];
        response.encode(&mut bytes)?;
        self.endpoints[1].queue(client, &bytes)
    }
    fn round(&mut self, client: usize, rid: u32, limit: u64) -> Result<(), Failure> {
        for _ in 0..limit.min(ps::MAX_ROUND) {
            let next = self
                .iterators
                .get_mut(&(client, rid))
                .and_then(VecDeque::pop_front);
            if let Some(record) = next {
                self.response(
                    client,
                    ps::Response::Record(ps::Envelope {
                        rid,
                        options: 0,
                        reserved: 0,
                        record: record.record(),
                    }),
                )?;
            } else {
                self.iterators.remove(&(client, rid));
                self.response(client, ps::Response::IterateEnd { rid, result: 1 })?;
                break;
            }
        }
        Ok(())
    }
    fn request(&mut self, source: usize, client: usize, bytes: &[u8]) -> Result<(), Failure> {
        match source {
            0 => {
                match pils::Request::decode(bytes)? {
                    pils::Request::Sign { request, .. } => {
                        assert!(
                            self.sign_rids.insert((client, request)),
                            "SIGN submitted twice on its original MQ"
                        );
                    }
                    pils::Request::Feed { .. } => self.feeds += 1,
                    _ => return Err("unexpected PILS effect in own-address regression".into()),
                }
                let mut reply = [0; 104];
                match self.pils.receive(
                    bytes,
                    &mut self.scratch,
                    SystemClock.sample()?.now.as_micros(),
                    &mut reply,
                )? {
                    Action::Reply { len, crypto_error } => {
                        assert!(crypto_error.is_none(), "genuine PILS signing failed");
                        self.endpoints[0].queue(client, &reply[..len])?;
                    }
                    Action::Broadcast { .. } => {
                        let announcement = self.pils.announcement().to_vec();
                        for subscriber in 0..self.endpoints[0].clients.len() {
                            if self.endpoints[0].clients[subscriber].is_some() {
                                self.endpoints[0].queue(subscriber, &announcement)?;
                            }
                        }
                    }
                    Action::Unchanged => {}
                }
            }
            1 => match ps::Request::decode(bytes)? {
                ps::Request::Store(envelope) => {
                    assert!(
                        self.store_rids.insert((client, envelope.rid)),
                        "STORE RID was submitted twice on its original MQ"
                    );
                    let record = Stored::copy(envelope.record);
                    if envelope.options == 1 {
                        self.records.retain(|old| {
                            old.peer != record.peer
                                || old.subsystem != record.subsystem
                                || old.key != record.key
                        });
                    }
                    self.records.push(record.clone());
                    self.submitted.push(record.clone());
                    if self.hold_first && record.own_address() {
                        self.hold_first = false;
                        self.held_store = Some((client, envelope.rid, record));
                    } else {
                        self.response(
                            client,
                            ps::Response::StoreResult {
                                rid: envelope.rid,
                                result: 1,
                            },
                        )?;
                    }
                }
                ps::Request::IterateStart(start) => {
                    let records = self
                        .records
                        .iter()
                        .filter(|record| record.matches(start.filter))
                        .cloned()
                        .collect();
                    self.iterators.insert((client, start.rid), records);
                    self.round(client, start.rid, 1)?;
                }
                ps::Request::IterateNext { rid, limit } => self.round(client, rid, limit)?,
                ps::Request::IterateStop { rid } => {
                    self.iterators.remove(&(client, rid));
                }
                ps::Request::MonitorStart(_) => self.response(client, ps::Response::MonitorSync)?,
                ps::Request::MonitorNext { .. } => {}
            },
            2 => match nat::Request::decode(bytes, gnunet_nat_client_host::native_profile()?)? {
                nat::Request::Register {
                    flags,
                    protocol,
                    addresses,
                    ..
                } => {
                    assert_eq!((flags, protocol), (0, 0));
                    assert!(addresses.is_empty());
                    self.nat_registrations += 1;
                }
                _ => return Err("unexpected NAT mutation in standalone Owner regression".into()),
            },
            _ => return Err("unknown fixture source".into()),
        }
        Ok(())
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        for source in 0..self.endpoints.len() {
            if let Poll::Ready(accepted) = self.endpoints[source].listener.poll_accept(cx) {
                let (stream, _) = accepted?;
                let mut io = Framed::new(
                    Connection::from_unix(stream),
                    FrameLimits {
                        frame_bytes: 65535,
                        ordinary: Budget {
                            frames: 64,
                            bytes: 1024 * 1024,
                        },
                        reserved: Budget::default(),
                        accounting: Accounting::Retained,
                        io_slice_bytes: 7,
                    },
                )?;
                if source == 0 {
                    io.enqueue_copy(self.pils.announcement(), (), Class::Ordinary)?;
                }
                self.endpoints[source].clients.push(Some(io));
            }
            for client in 0..self.endpoints[source].clients.len() {
                let request = {
                    let Some(io) = &mut self.endpoints[source].clients[client] else {
                        continue;
                    };
                    if let Poll::Ready(result) = io.poll_write(cx) {
                        let _written = result?;
                    }
                    let ended = match io.poll_read(cx) {
                        Poll::Ready(result) => matches!(result?, ReadStep::Eof),
                        Poll::Pending => false,
                    };
                    let frame = io.frame().map(<[u8]>::to_vec);
                    if frame.is_some() {
                        assert!(io.release_frame());
                    }
                    if ended {
                        self.endpoints[source].clients[client] = None;
                    }
                    frame
                };
                if let Some(request) = request {
                    self.request(source, client, &request)?;
                }
            }
        }
        Ok(())
    }
    fn addresses(&mut self) -> Result<Vec<Vec<u8>>, Failure> {
        let update = pils::PeerUpdate::decode(self.pils.announcement())?;
        let hello =
            gnunet_hello::Hello::parse_block(update.block, &mut self.scratch, hello_limits())?;
        hello.verify_at(
            Profile::ReferenceDeterministic.hello(),
            SystemClock.sample()?.now,
        )?;
        let mut addresses: Vec<_> = hello
            .addresses()
            .map(|address| address.as_bytes().to_vec())
            .collect();
        addresses.sort();
        Ok(addresses)
    }
    fn release_store(&mut self) -> Result<Stored, Failure> {
        let (client, rid, record) = self
            .held_store
            .take()
            .ok_or("no original STORE to release")?;
        self.response(client, ps::Response::StoreResult { rid, result: 1 })?;
        Ok(record)
    }
}

#[derive(Default)]
struct Observations {
    retiring: usize,
    started: usize,
    retired_stores: usize,
    native_retirements: usize,
}
impl Observations {
    fn event(&mut self, event: Event<'_>) {
        match event {
            Event::IdentityRetiring { previous, observed } => {
                assert_eq!(
                    previous.epoch(),
                    observed.epoch(),
                    "fixture must retain the original physical PILS source"
                );
                self.retiring += 1;
            }
            Event::IdentityActivated { .. } => self.started += 1,
            Event::PublicationRetired(writer::Event::StoredByService(_)) => {
                self.retired_stores += 1
            }
            Event::NativeRetired(_) => self.native_retirements += 1,
            _ => {}
        }
    }
}

fn hello_limits() -> gnunet_pils::HelloLimits {
    gnunet_pils::HelloLimits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 4096,
        maximum_addresses: 64,
    }
}
fn frame(kind: u16, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    bytes[..2].copy_from_slice(&(length as u16).to_be_bytes());
    bytes[2..4].copy_from_slice(&kind.to_be_bytes());
    bytes
}
fn add(address: &[u8]) -> Vec<u8> {
    let mut bytes = frame(1200, 21 + address.len());
    bytes[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    bytes[16..20].copy_from_slice(&1u32.to_be_bytes());
    bytes[20..20 + address.len()].copy_from_slice(address);
    bytes
}
fn leases(
    owner: &mut Owner<'_, Random>,
    original: &ClientId,
) -> Result<Vec<(AddressLease, Vec<u8>)>, Failure> {
    let scope = owner
        .dv_scope()
        .ok_or("Owner has no current identity scope")?;
    Ok(owner
        .dv_server(&scope)?
        .local_addresses()
        .map(|address| {
            assert_eq!(
                address.owner, original,
                "address acquired a replacement communicator owner"
            );
            (address.lease.clone(), address.uri.to_vec())
        })
        .collect())
}
async fn step(
    owner: &mut Owner<'_, Random>,
    reservations: &mut Reservations,
    services: &mut Services,
    observations: &mut Observations,
) -> Result<(), Failure> {
    poll_fn(|cx| {
        services.poll(cx)?;
        if let Poll::Ready(result) =
            owner.poll(cx, reservations, &mut |event| observations.event(event))
        {
            result?;
        }
        services.poll(cx)?;
        Poll::Ready(Ok::<_, Failure>(()))
    })
    .await?;
    tokio::time::sleep(Duration::from_millis(1)).await;
    Ok(())
}
async fn until<'id>(
    owner: &mut Owner<'id, Random>,
    reservations: &mut Reservations,
    services: &mut Services,
    observations: &mut Observations,
    mut done: impl FnMut(&mut Owner<'id, Random>, &mut Services, &Observations) -> Result<bool, Failure>,
) -> Result<(), Failure> {
    let deadline = Instant::now() + Duration::from_secs(12);
    while !done(owner, services, observations)? {
        if Instant::now() >= deadline {
            return Err("standalone Owner identity/resource regression deadline".into());
        }
        step(owner, reservations, services, observations).await?;
    }
    Ok(())
}

#[test]
fn same_pils_mq_keeps_original_communicator_leases_and_settles_old_store_once()
-> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let directory = Directory::new()?;
            let mut services = Services::new(&directory)?;
            let mut config = gnunet_config::Configuration::default();
            config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
            for (key, name) in [
                (b"MONOTIME_STORE".as_slice(), "stamps"),
                (b"DV_STORE".as_slice(), "dv"),
            ] {
                let path = directory.0.join(name);
                config.set_value(
                    b"transport-rust",
                    key,
                    Some(&gnunet_native::os_bytes::encode(path.as_os_str())),
                )?;
            }
            config.set_value(b"transport-rust", b"MAINTENANCE_INTERVAL", Some(b"1 ms"))?;
            let settings = Settings::read(&config)?;
            let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
            let mut pils = pc::Instance::new();
            let mut validated = gnunet_peerstore_client_host::Instance::new();
            let mut publications = gnunet_peerstore_client_host::Instance::new();
            let mut hello = gnunet_peerstore_client_host::Instance::new();
            let mut queries = gnunet_peerstore_client_host::Instance::new();
            let mut monitors = (0..settings.discovery.peers)
                .map(|_| gnunet_peerstore_client_host::Instance::new())
                .collect::<Vec<_>>();
            let nat = gnunet_nat_client_host::Instance::new();
            let mut reservations = Reservations::open(&settings.stamp_path)?;
            let mut owner = Owner::new(
                Instances {
                    pils: &mut pils,
                    validated: &mut validated,
                    publications: &mut publications,
                    hello: &mut hello,
                    queries: &mut queries,
                    monitors: &mut monitors,
                    nat: &nat,
                },
                Sources {
                    pils: EndpointSource::unix_with_clock(directory.0.join("pils"), clock.clone()),
                    peerstore: EndpointSource::unix_with_clock(
                        directory.0.join("ps"),
                        clock.clone(),
                    ),
                    nat: EndpointSource::unix_with_clock(directory.0.join("nat"), clock.clone()),
                },
                Clock::new(clock)?,
                &settings,
                Random,
            )?;
            let mut observations = Observations::default();
            until(
                &mut owner,
                &mut reservations,
                &mut services,
                &mut observations,
                |owner, services, _| Ok(owner.ready() && services.nat_registrations == 1),
            )
            .await?;
            let empty_peer = services.pils.identity().public_key();
            let (mut communicator, native) = UnixStream::pair()?;
            let original = owner.admit(Connection::from_unix(native))?;
            let mut registration = frame(1211, 16);
            registration[4..8].copy_from_slice(&1u32.to_be_bytes());
            registration[12..].copy_from_slice(b"tcp\0");
            communicator.write_all(&registration).await?;
            communicator.write_all(&add(b"tcp-127.0.0.1:4101")).await?;
            let a = b"tcp://127.0.0.1:4101".to_vec();
            let b = b"tcp://127.0.0.1:4102".to_vec();
            until(
                &mut owner,
                &mut reservations,
                &mut services,
                &mut observations,
                |owner, services, _| {
                    Ok(owner.ready()
                        && services.held_store.is_some()
                        && services.addresses()? == vec![a.clone()])
                },
            )
            .await?;
            let initial = leases(&mut owner, &original)?;
            assert_eq!(initial.len(), 1);
            let lease_a = initial[0].0.clone();
            let first_peer = services.pils.identity().public_key();
            assert_ne!(empty_peer, first_peer);
            let dv_scope = owner.dv_scope().ok_or("missing original DV scope")?;
            let dv_source = owner
                .dv_server(&dv_scope)?
                .dv_attach_source(PeerId(*first_peer.as_bytes()))?;
            let prior_retiring = observations.retiring;
            // Both official ADD helpers use aid0. A single original DEL must pop B,
            // while the original A lease remains owned by this same live MQ.
            communicator.write_all(&add(b"tcp-127.0.0.1:4102")).await?;
            until(
                &mut owner,
                &mut reservations,
                &mut services,
                &mut observations,
                |_, services, observations| {
                    Ok(observations.retiring > prior_retiring
                        && services.addresses()? == vec![a.clone(), b.clone()])
                },
            )
            .await?;
            assert!(!owner.ready());
            owner
                .dv_server(&dv_scope)?
                .dv_begin_retire_source(&dv_source)?;
            let old_store = services.release_store()?;
            until(
                &mut owner,
                &mut reservations,
                &mut services,
                &mut observations,
                |_, _, observations| Ok(observations.retired_stores == 1),
            )
            .await?;
            assert!(!owner.ready(), "replacement started before DV detached");
            owner.dv_server(&dv_scope)?.dv_retire_source(&dv_source)?;
            until(
                &mut owner,
                &mut reservations,
                &mut services,
                &mut observations,
                |owner, services, _| {
                    Ok(owner.ready()
                        && owner.dv_identity().is_some_and(|identity| {
                            identity.peer() == services.pils.identity().public_key()
                        })
                        && leases(owner, &original)?.len() == 2)
                },
            )
            .await?;
            assert_eq!(leases(&mut owner, &original)?[0].0, lease_a);
            assert!(owner.dv_server(&dv_scope).is_err());
            communicator.write_all(&frame(1201, 8)).await?;
            until(
                &mut owner,
                &mut reservations,
                &mut services,
                &mut observations,
                |owner, services, _| {
                    Ok(owner.ready()
                        && services.pils.identity().public_key() == first_peer
                        && services.addresses()? == vec![a.clone()]
                        && leases(owner, &original)?.len() == 1)
                },
            )
            .await?;
            assert_eq!(leases(&mut owner, &original)?[0].0, lease_a);
            communicator.write_all(&frame(1201, 8)).await?;
            until(
                &mut owner,
                &mut reservations,
                &mut services,
                &mut observations,
                |owner, services, _| {
                    Ok(owner.ready()
                        && owner
                            .dv_identity()
                            .is_some_and(|identity| identity.peer() == empty_peer)
                        && services.pils.identity().public_key() == empty_peer
                        && services.addresses()?.is_empty()
                        && leases(owner, &original)?.is_empty())
                },
            )
            .await?;
            let quiet = Instant::now() + Duration::from_millis(1200);
            while Instant::now() < quiet {
                step(
                    &mut owner,
                    &mut reservations,
                    &mut services,
                    &mut observations,
                )
                .await?;
            }
            assert_eq!(
                services.feeds, 4,
                "each of the four address revisions must submit exactly one FEED"
            );
            assert_eq!(
                services
                    .submitted
                    .iter()
                    .filter(|record| **record == old_store)
                    .count(),
                1,
                "old own-address STORE body was submitted twice"
            );
            assert_eq!(
                services.endpoints[0].clients.len(),
                1,
                "healthy PILS physical MQ was replaced"
            );
            assert_eq!(
                observations.native_retirements, 0,
                "identity change closed the original communicator MQ"
            );
            assert_eq!(
                owner.snapshot().ok_or("missing original Server")?.clients,
                1
            );
            assert!(leases(&mut owner, &original)?.is_empty());
            let errors = owner.stop(&mut |event| observations.event(event));
            assert!(errors.is_empty(), "original source retirement failed");
            reservations.shutdown().await?;
            Ok(())
        })
}
