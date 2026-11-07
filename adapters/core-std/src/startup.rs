//! Actual configuration/PILS bootstrap and foreground ownership. The service
//! never creates a C subprocess. A Node may instead supply Host's typed identity.
use crate::{Host, HostError, Limits, Report, io::Link};
use gnunet_client_host::Endpoint;
use gnunet_config::{Configuration, Environment, ProcessEnvironment, ProjectData};
use gnunet_core::session::Identity;
use gnunet_hello::Hello;
use gnunet_pils::{MasterKey, Profile};
use gnunet_resolver_broker::{Driver, FamilyProfile, LiveConfiguration, broker};
mod process;
use gnunet_service_runtime::clock::{RuntimeClock, SystemClock};
use gnunet_service_runtime::credentials::UnixAccess;
use gnunet_service_runtime::{
    Activation, BoundListeners,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use gnunet_service_runtime::{accepted::SocketEvent, connection::Connection};
use gnunet_types::Error;
use gnunet_wire::official::{
    core::{PeerClass, PeerId},
    pils::PeerUpdate,
};
pub use process::{PreparedProcess, ProcessPreparation, prepare_process};
use std::{
    error::Error as StdError,
    future::{Future, poll_fn},
    io,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use zeroize::Zeroizing;

/// Actual official PILS1831 feed. Its update derives and verifies a new local
/// identity before the enclosing owner replaces any active CORE sessions.
/// It implements neither the PILS service nor signing/ECDH operation APIs.
pub struct PilsFeed {
    link: Link,
    scratch: Zeroizing<Vec<u8>>,
    clock: Arc<dyn RuntimeClock>,
    profile: Profile,
}
impl PilsFeed {
    /// Take an already connected, original official PILS stream.
    pub fn new(connection: Connection) -> Result<Self, Error> {
        Self::with_clock(connection, Arc::new(SystemClock))
    }
    /// Join the same absolute source used by the process and CORE owner.
    pub fn with_clock(connection: Connection, clock: Arc<dyn RuntimeClock>) -> Result<Self, Error> {
        Self::with_profile(connection, clock, Profile::Reference029)
    }
    /// Choose one explicit official source/draft identity profile; failed
    /// verification never tries another interpretation of the announcement.
    pub fn with_profile(
        connection: Connection,
        clock: Arc<dyn RuntimeClock>,
        profile: Profile,
    ) -> Result<Self, Error> {
        Ok(Self {
            link: Link::new(connection, 65535, 1, 65535)?,
            scratch: Zeroizing::new(vec![0; 65535]),
            clock,
            profile,
        })
    }
    fn identity(&mut self, master: &MasterKey) -> Result<Identity, HostError> {
        let bytes = self.link.frame().ok_or(Error::NotReady)?;
        let update = PeerUpdate::decode(bytes)?;
        let hello = Hello::parse_block(
            update.block,
            &mut self.scratch,
            gnunet_hello::Limits {
                maximum_input_bytes: 65535,
                maximum_address_bytes: 65535,
                maximum_addresses: 128,
            },
        )?;
        let now = self
            .clock
            .sample()
            .map_err(HostError::Clock)?
            .now
            .as_micros();
        hello.verify_at(
            self.profile.hello(),
            gnunet_wire::official::AbsoluteTime::from_micros(now),
        )?;
        // The selected official build fixes address coverage. Reference029
        // verifies metadata binding; deterministic also authenticates addresses.
        if hello.address_hash(self.profile.hello()) != update.hash {
            return Err(Error::Authentication.into());
        }
        let identity = master.with_active_seed(&update.hash, self.profile, |seed| {
            Identity::from_seed(*seed)
        })?;
        if identity.public_key() != hello.peer() {
            return Err(Error::Authentication.into());
        }
        Ok(identity)
    }
    /// Poll one actual complete verified update; canceled waits retain the
    /// original partial bytes. No fabricated identity is emitted while offline.
    pub fn poll_identity(
        &mut self,
        cx: &mut Context<'_>,
        master: &MasterKey,
    ) -> Poll<Result<Identity, HostError>> {
        if self.link.frame().is_none() {
            match self.link.poll_rx(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(false)) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Ok(true)) => {}
            }
        }
        let result = self.identity(master);
        self.link.release();
        Poll::Ready(result)
    }
}
/// Load official defaults plus the selected user's configuration.
pub fn configuration(selected: Option<&Path>) -> Result<Configuration, Box<dyn StdError>> {
    let project = Arc::new(ProjectData::default());
    let mut config = Configuration::create(project.clone(), Default::default())?;
    let selected = if let Some(path) = selected {
        Some(path.to_owned())
    } else {
        let raw = match ProcessEnvironment.variable(b"XDG_CONFIG_HOME") {
            Some(mut p) => {
                p.push(b'/');
                p.extend_from_slice(&project.config_file);
                p
            }
            None => project.user_config_file.clone(),
        };
        let path = config.expand_filename(&raw, &ProcessEnvironment)?;
        path.is_file().then_some(path)
    };
    config.load(selected.as_deref())?;
    Ok(config)
}
fn class(config: &Configuration) -> Result<PeerClass, Box<dyn StdError>> {
    let Some(value) = config.get(b"core", b"CLASS") else {
        return Ok(PeerClass::UNKNOWN);
    };
    for (index, name) in [
        b"UNKNOWN".as_slice(),
        b"UNWILLING",
        b"MOBILE",
        b"DESKTOP",
        b"ROUTER",
        b"SERVER",
    ]
    .iter()
    .enumerate()
    {
        if value.eq_ignore_ascii_case(name) {
            return Ok(PeerClass(index as u32));
        }
    }
    Err("unsupported core CLASS".into())
}
enum Selection<T> {
    Value(T),
    Stopped,
}
async fn resolver_driver(
    driver: &mut Driver<128, 256>,
) -> Result<(), gnunet_resolver_broker::BrokerError> {
    loop {
        driver.drive_waiting(None, |_| {}).await?;
    }
}
async fn services<F: Future, S: Future<Output = io::Result<()>>>(
    future: F,
    driver: &mut Driver<128, 256>,
    mut shutdown: Pin<&mut S>,
) -> Result<Selection<F::Output>, Box<dyn StdError>> {
    let mut operation = std::pin::pin!(future);
    let mut resolver = std::pin::pin!(resolver_driver(driver));
    poll_fn(|cx| {
        if let Poll::Ready(value) = shutdown.as_mut().poll(cx) {
            return Poll::Ready(
                value
                    .map(|()| Selection::Stopped)
                    .map_err(|e| Box::new(e) as Box<dyn StdError>),
            );
        }
        if let Poll::Ready(value) = operation.as_mut().poll(cx) {
            return Poll::Ready(Ok(Selection::Value(value)));
        }
        match resolver.as_mut().poll(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(Box::new(e) as Box<dyn StdError>)),
            Poll::Ready(Ok(_)) => {
                Poll::Ready(Err("process Resolver driver stopped unexpectedly".into()))
            }
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}
enum Epoch {
    Rotate(Identity),
    PilsLost,
    HostStopped,
}
fn accumulate(total: &mut Report, one: Report) {
    macro_rules! add {($($field:ident),*)=>{$(total.$field=total.$field.saturating_add(one.$field);)*};}
    add!(
        accepted,
        closed,
        requests,
        authenticated,
        payloads,
        transport_sends,
        receive_credits,
        rejected_records,
        rejected_epoch,
        rejected_authentication,
        rejected_replay,
        rejected_truncated,
        rejected_malformed,
        rejected_invalid_input,
        rejected_unsupported,
        transport_losses,
        transport_disconnections,
        association_expirations,
        late_send_credits
    );
    if total.first_peer_loss.is_none() {
        total.first_peer_loss = one.first_peer_loss;
    }
}
/// Run a foreground service using real PILS announcements and the configured
/// TRANSPORT CLIENT endpoint. A single process Resolver is shared by both MQs.
/// Identity changes close old application/transport/session owners before key
/// replacement. PILS loss closes the old epoch and retries its actual endpoint.
/// This embedding entry never changes process identity. Configured USERNAME
/// requires the explicit [`prepare_process`] / [`ProcessPreparation::apply_identity`]
/// startup path in a fresh service process. It does not daemonize or launch C.
pub async fn foreground(
    config: &Configuration,
    activation: Activation,
    limits: Limits,
    ready: impl FnMut(&BoundListeners, PeerId) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe: impl FnMut(SocketEvent),
) -> Result<Report, Box<dyn StdError>> {
    foreground_with_clock(
        config,
        activation,
        limits,
        ready,
        shutdown,
        observe,
        Arc::new(SystemClock),
    )
    .await
}
/// Foreground assembly on the caller's canonical process clock, shared by CORE,
/// PILS verification, Resolver callbacks and both configured CLIENT endpoints.
/// Like [`foreground`], this never changes process identity; USERNAME requires
/// the explicit prepared-process path.
pub async fn foreground_with_clock(
    config: &Configuration,
    activation: Activation,
    limits: Limits,
    ready: impl FnMut(&BoundListeners, PeerId) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe: impl FnMut(SocketEvent),
    clock: Arc<dyn RuntimeClock>,
) -> Result<Report, Box<dyn StdError>> {
    if config.get(b"core", b"USERNAME").is_some() {
        return Err(
            "CORE USERNAME requires prepare_process and explicit apply_identity before foreground"
                .into(),
        );
    }
    let resources = ForegroundResources::bind(config, activation).await?;
    run_foreground(resources, limits, ready, shutdown, observe, clock).await
}

// A single owner carries the original initialized listeners across the explicit
// synchronous identity transition. No raw descriptor is reconstructed later.
struct ForegroundPolicy {
    options: ServiceOptions,
    unix_access: UnixAccess,
    local_class: PeerClass,
    profile: Profile,
}
impl ForegroundPolicy {
    fn read(config: &Configuration) -> Result<Self, Box<dyn StdError>> {
        let unix_access = UnixAccess {
            match_uid: config.get(b"core", b"UNIX_MATCH_UID").is_some()
                && config.get_yesno(b"core", b"UNIX_MATCH_UID")?,
            match_gid: config.get(b"core", b"UNIX_MATCH_GID").is_some()
                && config.get_yesno(b"core", b"UNIX_MATCH_GID")?,
        };
        let options = service_options(config, b"core", ShutdownMode::Immediate)?;
        let local_class = class(config)?;
        let profile = Profile::configured(config.get(b"PILS", b"PROFILE"), None)?;
        Ok(Self {
            options,
            unix_access,
            local_class,
            profile,
        })
    }
}
struct ForegroundResources<'config> {
    config: &'config Configuration,
    bound: BoundListeners,
    policy: ForegroundPolicy,
}
impl<'config> ForegroundResources<'config> {
    async fn bind(
        config: &'config Configuration,
        activation: Activation,
    ) -> Result<Self, Box<dyn StdError>> {
        let policy = ForegroundPolicy::read(config)?;
        let bound = BoundListeners::bind(config, b"core", activation).await?;
        Ok(Self {
            config,
            bound,
            policy,
        })
    }
}

async fn run_foreground(
    resources: ForegroundResources<'_>,
    limits: Limits,
    mut ready: impl FnMut(&BoundListeners, PeerId) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    mut observe: impl FnMut(SocketEvent),
    clock: Arc<dyn RuntimeClock>,
) -> Result<Report, Box<dyn StdError>> {
    let ForegroundResources {
        config,
        bound,
        policy:
            ForegroundPolicy {
                options,
                unix_access,
                local_class,
                profile,
            },
    } = resources;
    let key_path = config.get_filename(b"PEER", b"PRIVATE_KEY", &ProcessEnvironment)?;
    let master = gnunet_pils_host::identity::load_existing(&key_path)?;
    let native = gnunet_resolver_broker::native_profile()?;
    let family = FamilyProfile::new(
        native.encode(gnunet_resolver_broker::Family::V4),
        native.encode(gnunet_resolver_broker::Family::V6),
    )?;
    let live = LiveConfiguration::new(config.duplicate()?);
    let (context, mut resolver) =
        broker::<128, 256>(live.clone(), Default::default(), family, clock.clone())?;
    let resolution = context.resolution_context();
    let pils_endpoint = Endpoint::configuration_live(live.clone(), b"pils", resolution.clone())?;
    let transport_endpoint = Endpoint::configuration_live(live, b"transport", resolution)?;
    let mut shutdown = std::pin::pin!(shutdown);
    let mut total = Report::default();
    let mut round = 0_u64;
    loop {
        let connection = match services(
            pils_endpoint.attempt(round),
            &mut resolver,
            shutdown.as_mut(),
        )
        .await?
        {
            Selection::Stopped => return Ok(total),
            Selection::Value(Ok(c)) => c,
            Selection::Value(Err(_)) => {
                round = round.checked_add(1).ok_or(Error::Capacity)?;
                if matches!(
                    services(
                        tokio::time::sleep(Duration::from_secs(1)),
                        &mut resolver,
                        shutdown.as_mut()
                    )
                    .await?,
                    Selection::Stopped
                ) {
                    return Ok(total);
                }
                continue;
            }
        };
        let mut pils = PilsFeed::with_profile(connection, clock.clone(), profile)?;
        let first = poll_fn(|cx| pils.poll_identity(cx, &master));
        let mut identity = match services(first, &mut resolver, shutdown.as_mut()).await? {
            Selection::Stopped => return Ok(total),
            Selection::Value(Ok(i)) => i,
            Selection::Value(Err(e @ HostError::Clock(_))) => return Err(e.into()),
            Selection::Value(Err(_)) => {
                round = round.checked_add(1).ok_or(Error::Capacity)?;
                if matches!(
                    services(
                        tokio::time::sleep(Duration::from_secs(1)),
                        &mut resolver,
                        shutdown.as_mut()
                    )
                    .await?,
                    Selection::Stopped
                ) {
                    return Ok(total);
                }
                continue;
            }
        };
        loop {
            let mut host = Host::with_clock(
                &identity,
                b"",
                local_class,
                transport_endpoint.clone(),
                limits,
                options.clone(),
                clock.clone(),
            )?;
            host.set_unix_access(unix_access)?;
            ready(&bound, host.identity())?;
            let public = identity.public_key();
            let listeners = bound.listeners();
            let result = {
                let mut drive = std::pin::pin!(host.drive(&listeners, &mut observe));
                let epoch = poll_fn(|cx| {
                    match pils.poll_identity(cx, &master) {
                        Poll::Ready(Ok(next)) if next.public_key() != public => {
                            return Poll::Ready(Ok(Epoch::Rotate(next)));
                        }
                        Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
                        Poll::Ready(Err(e @ HostError::Clock(_))) => return Poll::Ready(Err(e)),
                        Poll::Ready(Err(_)) => return Poll::Ready(Ok(Epoch::PilsLost)),
                        Poll::Pending => {}
                    }
                    match drive.as_mut().poll(cx) {
                        Poll::Ready(result) => Poll::Ready(result.map(|()| Epoch::HostStopped)),
                        Poll::Pending => Poll::Pending,
                    }
                });
                services(epoch, &mut resolver, shutdown.as_mut()).await
            };
            host.shutdown();
            accumulate(&mut total, host.report());
            drop(host);
            match result? {
                Selection::Stopped => return Ok(total),
                Selection::Value(Err(e)) => return Err(e.into()),
                Selection::Value(Ok(Epoch::HostStopped)) => return Ok(total),
                Selection::Value(Ok(Epoch::PilsLost)) => break,
                Selection::Value(Ok(Epoch::Rotate(next))) => identity = next,
            }
        }
        round = round.checked_add(1).ok_or(Error::Capacity)?;
        if matches!(
            services(
                tokio::time::sleep(Duration::from_secs(1)),
                &mut resolver,
                shutdown.as_mut()
            )
            .await?,
            Selection::Stopped
        ) {
            return Ok(total);
        }
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    use gnunet_crypto::{EddsaPublicKey, EddsaSignature};
    use gnunet_hello::{HelloBuilder, Limits as HelloLimits};
    use gnunet_pils::{Action, Service};
    use gnunet_wire::official::{AbsoluteTime, pils::Request};
    use tokio::{io::AsyncWriteExt, net::UnixStream, time::timeout};

    #[tokio::test(flavor = "current_thread")]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The finite Unix component checks verified actual source announcements and rejects a mismatched profile without fallback"
    )]
    async fn configured_deterministic_core_feed_adopts_address_changes_without_default_fallback()
    -> Result<(), Box<dyn StdError>> {
        // Actual pure PILS generation/EdDSA and native Unix framing. This is
        // neither a normal PILS daemon nor a C interoperability observation.
        let mut config =
            Configuration::create(Arc::new(ProjectData::default()), Default::default())?;
        config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
        let profile = ForegroundPolicy::read(&config)?.profile;
        let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
        let now = clock.sample()?.now.as_micros();
        let limits = HelloLimits {
            maximum_input_bytes: 4096,
            maximum_address_bytes: 2048,
            maximum_addresses: 16,
        };
        let master = MasterKey::from_seed([93; 32]);
        let mut service =
            Service::<4096>::new(MasterKey::from_seed([93; 32]), profile, now, limits)?;
        let (local, mut remote) = UnixStream::pair()?;
        let mut feed =
            PilsFeed::with_profile(Connection::from_unix(local), clock.clone(), profile)?;
        remote.write_all(service.announcement()).await?;
        let mut previous = timeout(
            Duration::from_secs(2),
            poll_fn(|cx| feed.poll_identity(cx, &master)),
        )
        .await??;
        assert_eq!(previous.public_key(), service.identity().public_key());
        for address in [
            b"tcp://127.0.0.1:1234".as_slice(),
            b"tcp://127.0.0.1:5678".as_slice(),
        ] {
            let mut addresses = [0; 2048];
            let mut builder = HelloBuilder::new(&mut addresses, limits);
            builder.add_address(address)?;
            // FEED carries unsigned address material; only the real Service
            // derives the active identity and produces the signed announcement.
            let unsigned = builder.with_signature(
                EddsaPublicKey::from_bytes([0; 32]),
                EddsaSignature::from_bytes([0; 64]),
                AbsoluteTime::from_micros(now + 1_000_000),
            );
            let mut block = vec![0; unsigned.block_len()?];
            unsigned.encode_block(&mut block)?;
            let mut input = vec![0; block.len() + 8];
            Request::Feed { block: &block }.encode(&mut input)?;
            let mut scratch = [0; 2048];
            let mut output = [0; 4096];
            assert!(matches!(
                service.receive(&input, &mut scratch, now, &mut output)?,
                Action::Broadcast {
                    identity_changed: true
                }
            ));
            for part in service.announcement().chunks(3) {
                remote.write_all(part).await?;
            }
            let changed = timeout(
                Duration::from_secs(2),
                poll_fn(|cx| feed.poll_identity(cx, &master)),
            )
            .await??;
            assert_ne!(changed.public_key(), previous.public_key());
            assert_eq!(changed.public_key(), service.identity().public_key());
            previous = changed;
        }
        let (local, mut remote) = UnixStream::pair()?;
        let mut default_feed = PilsFeed::with_clock(Connection::from_unix(local), clock)?;
        remote.write_all(service.announcement()).await?;
        assert!(matches!(
            timeout(
                Duration::from_secs(2),
                poll_fn(|cx| default_feed.poll_identity(cx, &master))
            )
            .await?,
            Err(HostError::Protocol(Error::Authentication))
        ));
        Ok(())
    }
}
