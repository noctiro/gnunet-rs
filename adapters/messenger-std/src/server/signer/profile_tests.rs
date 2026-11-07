//! Actual Unix CLIENT verification of real pure-PILS signed nonempty HELLOs.
//! CADET is not polled; this component grants no normal daemon/peer qualification.
use super::*;
use gnunet_pils::{Action, HelloLimits, MasterKey, Profile, Service};
use gnunet_service_runtime::clock::SystemClock;
use std::{
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::net::{UnixListener, UnixStream};

type Failure = Box<dyn std::error::Error>;
static NEXT: AtomicU64 = AtomicU64::new(0);
pub(super) struct Directory(pub(super) PathBuf);
impl Directory {
    pub(super) fn new() -> Result<Self, Failure> {
        let path = std::env::temp_dir().join(format!(
            "msg-pils-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}
pub(super) struct NoEntropy;
impl Entropy for NoEntropy {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), Fault> {
        Err(Fault::Entropy)
    }
}

async fn original_identity(source_profile: Profile, selected: Profile) -> Result<(), Failure> {
    let directory = Directory::new()?;
    let path = directory.0.join("p");
    let listener = UnixListener::bind(&path)?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
    let now = clock.sample()?.now.as_micros();
    let mut service = Service::<4096>::new(
        MasterKey::from_seed([0x6b; 32]),
        source_profile,
        now,
        HelloLimits {
            maximum_input_bytes: 4096,
            maximum_address_bytes: 2048,
            maximum_addresses: 16,
        },
    )?;
    let initial = gnunet_wire::official::pils::PeerUpdate::decode(service.announcement())?;
    let mut block = initial.block.to_vec();
    block.extend_from_slice(b"tcp://127.0.0.1:1234\0");
    let mut input = vec![0; block.len() + 8];
    let len = gnunet_wire::official::pils::Request::Feed { block: &block }.encode(&mut input)?;
    let mut scratch = [0; 2048];
    let mut output = [0; 104];
    if !matches!(
        service.receive(&input[..len], &mut scratch, now, &mut output)?,
        Action::Broadcast { .. }
    ) {
        return Err("real nonempty PILS feed did not produce an announcement".into());
    }
    let expected = *service.identity().public_key().as_bytes();
    let mut core_instance = core::Instance::new();
    let mut cadet_instance = cadet::Instance::new();
    let mut pils_instance = pc::Instance::new();
    let mut ports = [cadet::PortSlot::new()];
    let mut channels = [cadet::ChannelSlot::new()];
    let limits = Limits {
        clients: 1,
        rooms: 1,
        client_rooms: 1,
        tunnels: 1,
        deliveries: 4,
        signatures: 1,
        controls: 2,
        min_routers: 0,
        pils_profile: selected,
        ..Limits::default()
    };
    let mut server = Server::<_, 1>::new(
        &mut core_instance,
        &mut cadet_instance,
        &mut pils_instance,
        &mut ports,
        &mut channels,
        core::Limits::default(),
        limits,
        Ports {
            options: ServiceOptions::default(),
            unix: UnixAccess::default(),
            clock: clock.clone(),
            cadet: EndpointSource::unix_with_clock(directory.0.join("unused-cadet"), clock.clone()),
            pils: EndpointSource::unix_with_clock(path, clock),
        },
        NoEntropy,
    )?;
    let mut sending = std::pin::pin!(async {
        let (stream, _) = listener.accept().await?;
        let bytes = service.announcement();
        let mut cursor = 0;
        while cursor < bytes.len() {
            stream.writable().await?;
            match stream.try_write(&bytes[cursor..(cursor + 3).min(bytes.len())]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "PILS fixture wrote zero",
                    ));
                }
                Ok(n) => cursor += n,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        Ok::<UnixStream, io::Error>(stream)
    });
    let mut held = None;
    let mut identities = 0;
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            poll_fn(|cx| {
                if held.is_none() {
                    match sending.as_mut().poll(cx) {
                        Poll::Ready(Ok(stream)) => held = Some(stream),
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(Error::Io(error))),
                        Poll::Pending => {}
                    }
                }
                server
                    .signer_poll(cx, &mut |event| {
                        if matches!(event, Event::Identity) {
                            identities += 1;
                        }
                    })
                    .map(|result| result.map(|_| ()))
            })
            .await?;
            if identities != 0 && server.identity_ready() {
                return Ok::<_, Error>(());
            }
        }
    })
    .await;
    let applied = server.applied_identity();
    server.close_all(&mut |_| {});
    let cleanup = server.take_cleanup_error();
    drop(held);
    let observed = result?;
    if let Some(error) = cleanup {
        return Err(error.into());
    }
    if selected == source_profile {
        observed?;
        if applied.map(|identity| *identity.peer().as_bytes()) != Some(expected)
            || identities != 1
            || applied.is_none()
        {
            return Err(
                "selected original native PILS identity was not retained exactly once".into(),
            );
        }
    } else if !matches!(
        observed,
        Err(Error::PilsLost(pils::LossCause::Protocol(
            Fault::Authentication
        )))
    ) {
        return Err("mismatched nonempty HELLO profile did not fail authentication".into());
    } else if server.current_peer().is_some() || identities != 0 {
        return Err("failed HELLO verification manufactured an identity event".into());
    }
    Ok(())
}

#[test]
fn nonempty_pils_announcement_uses_selected_profile_without_fallback() -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        original_identity(Profile::Reference029, Limits::default().pils_profile).await?;
        original_identity(
            Profile::ReferenceDeterministic,
            Profile::ReferenceDeterministic,
        )
        .await?;
        original_identity(Profile::ReferenceDeterministic, Profile::Reference029).await
    })
}
