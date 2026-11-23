//! The normal observer factory over native local input and pure PILS signatures.
//! This is not a normal PILS daemon, DH/tunnel flow, or interoperability receipt.
use super::*;
use gnunet_config::Configuration;
use gnunet_pils::{Action, HelloLimits, MasterKey, Service};
use gnunet_service_runtime::{
    clock::SystemClock,
    local::{Listener, Stream},
};
#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!(
            "cad-pils-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        #[cfg(unix)]
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        #[cfg(windows)]
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}

async fn selected_observer(label: &[u8]) -> Result<(), Box<dyn Error>> {
    let directory = Directory::new()?;
    let path = directory.0.join("p");
    let listener = Listener::bind(&path)?;
    let mut config = Configuration::default();
    config.set_value(b"cadet-rust", b"PEER_CORE", Some(b"NO"))?;
    config.set_value(b"PILS", b"PROFILE", Some(label))?;
    let settings = Settings::read(&config)?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
    let now = clock.sample()?.now.as_micros();
    let mut service = Service::<4096>::new(
        MasterKey::from_seed([0x53; 32]),
        settings.pils_profile,
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
    let length = gnunet_wire::official::pils::Request::Feed { block: &block }.encode(&mut input)?;
    let mut scratch = [0; 2048];
    let mut output = [0; 104];
    if !matches!(
        service.receive(&input[..length], &mut scratch, now, &mut output)?,
        Action::Broadcast { .. }
    ) {
        return Err("actual nonempty PILS FEED did not publish".into());
    }
    let expected = service.identity().public_key();
    let mut instance = gnunet_pils::client::Instance::new();
    let mut client = observer(
        &mut instance,
        gnunet_client_host::EndpointSource::unix_with_clock(path, clock),
        &settings,
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
        Ok::<Stream, io::Error>(stream)
    });
    let mut held = None;
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let progress = poll_fn(|cx| {
                if held.is_none() {
                    match sending.as_mut().poll(cx) {
                        Poll::Ready(Ok(stream)) => held = Some(stream),
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(PilsError::Io(error))),
                        Poll::Pending => {}
                    }
                }
                let mut driving = std::pin::pin!(client.drive(None));
                driving.as_mut().poll(cx)
            })
            .await?;
            match progress {
                Progress::Inbound(Inbound::Identity { identity, .. }) => {
                    return Ok::<_, Box<dyn Error>>(identity);
                }
                Progress::Lost { cause, .. } => {
                    return Err(io::Error::other(format!("original PILS lost: {cause:?}")).into());
                }
                Progress::Unavailable(error) => return Err(error.into()),
                Progress::Closed => return Err("original PILS closed before identity".into()),
                _ => {}
            }
        }
    })
    .await;
    let _retired = client.close();
    drop(held);
    let actual = result??;
    if actual.peer() != expected || actual.coverage() != settings.pils_profile.hello().coverage() {
        return Err("normal observer did not retain the selected source identity/coverage".into());
    }
    Ok(())
}

#[test]
fn normal_observer_accepts_nonempty_signed_hello_in_each_selected_profile()
-> Result<(), Box<dyn Error>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            selected_observer(b"reference029").await?;
            selected_observer(b"deterministic").await
        })
}

async fn write_all(stream: &Stream, bytes: &[u8]) -> io::Result<()> {
    let mut cursor = 0;
    while cursor < bytes.len() {
        stream.writable().await?;
        match stream.try_write(&bytes[cursor..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => cursor += n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

async fn attach<'a>(
    client: &mut Pils<'a>,
    listener: &Listener,
    announcement: &[u8],
    mut recovering: Option<(&mut recovery::Recovery, Identity<'a>)>,
) -> Result<(Identity<'a>, Stream), Box<dyn Error>> {
    let mut sending = std::pin::pin!(async {
        let (stream, _) = listener.accept().await?;
        write_all(&stream, announcement).await?;
        Ok::<_, io::Error>(stream)
    });
    let mut held = None;
    loop {
        let progress = poll_fn(|cx| {
            if held.is_none() {
                match sending.as_mut().poll(cx) {
                    Poll::Ready(Ok(stream)) => held = Some(stream),
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(PilsError::Io(error))),
                    Poll::Pending => {}
                }
            }
            let mut driving = std::pin::pin!(client.drive(None));
            driving.as_mut().poll(cx)
        })
        .await?;
        let identity = if let Some((owner, expected)) = recovering.as_mut() {
            match owner.observe(Ok(progress), *expected)? {
                IdentityUpdate::Ready(identity) => Some(identity),
                IdentityUpdate::Waiting | IdentityUpdate::Activity => None,
            }
        } else {
            match progress {
                Progress::Inbound(Inbound::Identity { identity, .. }) => Some(identity),
                original
                @ (Progress::Lost { .. } | Progress::Unavailable(_) | Progress::Closed) => {
                    return Err(provider_loss(original));
                }
                _ => None,
            }
        };
        if let Some(identity) = identity {
            return Ok((
                identity,
                held.take().ok_or("fixture announcement socket missing")?,
            ));
        }
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Native observer generations and fixed recovery ownership are the regression contract"
)]
fn observer_socket_replacement_needs_fresh_identity_and_keeps_the_first_bound()
-> Result<(), Box<dyn Error>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(10), async {
                let directory = Directory::new()?;
                let path = directory.0.join("p");
                let listener = Listener::bind(&path)?;
                let mut config = Configuration::default();
                config.set_value(b"cadet-rust", b"PEER_CORE", Some(b"NO"))?;
                let settings = Settings::read(&config)?;
                let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
                let hello = HelloLimits {
                    maximum_input_bytes: 4096,
                    maximum_address_bytes: 2048,
                    maximum_addresses: 16,
                };
                let original_service = Service::<4096>::new(
                    MasterKey::from_seed([0x61; 32]),
                    settings.pils_profile,
                    clock.sample()?.now.as_micros(),
                    hello,
                )?;
                let mut instance = gnunet_pils::client::Instance::new();
                let mut client = observer(
                    &mut instance,
                    gnunet_client_host::EndpointSource::unix_with_clock(
                        path.clone(),
                        clock.clone(),
                    ),
                    &settings,
                )?;
                let (original, stream) = attach(
                    &mut client,
                    &listener,
                    original_service.announcement(),
                    None,
                )
                .await?;
                drop(stream);
                drop(listener);
                std::fs::remove_file(&path)?;
                let mut owner = recovery::Recovery::new(Duration::from_secs(8));
                loop {
                    let actual = client.drive(None).await?;
                    let lost = matches!(actual, Progress::Lost { .. });
                    let update = owner.observe(Ok(actual), original)?;
                    if lost {
                        assert!(matches!(update, IdentityUpdate::Waiting));
                        break;
                    }
                }
                assert!(client.identity().is_none());
                let hard = owner.hard().ok_or("original recovery bound missing")?;
                let first = owner.first().ok_or("original loss missing")?.to_string();
                loop {
                    let actual = client.drive(None).await?;
                    let retry = matches!(actual, Progress::ConnectRetry { .. });
                    let update = owner.observe(Ok(actual), original)?;
                    if retry {
                        assert!(matches!(update, IdentityUpdate::Waiting));
                        break;
                    }
                }
                assert_eq!(owner.hard(), Some(hard));
                assert_eq!(
                    owner.first().ok_or("loss missing after retry")?.to_string(),
                    first
                );
                let replacement = Service::<4096>::new(
                    MasterKey::from_seed([0x62; 32]),
                    settings.pils_profile,
                    clock.sample()?.now.as_micros(),
                    hello,
                )?;
                let listener = Listener::bind(&path)?;
                let (fresh, stream) = attach(
                    &mut client,
                    &listener,
                    replacement.announcement(),
                    Some((&mut owner, original)),
                )
                .await?;
                assert_ne!(fresh.epoch(), original.epoch());
                assert_ne!(fresh.peer(), original.peer());
                assert_eq!(client.identity(), Some(fresh));
                // Identity verification does not stand in for the caller's provider barrier.
                assert_eq!(owner.hard(), Some(hard));
                owner.complete()?;
                assert!(!owner.pending());
                let malformed = [
                    0,
                    4,
                    replacement.announcement()[2],
                    replacement.announcement()[3],
                ];
                write_all(&stream, &malformed).await?;
                loop {
                    let actual = client.drive(None).await?;
                    if matches!(actual, Progress::Lost { .. }) {
                        assert!(owner.observe(Ok(actual), fresh).is_err());
                        assert!(!owner.pending());
                        break;
                    }
                }
                assert!(client.identity().is_none());
                assert!(client.close().iter().all(Option::is_none));
                Ok::<_, Box<dyn Error>>(())
            })
            .await?
        })
}
