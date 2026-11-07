//! The normal observer factory over actual Unix input and pure PILS signatures.
//! This is not a normal PILS daemon, DH/tunnel flow, or interoperability receipt.
use super::*;
use gnunet_config::Configuration;
use gnunet_pils::{Action, HelloLimits, MasterKey, Service};
use gnunet_service_runtime::clock::SystemClock;
use std::{
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::net::{UnixListener, UnixStream};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!(
            "cad-pils-{}-{}",
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

async fn selected_observer(label: &[u8]) -> Result<(), Box<dyn Error>> {
    let directory = Directory::new()?;
    let path = directory.0.join("p");
    let listener = UnixListener::bind(&path)?;
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
        Ok::<UnixStream, io::Error>(stream)
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
