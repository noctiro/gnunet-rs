//! Actual kernel TCP/Unix admission without driving or inventing CORE/PILS/NSE effects.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Actual native admission must retain exact denial, capacity, EOF and inactive-owner observations"
)]
use gnunet_client_host::EndpointSource;
use gnunet_config::Configuration;
use gnunet_nse::owner;
use gnunet_nse_host::{Error as HostError, Host, Instances, Limits, Ports, proof, startup};
use gnunet_service_runtime::{
    clock::{RuntimeClock, SystemClock},
    service::{Listener, ShutdownMode},
    service_options,
};
use std::{error::Error, future::poll_fn, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream, UnixListener, UnixStream},
};
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self, Box<dyn Error>> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("gnrs-nse-admission-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn actual_kernel_admission_precedes_framing_and_pure_start() -> Result<(), Box<dyn Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let scratch = Scratch::new()?;
        let mut config = Configuration::default();
        config.set_value(b"NSE", b"REJECT_FROM", Some(b"127.0.0.1;"))?;
        config.set_value(b"NSE", b"UNIX_MATCH_UID", Some(b"YES"))?;
        config.set_value(b"NSE", b"UNIX_MATCH_GID", Some(b"YES"))?;
        let options = service_options(&config, b"NSE", ShutdownMode::Immediate)?;
        let access = startup::unix_access(&config)?;
        assert!(access.match_uid && access.match_gid);
        let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
        let mut nse_instance = owner::Instance::new();
        let mut core_instance = gnunet_core_client_host::Instance::new();
        let mut pils_instance = gnunet_pils::client::Instance::new();
        let mut host = Host::<2, 1>::new_with_access(
            Instances {
                nse: &mut nse_instance,
                core: &mut core_instance,
                pils: &mut pils_instance,
            },
            Ports {
                core: EndpointSource::unix_with_clock(scratch.0.join("unused-core"), clock.clone()),
                pils: EndpointSource::unix_with_clock(scratch.0.join("unused-pils"), clock.clone()),
                clock,
            },
            owner::Config::default(),
            Limits {
                peers: 2,
                subscribers: 1,
                ..Limits::default()
            },
            options,
            access,
            proof::Store::open(scratch.0.join("proof"))?,
        )?;
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        let mut denied = TcpStream::connect(tcp.local_addr()?).await?;
        let accepted = poll_fn(|cx| Listener::Tcp(&tcp).poll_canonical_connection(cx)).await?;
        assert!(!host.admit(accepted, &mut |_| {})?);
        let mut byte = [0; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), denied.read(&mut byte)).await??,
            0
        );
        assert_eq!(host.report().accepted, 0);
        assert_eq!(host.report().rejected, 1);

        // Same actual effective UID is accepted with both flags selected. This
        // uses kernel credentials; it does not assert a foreign-account matrix.
        let unix_path = scratch.0.join("nse");
        let unix = UnixListener::bind(&unix_path)?;
        let mut first = UnixStream::connect(&unix_path).await?;
        let accepted = poll_fn(|cx| Listener::Unix(&unix).poll_canonical_connection(cx)).await?;
        assert!(host.admit(accepted, &mut |_| {})?);
        assert_eq!(host.report().accepted, 1);
        assert_eq!(host.identity(), None);
        assert_eq!(host.peer_count(), 0);
        assert_eq!(host.report().work_calls, 0);
        assert_eq!(host.report().signatures, 0);
        assert_eq!(host.report().submissions, 0);
        assert_eq!(host.pending_effects(), (0, 0, false, false, None));

        // The public external-accept port also refuses a full original slot.
        // It closes only the new stream and retains the first physical MQ.
        let mut extra = UnixStream::connect(&unix_path).await?;
        let accepted = poll_fn(|cx| Listener::Unix(&unix).poll_canonical_connection(cx)).await?;
        assert!(matches!(
            host.admit(accepted, &mut |_| {}),
            Err(HostError::Protocol(gnunet_types::Error::Capacity))
        ));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), extra.read(&mut byte)).await??,
            0
        );
        assert_eq!(host.report().accepted, 1);
        assert_eq!(host.report().admission_failures, 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), first.read(&mut byte))
                .await
                .is_err()
        );
        host.close()?;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), first.read(&mut byte)).await??,
            0
        );
        assert_eq!(host.report().work_calls, 0);
        assert_eq!(host.identity(), None);
        drop(host);
        drop((extra, first, denied, unix, tcp));
        Ok::<_, Box<dyn Error>>(())
    })
}
