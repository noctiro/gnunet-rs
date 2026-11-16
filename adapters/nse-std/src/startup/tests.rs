use super::driver::poll_ports;
#[cfg(unix)]
use super::identity::require_ids;
use super::*;
use crate::Progress;
use crate::test_support::{Directory, Listener as UnixListener};
use gnunet_client::resolver::{Reply, Request, encode_response};
use gnunet_resolver_broker::{FamilyProfile, LiveConfiguration, broker};
#[cfg(unix)]
use gnunet_service_startup::Identity as ProcessIdentity;
use gnunet_wire::official::Frame;
use std::time::Duration;
use std::{future::poll_fn, task::Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Selected identity and credential options must fail closed without mutating process IDs"
)]
fn configured_admission_and_primary_ids_are_explicit() -> Result<(), Box<dyn Error>> {
    let mut config = Configuration::default();
    assert_eq!(
        configured_limits(&config, Limits::default())?.pils_profile,
        gnunet_pils::Profile::Reference029
    );
    config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
    assert_eq!(
        configured_limits(&config, Limits::default())?.pils_profile,
        gnunet_pils::Profile::ReferenceDeterministic
    );
    config.set_value(b"PILS", b"PROFILE", Some(b"unknown"))?;
    assert!(configured_limits(&config, Limits::default()).is_err());
    config.set_value(b"PILS", b"PROFILE", None)?;
    let absent = unix_access(&config)?;
    assert!(!absent.match_uid && !absent.match_gid);
    verify_configured_identity(&config)?;
    config.set_value(b"NSE", b"UNIX_MATCH_UID", Some(b"YES"))?;
    config.set_value(b"NSE", b"UNIX_MATCH_GID", Some(b"YES"))?;
    let selected = unix_access(&config)?;
    assert!(selected.match_uid && selected.match_gid);
    for key in [b"UNIX_MATCH_UID".as_slice(), b"UNIX_MATCH_GID".as_slice()] {
        config.set_value(b"NSE", key, Some(b"malformed"))?;
        assert!(unix_access(&config).is_err());
        config.set_value(b"NSE", key, Some(b"YES"))?;
    }
    #[cfg(unix)]
    {
        let matching = ProcessIdentity {
            uid: 41,
            euid: 41,
            gid: 83,
            egid: 83,
        };
        assert_eq!(require_ids(41, 83, matching), Ok(()));
        for actual in [
            ProcessIdentity {
                uid: 42,
                ..matching
            },
            ProcessIdentity {
                euid: 42,
                ..matching
            },
            ProcessIdentity {
                gid: 84,
                ..matching
            },
            ProcessIdentity {
                egid: 84,
                ..matching
            },
        ] {
            assert_eq!(
                require_ids(41, 83, actual),
                Err(ConfiguredIdentityMismatch {
                    expected_uid: 41,
                    expected_gid: 83,
                    actual,
                })
            );
        }
    }
    Ok(())
}
#[test]
fn continuously_ready_host_does_not_starve_original_shared_resolver_end()
-> Result<(), Box<dyn Error>> {
    resolver_completion(false)
}
#[test]
fn pending_host_does_not_repoll_completed_original_resolver_future() -> Result<(), Box<dyn Error>> {
    resolver_completion(true)
}
#[expect(
    clippy::panic_in_result_fn,
    reason = "Actual Unix Resolver completion must remain driven while the other service future is pending"
)]
fn resolver_completion(pending_host: bool) -> Result<(), Box<dyn Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let directory = Directory::new()?;
        let socket = directory.0.join("resolver");
        let listener = UnixListener::bind(&socket).await?;
        let native = gnunet_resolver_broker::native_profile()?;
        let family = FamilyProfile::new(
            native.encode(gnunet_resolver_broker::Family::V4),
            native.encode(gnunet_resolver_broker::Family::V6),
        )?;
        let mut config = Configuration::default();
        config.set_value(
            b"resolver",
            b"UNIXPATH",
            Some(&gnunet_native::os_bytes::encode(socket.as_os_str())),
        )?;
        let shared = Arc::new(gnunet_program_host::shared_clock::SharedClock::native(8)?);
        let clock: Arc<dyn RuntimeClock> = shared.clone();
        let (context, mut driver) = broker::<4, 64>(
            LiveConfiguration::new(config),
            Default::default(),
            family,
            clock.clone(),
        )?;
        let ports = context.resolution_context();
        assert!(Arc::ptr_eq(&clock, &ports.clock()));
        let mut lookup = ports
            .lookup(b"nse-original-fairness.invalid", Duration::from_secs(2))?
            .ok_or("missing original shared query")?;
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.socket.accept().await?;
            let mut header = [0; 4];
            stream.read_exact(&mut header).await?;
            let len = usize::from(u16::from_be_bytes([header[0], header[1]]));
            let mut bytes = vec![0; len];
            bytes[..4].copy_from_slice(&header);
            stream.read_exact(&mut bytes[4..]).await?;
            let request = Request::decode(Frame::decode(&bytes)?, family)?;
            assert!(matches!(
                request.query(),
                gnunet_client::resolver::Query::Forward {
                    hostname: b"nse-original-fairness.invalid",
                    ..
                }
            ));
            let mut end = [0; 8];
            let n = encode_response(request.id(), Reply::End, &mut end)?;
            stream.write_all(&end[..n]).await?;
            assert_eq!(stream.read(&mut [0]).await?, 0);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        let until = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            tokio::task::yield_now().await;
            {
                let driving = async {
                    if pending_host {
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Ok(Progress::Activity)
                };
                let resolving = driver.drive_waiting(None, |_| {});
                let mut driving = std::pin::pin!(driving);
                let mut resolving = std::pin::pin!(resolving);
                assert!(matches!(
                    poll_fn(|cx| poll_ports(cx, driving.as_mut(), resolving.as_mut())).await?,
                    Some(Progress::Activity)
                ));
            }
            let done = poll_fn(|cx| {
                Poll::Ready(match lookup.poll_next(cx) {
                    Poll::Ready(result) => Some(result),
                    Poll::Pending => None,
                })
            })
            .await;
            if let Some(result) = done {
                assert_eq!(result?, None);
                break;
            }
            if tokio::time::Instant::now() >= until {
                return Err("continuously ready Host starved actual Resolver request/END".into());
            }
        }
        assert_eq!(context.pending_requests()?, 0);
        drop(lookup);
        drop(ports);
        drop(driver);
        drop(context);
        peer.await?.map_err(|e| e.to_string())?;
        assert_eq!(shared.listeners()?, 0);
        Ok::<_, Box<dyn Error>>(())
    })
}
