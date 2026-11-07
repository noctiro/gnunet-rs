//! The queued owner over official configured TCP and lazy invalid configuration.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Real TCP wire traffic and original owner assertions"
)]
#[path = "../../resolver-broker-std/tests/support/domain.rs"]
mod resolution_domain;
use gnunet_client::{
    statistics::Selector,
    statistics_handle::{DestroyOutcome, GetFlow, SetterAdmission},
};
use gnunet_config::Configuration;
use gnunet_ipc_unix::handle::{Event, Limits, Progress, StatisticsHandle};
use std::{error::Error, io, net::Ipv4Addr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::Instant,
};
type Handle<'owner> = StatisticsHandle<'owner, 16, 128, 4, 16, 8>;
type TestResult = Result<(), Box<dyn Error>>;
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn config(port: u16) -> Result<Configuration, gnunet_config::Error> {
    let mut c = Configuration::new(Default::default());
    c.set_value(b"statistics", b"HOSTNAME", Some(b"127.0.0.1"))?;
    c.set_value(b"statistics", b"PORT", Some(port.to_string().as_bytes()))?;
    Ok(c)
}
fn create<'owner>(
    instance: &'owner mut gnunet_client::statistics_handle::Instance,
    config: &Configuration,
    resolution: gnunet_client_host::resolution::SharedResolution,
) -> Result<Handle<'owner>, Box<dyn Error>> {
    Ok(Handle::from_config(
        instance,
        config,
        resolution,
        b"s",
        Limits {
            max_frame_bytes: 256,
            write_chunk_bytes: 2,
        },
    )?
    .ok_or("owner disabled")?)
}
async fn frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let size = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if !(4..=65535).contains(&size) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = vec![0; size];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
fn selector() -> Selector<'static> {
    Selector {
        subsystem: b"s",
        name: b"n",
    }
}
#[test]
fn configured_tcp_uses_identical_official_frames_and_retains_partial_cursors() -> TestResult {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut statistics_instance_2 = gnunet_client::statistics_handle::Instance::new();
        let mut client = create(
            &mut statistics_instance_2,
            &config(listener.local_addr()?.port())?,
            domain.resolution(),
        )?;
        assert!(client.connection_epoch().is_none());
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            assert_eq!(
                frame(&mut stream).await?,
                b"\0\x14\0\xa8\0\0\0\x02\0\0\0\0\0\0\0\x07s\0n\0"
            );
            assert_eq!(frame(&mut stream).await?, b"\0\x08\0\xa9s\0n\0");
            let replies = b"\0\x14\0\xaa\x80\0\0\x03\0\0\0\0\0\0\0\x07s\0n\0\0\x04\0\xab";
            for byte in replies {
                stream.write_all(&[*byte]).await?;
            }
            assert_eq!(stream.read(&mut [0]).await?, 0);
            Ok::<_, io::Error>(())
        });
        client.set(b"n", 7, true)?;
        let get = client.get(selector())?;
        let mut done = false;
        let mut values = Vec::new();
        let until = Instant::now() + Duration::from_secs(2);
        while !done {
            assert_eq!(
                client
                    .drive(Some(until), |event, _| {
                        match event {
                            Event::GetValue { get: id, statistic } => {
                                assert_eq!(id, get);
                                assert_eq!(statistic.selector, selector());
                                values.push((statistic.value, statistic.persistent()));
                            }
                            Event::GetComplete(c) => {
                                assert_eq!(c.get, get);
                                assert!(c.result.is_ok());
                                done = true;
                            }
                            _ => {}
                        }
                        GetFlow::Continue
                    })
                    .await?,
                Progress::Activity
            );
        }
        assert_eq!(values, [(7, true)]);
        client.destroy(false)?;
        peer.await??;
        Ok(())
    })
}
#[test]
fn invalid_configuration_is_lazy_observable_and_never_creates_mq_or_unknown_setters() -> TestResult
{
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        for setting in [
            None,
            Some(b"NO" as &[u8]),
            Some(b"invalid"),
            Some(b"YES"),
            Some(b"yes"),
        ] {
            let mut config = Configuration::new(Default::default());
            if let Some(value) = setting {
                config.set_value(b"statistics", b"DISABLE", Some(value))?;
            }
            let mut statistics_instance_1 = gnunet_client::statistics_handle::Instance::new();
            let owner = Handle::from_config(
                &mut statistics_instance_1,
                &config,
                domain.resolution(),
                b"s",
                Limits::default(),
            )?;
            if setting.is_some_and(|v| v.eq_ignore_ascii_case(b"YES")) {
                assert!(owner.is_none());
                continue;
            }
            let mut client = owner.ok_or("non-YES disabled statistics")?;
            assert_eq!(client.update(b"n", 0, true)?, SetterAdmission::Noop);
            assert!(client.connection_epoch().is_none());
            assert_eq!(client.set(b"n", 1, false)?, SetterAdmission::Queued);
            assert!(client.connection_epoch().is_none());
            assert_eq!(client.set(b"n", 2, true)?, SetterAdmission::Coalesced);
            let mut unavailable = false;
            assert_eq!(
                client
                    .drive(Some(Instant::now() + Duration::from_secs(1)), |event, _| {
                        if let Event::ConnectionUnavailable { .. } = event {
                            unavailable = true;
                        }
                        GetFlow::Continue
                    })
                    .await?,
                Progress::Activity
            );
            assert!(unavailable);
            assert!(client.take_connect_error().is_some());
            client.destroy(true)?;
            let mut report = None;
            assert_eq!(
                client
                    .drive(None, |event, _| {
                        if let Event::Destroyed(value) = event {
                            report = Some(value);
                        }
                        GetFlow::Continue
                    })
                    .await?,
                Progress::Closed
            );
            let report = report.ok_or("missing destruction report")?;
            assert_eq!(report.outcome, DestroyOutcome::Discarded);
            assert_eq!(report.queued_mutations_discarded, 1);
            assert_eq!(report.unconfirmed_mutations, 0);
        }
        Ok(())
    })
}
#[test]
fn initial_tcp_refusal_preserves_virtual_mq_and_the_first_immutable_setter() -> TestResult {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = reserved.local_addr()?.port();
        drop(reserved);
        let mut statistics_instance_3 = gnunet_client::statistics_handle::Instance::new();
        let mut client = create(
            &mut statistics_instance_3,
            &config(port)?,
            domain.resolution(),
        )?;
        client.set(b"n", 1, false)?;
        let epoch = client.connection_epoch().ok_or("virtual MQ absent")?;
        let until = Instant::now() + Duration::from_secs(3);
        let mut retried = false;
        while !retried {
            assert_eq!(
                client
                    .drive(Some(until), |event, _| {
                        if let Event::ConnectRetry { epoch: id, .. } = event {
                            assert_eq!(id, epoch);
                            retried = true;
                        }
                        GetFlow::Continue
                    })
                    .await?,
                Progress::Activity
            );
        }
        client.set(b"n", 2, false)?;
        assert_eq!(client.set(b"n", 3, false)?, SetterAdmission::Coalesced);
        let get = client.get(selector())?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            for expected in [1_u64, 3] {
                let bytes = frame(&mut stream).await?;
                assert_eq!(&bytes[..8], b"\0\x14\0\xa8\0\0\0\0");
                assert_eq!(&bytes[8..16], &expected.to_be_bytes());
                assert_eq!(&bytes[16..], b"s\0n\0");
            }
            assert_eq!(frame(&mut stream).await?, b"\0\x08\0\xa9s\0n\0");
            stream
                .write_all(b"\0\x14\0\xaa\0\0\0\x03\0\0\0\0\0\0\0\x03s\0n\0\0\x04\0\xab")
                .await?;
            assert_eq!(stream.read(&mut [0]).await?, 0);
            Ok::<_, io::Error>(())
        });
        let mut done = false;
        let mut values = Vec::new();
        while !done {
            assert_eq!(
                client
                    .drive(Some(until), |event, _| {
                        match event {
                            Event::GetValue { get: id, statistic } => {
                                assert_eq!(id, get);
                                values.push(statistic.value);
                            }
                            Event::GetComplete(c) => {
                                assert_eq!(c.get, get);
                                assert!(c.result.is_ok());
                                done = true;
                            }
                            Event::ConnectionLost { .. } => {
                                assert!(
                                    !matches!(event, Event::ConnectionLost { .. }),
                                    "initial refusal retired the original MQ"
                                )
                            }
                            _ => {}
                        }
                        GetFlow::Continue
                    })
                    .await?,
                Progress::Activity
            );
            assert_eq!(client.connection_epoch(), Some(epoch));
        }
        assert_eq!(values, [3]);
        client.destroy(false)?;
        peer.await??;
        Ok(())
    })
}
