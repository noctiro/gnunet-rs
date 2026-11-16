//! Native TLS drivers, private IPC and signed Rust PILS component fixtures.
//! This does not qualify official C peers or GNUnet identity authentication.
use super::*;
use gnunet_pils::{HelloLimits, MasterKey, Service};
use gnunet_service_runtime::{
    clock::SystemClock,
    local::{Listener, Stream},
};
use std::{
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    task::Waker,
};

type Failure = Box<dyn std::error::Error>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}
fn drain(stream: &Stream, bytes: &mut Vec<u8>) -> io::Result<bool> {
    let mut buffer = [0; 4096];
    loop {
        match stream.try_read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(n) => bytes.extend_from_slice(&buffer[..n]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
    }
}
async fn case(profile: crate::tls::Profile, changed_peer: bool) -> Result<(), Failure> {
    let directory = Directory(std::env::temp_dir().join(format!(
        "quic-source-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    gnunet_service_runtime::private_parents(&directory.0.join(".fixture"))?;
    let p = directory.0.join("p");
    let t = directory.0.join("t");
    let p_listener = Listener::bind(&p)?;
    let t_listener = Listener::bind(&t)?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
    let utc = clock.sample()?.now.as_micros();
    let hello = HelloLimits {
        maximum_input_bytes: 2048,
        maximum_address_bytes: 1024,
        maximum_addresses: 8,
    };
    let original = Service::<2048>::new(
        MasterKey::from_seed([7; 32]),
        gnunet_pils::Profile::Reference029,
        utc,
        hello,
    )?;
    let replacement = Service::<2048>::new(
        MasterKey::from_seed([if changed_peer { 8 } else { 7 }; 32]),
        gnunet_pils::Profile::Reference029,
        utc,
        hello,
    )?;
    let original_peer = *original.identity().public_key().as_bytes();
    let limits = Limits {
        backend: endpoint::Limits {
            connections: 1,
            bidi: 4,
            ..Default::default()
        },
        h3_polls: 1,
        io_slice: 7,
        startup: Duration::from_secs(5),
        lifetime: Duration::from_secs(15),
        close_grace: Duration::from_millis(100),
        ..Default::default()
    };
    let instance = Instance::new();
    let mut raw_body = vec![0; limits.raw_body];
    let mut raw_loans = [Some(&mut raw_body[..])];
    let mut bodies = vec![vec![0; limits.h3_body]; limits.h3_polls + 2];
    let mut slots: Vec<_> = bodies
        .iter_mut()
        .map(|body| gnunet_transport_quic::h3::Slot::new(body))
        .collect();
    let mut h3_loans = [Some(&mut slots[..])];
    let loans = match profile {
        crate::tls::Profile::Raw => Buffers::Raw(&mut raw_loans),
        crate::tls::Profile::Http3 => Buffers::Http3(&mut h3_loans),
    };
    let mut pils_instance = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::new(
        &instance,
        &mut pils_instance,
        Sources {
            transport: EndpointSource::unix_with_clock(t, clock.clone()),
            pils: EndpointSource::unix_with_clock(p, clock),
            nat: None,
        },
        "127.0.0.1:0".parse()?,
        Tls::fresh(profile, vec!["gnunet".into()])?,
        loans,
        limits,
    )?;
    let bound = runtime.local_addr()?;
    let allocation = runtime.epoch;
    let mut peer = Endpoint::bind(
        "127.0.0.1:0".parse()?,
        Tls::fresh(profile, vec!["gnunet".into()])?,
        limits.backend,
        Instant::now() + Duration::from_secs(15),
    )
    .map_err(Fault::from)?;
    let mut connecting: Option<endpoint::Connecting> = None;
    let mut connection = None;
    let mut streams: Vec<(Stream, Vec<u8>, bool)> = Vec::new();
    let mut source = None;
    let mut accepted = 0;
    let mut write = 0;
    let mut cut = false;
    let mut losses = 0;
    let mut old_exposed = 0;
    let mut first_bound = None;
    let mut saw_unsigned = false;
    let mut cx = Context::from_waker(Waker::noop());
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        peer.poll_drivers(&mut cx).map_err(Fault::from)?;
        if let Some(attempt) = &mut connecting
            && let Poll::Ready(result) = Pin::new(&mut attempt.connecting).poll(&mut cx)
        {
            connection = Some(result?);
            connecting = None;
        }
        if let Poll::Ready(result) = runtime.poll(&mut cx, None, &mut |event| match event {
            Event::IdentityEnded { .. } => losses += 1,
            Event::TransportOutputRetired {
                generation: 1,
                bytes,
                ..
            } => old_exposed += bytes,
            _ => {}
        }) {
            result?;
        }
        if cut && runtime.pils.epoch().is_some() {
            assert!(
                runtime.rows.iter().all(Option::is_none) && runtime.loans.available(),
                "successor PILS source polled before old driver/loans retired"
            );
        }
        if let Poll::Ready(result) = t_listener.poll_accept(&mut cx) {
            streams.push((result?.0, Vec::new(), false));
        }
        for (stream, bytes, ended) in &mut streams {
            if !*ended {
                *ended = drain(stream, bytes)?;
            }
        }
        if let Poll::Ready(result) = p_listener.poll_accept(&mut cx) {
            accepted += 1;
            write = 0;
            if accepted == 2 {
                drop(result?.0);
                saw_unsigned = true;
            } else {
                source = Some(result?.0);
            }
        }
        if let Some(stream) = &source {
            let announcement = if accepted == 1 {
                original.announcement()
            } else {
                replacement.announcement()
            };
            if write < announcement.len() {
                match stream.try_write(&announcement[write..]) {
                    Ok(0) => return Err("fixture PILS write zero".into()),
                    Ok(n) => write += n,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        if runtime.restored && !cut && connecting.is_none() && connection.is_none() {
            connecting = Some(peer.dial(bound).map_err(Fault::from)?);
        }
        if !cut
            && connection.is_some()
            && runtime.rows.iter().flatten().any(|row| row.link.is_some())
        {
            assert_eq!(runtime.identity.selected(), Some(original_peer));
            drop(source.take());
            cut = true;
        }
        if cut && runtime.identity.source_lost() {
            let current = runtime
                .identity
                .bound()
                .ok_or("source loss omitted recovery bound")?;
            if let Some(first) = first_bound {
                assert_eq!(
                    current, first,
                    "connection retry renewed original recovery bound"
                );
            } else {
                first_bound = Some(current);
            }
            assert!(runtime.identity.selected().is_none());
        }
        if cut && accepted >= 3 && runtime.restored && runtime.identity.bound().is_none() {
            assert_eq!(losses, 2);
            assert!(saw_unsigned && first_bound.is_some());
            assert_eq!(runtime.local_addr()?, bound);
            assert_eq!(runtime.epoch, allocation);
            assert_eq!(
                runtime.identity.selected() != Some(original_peer),
                changed_peer
            );
            assert_eq!(streams.len(), 2);
            assert!(streams[0].2, "old IPC stream remained open");
            assert!(runtime.rows.iter().all(Option::is_none) && runtime.loans.available());
            let mut captured = true;
            for (index, (_, bytes, _)) in streams.iter().enumerate() {
                let mut input = bytes.as_slice();
                let mut registered = false;
                while !input.is_empty() {
                    if input.len() < 4 {
                        if index == 0 {
                            assert_eq!(
                                input.len(),
                                old_exposed,
                                "old partial header lost its actual retirement receipt"
                            );
                        } else {
                            captured = false;
                        }
                        break;
                    }
                    let len = usize::from(u16::from_be_bytes([input[0], input[1]]));
                    if len < 4 {
                        return Err("invalid fixture IPC frame".into());
                    }
                    if len > input.len() {
                        if index == 0 {
                            assert_eq!(
                                input.len(),
                                old_exposed,
                                "old partial frame lost its actual retirement receipt"
                            );
                        } else {
                            captured = false;
                        }
                        break;
                    }
                    registered |=
                        matches!(Request::decode(&input[..len])?, Request::Register { .. });
                    input = &input[len..];
                }
                if index == 0 {
                    assert!(registered, "original lacked a whole-written REGISTER");
                } else {
                    captured &= registered;
                }
            }
            // A local whole-write receipt can precede the fixture reactor's
            // next readable turn. Keep reading the same original stream.
            if captured {
                break;
            }
        }
        assert!(
            Instant::now() < until,
            "source recovery stalled: profile={profile:?} accepted={accepted} losses={losses} cut={cut} rows={} ready={} restored={}",
            runtime.rows.iter().flatten().count(),
            runtime.ready,
            runtime.restored
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let closed = runtime.shutdown(|_| {}).await;
    assert!(
        closed.cleanup.is_none(),
        "runtime cleanup failed: {closed:?}"
    );
    drop(connection);
    drop(connecting);
    peer.begin_close();
    peer.close().map_err(Fault::from)?;
    Ok(())
}
#[test]
fn native_pils_replacement_retires_tls_drivers_and_keeps_endpoint_for_both_profiles()
-> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            case(crate::tls::Profile::Raw, false).await?;
            case(crate::tls::Profile::Raw, true).await?;
            #[cfg(feature = "h3-profile")]
            {
                case(crate::tls::Profile::Http3, false).await?;
                case(crate::tls::Profile::Http3, true).await?;
            }
            Ok(())
        })
}
