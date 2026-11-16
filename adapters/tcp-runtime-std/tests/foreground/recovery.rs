//! Normal Rust foreground and PILS host over private IPC; PEERSTORE/TRANSPORT
//! are stream fixtures, so this is not official C or peer-handshake coverage.
use super::*;
use gnunet_pils_host::service::Host;
use gnunet_tcp_communicator_runtime::startup::{Diagnostic, IdentityEvent};
use std::{cell::Cell, rc::Rc};

fn pils(config: &gnunet_config::Configuration) -> Result<Host, Failure> {
    Ok(gnunet_pils_host::startup::prepare(
        config,
        Arc::new(SystemClock),
        gnunet_pils_host::service::Limits {
            clients: 4,
            address_bytes: 4096,
            ..Default::default()
        },
    )?
    .into_host())
}
fn frontier(root: &std::path::Path, peer: [u8; 32]) -> PathBuf {
    let name: String = peer.iter().map(|byte| format!("{byte:02x}")).collect();
    root.join(format!("state/tcp-{name}.frontier"))
}
fn clean(path: &std::path::Path) -> Result<bool, Failure> {
    let bytes = std::fs::read(path)?;
    let image = gnunet_tcp_communicator_runtime::replay::pairing::FrontierImage::decode(
        bytes.as_slice().try_into().map_err(|_| Error::Malformed)?,
    )?;
    Ok(!image.dirty && image.minimum > 0 && image.reserved > 0)
}
async fn source_replacement(changed_master: bool) -> Result<(), Failure> {
    let directory = Directory::create("gn-tcp-source")?;
    let root = &directory.0;
    let seed = root.join("seed");
    let mut file = gnunet_native::filesystem::Directory::open(root)?
        .create_private_file(std::ffi::OsStr::new("seed"))?;
    std::io::Write::write_all(&mut file, &[17; 32])?;
    file.sync_all()?;
    drop(file);
    let mut config = gnunet_config::Configuration::default();
    for (section, path) in [
        (b"pils".as_slice(), root.join("p")),
        (b"peerstore", root.join("s")),
        (b"transport", root.join("t")),
    ] {
        config.set_value(
            section,
            b"UNIXPATH",
            Some(path.as_os_str().as_encoded_bytes()),
        )?;
    }
    config.set_value(b"communicator-tcp", b"BINDTO", Some(b"127.0.0.1:0"))?;
    config.set_value(b"communicator-tcp", b"DISABLE_V6", Some(b"YES"))?;
    config.set_value(
        b"peer",
        b"PRIVATE_KEY",
        Some(seed.as_os_str().as_encoded_bytes()),
    )?;
    let p = UnixListener::bind(root.join("p"))?;
    let s = UnixListener::bind(root.join("s"))?;
    let t = UnixListener::bind(root.join("t"))?;
    let ports = [gnunet_service_runtime::service::Listener::Unix(&p)];
    let mut provider = Some(pils(&config)?);
    let original_peer = provider
        .as_ref()
        .and_then(Host::identity)
        .ok_or("missing initial PILS peer")?;
    let original_frontier = frontier(root, original_peer);
    let expected_peer = Cell::new(original_peer);
    let ready = RefCell::new(None);
    let ready_calls = Cell::new(0);
    let generations = Cell::new(0);
    let connections = Cell::new(0);
    let losses = Cell::new(0);
    let stop = Rc::new(Cell::new(false));
    let stop_poll = stop.clone();
    let clock = Clock::new();
    let shutdown = std::future::poll_fn(move |_| {
        if stop_poll.get() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    });
    let mut future = Box::pin(startup::foreground_local_with_clock(
        LocalStartup {
            config: &config,
            activation: Activation::default(),
            state_directory: root.join("state"),
            local_key: LocalKeyCapability {
                ikm_file: seed.clone(),
            },
            limits: Limits {
                sessions: 1,
                ..Default::default()
            },
        },
        |listeners, _| {
            ready_calls.set(ready_calls.get() + 1);
            *ready.borrow_mut() = Some(listeners.addresses()[0]);
            Ok(())
        },
        shutdown,
        |_| {},
        |event| match event {
            gnunet_pils_host::client::Progress::Connected(_) => {
                connections.set(connections.get() + 1)
            }
            gnunet_pils_host::client::Progress::Lost { .. } => losses.set(losses.get() + 1),
            _ => {}
        },
        |event| {
            if let Diagnostic::Identity(IdentityEvent::Ready { peer }) = event {
                assert_eq!(
                    peer,
                    expected_peer.get(),
                    "ready used an unverified/obsolete peer"
                );
                generations.set(generations.get() + 1);
            }
        },
        Arc::new(clock.clone()),
    ));
    let mut stores: Vec<(UnixStream, bool)> = Vec::new();
    let mut transports: Vec<(UnixStream, bool)> = Vec::new();
    let mut raw = None;
    let mut admitted = None;
    let mut cut = false;
    let mut old_clean = false;
    let mut replaced = false;
    let mut cx = Context::from_waker(Waker::noop());
    let deadline = Instant::now() + Duration::from_secs(15);
    let result = loop {
        if let Some(provider) = &mut provider {
            let mut observe = |_| {};
            let mut drive = std::pin::pin!(provider.drive(&ports, &mut observe, None));
            if let Poll::Ready(result) = drive.as_mut().poll(&mut cx) {
                result?;
            }
        }
        if let Poll::Ready(result) = s.poll_accept(&mut cx) {
            stores.push((result?.0, false));
        }
        if let Poll::Ready(result) = t.poll_accept(&mut cx) {
            transports.push((result?.0, false));
        }
        for (stream, ended) in stores.iter_mut().chain(transports.iter_mut()) {
            if !*ended {
                *ended = drain(stream)?;
            }
        }
        if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
            break result;
        }
        if generations.get() == 1 && raw.is_none() {
            let address = (*ready.borrow()).ok_or("listener was not retained")?;
            let mut stream = TcpStream::connect(address).await?;
            stream.write_all(&[0]).await?;
            raw = Some(stream);
            admitted = Some(Instant::now());
        }
        if !cut && admitted.is_some_and(|at| at.elapsed() > Duration::from_millis(50)) {
            assert!(
                !clean(&original_frontier)?,
                "first active epoch was not dirty"
            );
            provider.take().ok_or("initial source disappeared")?.close();
            cut = true;
        }
        if cut && !replaced {
            old_clean = clean(&original_frontier)?;
            if !old_clean {
                assert_eq!(
                    connections.get(),
                    1,
                    "PILS reconnected before actual old replay retirement"
                );
            }
            if old_clean
                && stores.first().is_some_and(|(_, end)| *end)
                && transports.first().is_some_and(|(_, end)| *end)
            {
                let mut byte = [0];
                assert_eq!(
                    raw.as_ref()
                        .ok_or("missing original peer stream")?
                        .try_read(&mut byte)?,
                    0,
                    "old partial peer stream survived replacement"
                );
                if changed_master {
                    // The original normal provider has released its private
                    // file lease. Replace only this fixture's existing raw32.
                    let mut file = std::fs::OpenOptions::new().write(true).open(&seed)?;
                    std::io::Write::write_all(&mut file, &[18; 32])?;
                    file.sync_all()?;
                }
                let next = pils(&config)?;
                expected_peer.set(next.identity().ok_or("missing replacement identity")?);
                provider = Some(next);
                replaced = true;
            }
        }
        if generations.get() == 2 {
            stop.set(true);
        }
        assert!(
            Instant::now() < deadline,
            "TCP source recovery stalled: cut={cut} old_clean={old_clean} replaced={replaced} ready={} connections={} loss={} stores={} transports={}",
            generations.get(),
            connections.get(),
            losses.get(),
            stores.len(),
            transports.len()
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    };
    let report = result?;
    drop(future);
    assert!(cut && old_clean && replaced && report.clean);
    assert_eq!(report.generations, 2);
    assert_eq!(generations.get(), 2);
    assert_eq!(ready_calls.get(), 1);
    assert_eq!(losses.get(), 1);
    assert!(connections.get() >= 2);
    assert_eq!(expected_peer.get() != original_peer, changed_master);
    assert!(clean(&original_frontier)?);
    assert!(clean(&frontier(root, expected_peer.get()))?);
    assert_eq!(clock.active(), 0, "original canonical subscriptions leaked");
    provider
        .as_mut()
        .ok_or("replacement source absent")?
        .close();
    for (mut stream, _) in stores.into_iter().chain(transports) {
        tokio::time::timeout(Duration::from_secs(1), async {
            let mut bytes = [0; 4096];
            while stream.read(&mut bytes).await? != 0 {}
            Ok::<_, std::io::Error>(())
        })
        .await??;
    }
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn normal_foreground_retires_old_epoch_before_same_or_changed_pils_source_recovers()
-> Result<(), Failure> {
    source_replacement(false).await?;
    source_replacement(true).await
}
