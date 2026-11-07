//! Real loopback SOAP exchanges exercise the manager's original mutation debt.
//! No SSDP, real gateway, interface enumeration or helper process is used.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Loopback ownership regressions assert actual requests and cleanup observations."
)]
use super::*;
use gnunet_client_host::resolution::{AddressLookup, ResolutionContext, ResolutionTimer};
use gnunet_service_runtime::{
    clock::{self, SystemClock},
    connection::ConnectionLease,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
mod selection_tests;

const SERVICE: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";
const INTERNAL: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
const PORT: u16 = 2086;

struct LocalPorts(Arc<dyn RuntimeClock>);
struct NumericLookup(u8);
struct NumericLease;
impl ConnectionLease for NumericLease {}
impl AddressLookup for NumericLookup {
    fn poll_next(&mut self, _: &mut Context<'_>) -> Poll<io::Result<Option<IpAddr>>> {
        match self.0 {
            0 => {
                self.0 = 1;
                Poll::Ready(Ok(Some(IpAddr::V4(Ipv4Addr::LOCALHOST))))
            }
            1 => Poll::Ready(Err(io::Error::other("address effect not returned"))),
            _ => Poll::Ready(Ok(None)),
        }
    }
    fn address_effect_done(&mut self) -> io::Result<()> {
        if self.0 != 1 {
            return Err(io::Error::other("no original numeric callback"));
        }
        self.0 = 2;
        Ok(())
    }
    fn connected(self: Box<Self>) -> io::Result<Box<dyn ConnectionLease>> {
        if self.0 != 2 {
            return Err(io::Error::other("numeric callback not acknowledged"));
        }
        Ok(Box::new(NumericLease))
    }
}
impl ResolutionContext for LocalPorts {
    fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.0.clone()
    }
    fn lookup(&self, host: &[u8], _: Duration) -> io::Result<Option<Box<dyn AddressLookup>>> {
        if host != b"127.0.0.1" {
            return Err(io::Error::other(
                "fixture permits only its numeric loopback target",
            ));
        }
        Ok(Some(Box::new(NumericLookup(0))))
    }
    fn timer(&self, delay: Duration) -> io::Result<ResolutionTimer> {
        let timer = clock::Deadline::after(self.0.clone(), delay).map_err(io::Error::other)?;
        Ok(Box::pin(
            async move { timer.await.map_err(io::Error::other) },
        ))
    }
}
fn settings() -> Settings {
    Settings {
        enable_upnp: false,
        enable_ipscan: false,
        disable_v6: false,
        return_local_addresses: false,
        use_stun: false,
        interface_interval: Duration::from_secs(60),
        dyndns_interval: Duration::from_secs(60),
        external_interval: Duration::from_secs(60),
        stun_stale: Duration::from_secs(60),
        stun_interval: Duration::from_secs(60),
        stun_servers: Vec::new(),
        stun_datagrams: 1,
        job_timeout: Duration::from_secs(5),
        cleanup_timeout: Duration::from_secs(5),
        mapping_interval: Duration::from_secs(60),
        jobs: 4,
        mappings: 4,
        interfaces: gnunet_native::interfaces::Limits::default(),
        helper_limits: crate::helpers::Limits::default(),
        helper_paths: crate::helpers::Paths {
            server: "/private/tmp/gnrs-upnp-unused-server".into(),
            client: "/private/tmp/gnrs-upnp-unused-client".into(),
        },
    }
}
fn manager(device: Device) -> Result<(Manager, Source, Intent), Failure> {
    let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
    manager_with_clock(device, clock)
}
fn manager_with_clock(
    device: Device,
    clock: Arc<dyn RuntimeClock>,
) -> Result<(Manager, Source, Intent), Failure> {
    let resolver: SharedResolution = Arc::new(LocalPorts(clock.clone()));
    let mut manager = Manager::new(
        Configuration::default(),
        settings(),
        state::Limits::default(),
        resolver,
        clock,
    )?;
    let source = manager.source_attached()?;
    let binding = SocketAddress::V4 {
        ip: INTERNAL.octets(),
        port: PORT,
    };
    manager.core.register(
        source,
        state::RegistrationInput {
            flags: nat::ADDRESSES,
            protocol: 6,
            section: b"fixture",
            bindings: &[binding],
            options: state::Options::default(),
        },
        manager.clock.sample()?.now.as_micros(),
    )?;
    let provider = manager.core.provider_started(ProviderKind::Mapping {
        source,
        protocol: 6,
        internal: binding,
    })?;
    Ok((
        manager,
        source,
        Intent {
            source,
            provider,
            device,
            internal: INTERNAL,
            port: PORT,
            protocol: Protocol::Tcp,
        },
    ))
}
enum WatchedResponse {
    Add(upnp::AddAttempt),
    Delete(upnp::DeleteAttempt),
}
std::thread_local! {
    // Attempts are caller-thread Rc owners. The controlled clock reads their
    // actual observations on this current-thread runtime; it never constructs
    // a response receipt or injects a phase into the production owners.
    static POST_RESPONSE: std::cell::RefCell<Option<WatchedResponse>> = const { std::cell::RefCell::new(None) };
}
struct Watch;
impl Drop for Watch {
    fn drop(&mut self) {
        POST_RESPONSE.with(|slot| {
            *slot.borrow_mut() = None;
        });
    }
}
fn watch(response: WatchedResponse) -> Watch {
    POST_RESPONSE.with(|slot| {
        *slot.borrow_mut() = Some(response);
    });
    Watch
}
struct PostResponseClock;
impl RuntimeClock for PostResponseClock {
    fn sample(&self) -> Result<clock::ClockSample, Fault> {
        let completed = POST_RESPONSE.with(|slot| match slot.borrow().as_ref() {
            Some(WatchedResponse::Add(attempt)) => matches!(
                attempt.outcome(),
                upnp::AddOutcome::Committed | upnp::AddOutcome::KnownRejected
            ),
            Some(WatchedResponse::Delete(attempt)) => {
                attempt.removal() == Some(upnp::Removal::Removed)
            }
            None => false,
        });
        if completed {
            Err(Fault::TimeUncertain)
        } else {
            SystemClock.sample()
        }
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Fault> {
        SystemClock.subscribe()
    }
}
fn device(address: SocketAddr) -> Result<Device, Failure> {
    let location = crate::http::Url::parse(&format!("http://{address}/device.xml"))?;
    let descriptor = format!(
        "<root><device><serviceList><service><serviceType>{SERVICE}</serviceType><controlURL>/control</controlURL></service></serviceList></device></root>"
    );
    let mut devices = upnp::descriptor(location, descriptor.as_bytes(), upnp::Limits::default())?;
    if devices.len() != 1 {
        return Err("fixture descriptor did not contain exactly one service".into());
    }
    Ok(devices.pop().ok_or(Fault::NotFound)?)
}
async fn request(stream: &mut TcpStream) -> io::Result<String> {
    let mut bytes = Vec::new();
    loop {
        let mut scratch = [0; 4096];
        let n = stream.read(&mut scratch).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete SOAP request",
            ));
        }
        bytes.extend_from_slice(&scratch[..n]);
        if bytes.len() > 65536 {
            return Err(io::Error::other("SOAP request exceeded fixture limit"));
        }
        if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&bytes[..end]).map_err(io::Error::other)?;
            let length = headers
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then_some(value.trim())
                })
                .map(str::parse::<usize>)
                .transpose()
                .map_err(io::Error::other)?;
            let length = match length {
                Some(length) => length,
                None if headers.starts_with("GET ") => 0,
                None => return Err(io::Error::other("missing SOAP request length")),
            };
            if bytes.len() >= end + 4 + length {
                return String::from_utf8(bytes).map_err(io::Error::other);
            }
        }
    }
}
fn field(request: &str, name: &str) -> io::Result<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    request
        .split_once(open.as_str())
        .and_then(|(_, tail)| tail.split_once(close.as_str()))
        .map(|(value, _)| value.to_string())
        .ok_or_else(|| io::Error::other("missing SOAP parameter"))
}
#[derive(Clone, Copy)]
enum Reply {
    Conflict,
    Lost,
    Added,
    External,
    Own,
    Foreign,
    Absent,
    Deleted,
}
async fn router(listener: TcpListener, replies: Vec<Reply>) -> io::Result<Vec<String>> {
    let mut requests = Vec::new();
    let mut ownership = None;
    for reply in replies {
        let (mut stream, _) = listener.accept().await?;
        let request = request(&mut stream).await?;
        if request.contains("<u:AddPortMapping ") {
            ownership = Some(field(&request, "NewPortMappingDescription")?);
        }
        requests.push(request);
        let (status, action, fields) = match reply {
            Reply::Lost => continue,
            Reply::Conflict | Reply::Absent => {
                let code = if matches!(reply, Reply::Conflict) {
                    718
                } else {
                    714
                };
                let body = format!(
                    "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><s:Fault><faultcode>s:Client</faultcode><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>{code}</errorCode><errorDescription>fixture refusal</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"
                );
                response(&mut stream, 500, &body).await?;
                continue;
            }
            Reply::Added => (200, "AddPortMapping", String::new()),
            Reply::External => (
                200,
                "GetExternalIPAddress",
                "<NewExternalIPAddress>203.0.113.1</NewExternalIPAddress>".to_string(),
            ),
            Reply::Own | Reply::Foreign => {
                let description = if matches!(reply, Reply::Own) {
                    ownership
                        .as_deref()
                        .ok_or_else(|| io::Error::other("query preceded Add"))?
                } else {
                    // Same tuple deliberately cannot authorize deleting another attempt.
                    "Another mapping owner"
                };
                (
                    200,
                    "GetSpecificPortMappingEntry",
                    format!(
                        "<NewInternalClient>{INTERNAL}</NewInternalClient><NewInternalPort>{PORT}</NewInternalPort><NewEnabled>1</NewEnabled><NewPortMappingDescription>{description}</NewPortMappingDescription>"
                    ),
                )
            }
            Reply::Deleted => (200, "DeletePortMapping", String::new()),
        };
        let body = format!(
            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:{action}Response xmlns:u=\"{SERVICE}\">{fields}</u:{action}Response></s:Body></s:Envelope>"
        );
        response(&mut stream, status, &body).await?;
    }
    Ok(requests)
}
async fn response(stream: &mut TcpStream, status: u16, body: &str) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status} fixture\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}
async fn drain(manager: &mut Manager, events: &mut Vec<Event>) -> Result<(), Failure> {
    while !manager.jobs.is_empty() || !manager.cleanup_queue.is_empty() {
        poll_fn(|cx| manager.poll(cx, &mut |event| events.push(event))).await?;
    }
    Ok(())
}
fn run(future: impl Future<Output = Result<(), Failure>>) -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async { tokio::time::timeout(Duration::from_secs(15), future).await? })
}
#[test]
fn explicit_conflict_does_not_queue_a_delete_of_the_existing_mapping() -> Result<(), Failure> {
    run(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let device = device(listener.local_addr()?)?;
        let router = tokio::spawn(router(listener, vec![Reply::Conflict]));
        let (mut manager, _, intent) = manager(device)?;
        manager.add(
            intent,
            Bounds::after(&*manager.clock, Duration::from_secs(5))?,
        )?;
        let mut events = Vec::new();
        drain(&mut manager, &mut events).await?;
        let requests = router.await??;
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("<u:AddPortMapping "));
        assert!(events.iter().any(|event| matches!(event, Event::Failed { error, .. } if matches!(error.downcast_ref::<upnp::Error>(), Some(upnp::Error::Soap { code: 718, .. })))));
        assert!(!events.iter().any(|event| matches!(
            event,
            Event::MappingUnknown { .. } | Event::MappingRemoved { .. }
        )));
        assert_eq!(manager.unresolved(), 0);
        assert_eq!(manager.pending(), 0);
        Ok(())
    })
}
#[test]
fn lost_add_response_does_not_delete_a_foreign_entry_with_the_same_tuple() -> Result<(), Failure> {
    run(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let device = device(listener.local_addr()?)?;
        let router = tokio::spawn(router(listener, vec![Reply::Lost, Reply::Foreign]));
        let (mut manager, _, intent) = manager(device)?;
        manager.add(
            intent,
            Bounds::after(&*manager.clock, Duration::from_secs(5))?,
        )?;
        let mut events = Vec::new();
        drain(&mut manager, &mut events).await?;
        let requests = router.await??;
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("<u:GetSpecificPortMappingEntry "));
        assert!(
            !requests
                .iter()
                .any(|request| request.contains("<u:DeletePortMapping "))
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::Failed { .. }))
                .count(),
            1
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::MappingRemoved { .. }))
        );
        assert_eq!(manager.unresolved(), 1);
        assert_eq!(manager.pending(), 0);
        Ok(())
    })
}
#[test]
fn uncertain_add_cleans_only_its_actual_echoed_attempt_and_keeps_original_failure()
-> Result<(), Failure> {
    run(async {
        for absent_after_owned in [false, true] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let device = device(listener.local_addr()?)?;
            let router = tokio::spawn(router(
                listener,
                vec![
                    Reply::Lost,
                    Reply::Own,
                    if absent_after_owned {
                        Reply::Absent
                    } else {
                        Reply::Deleted
                    },
                ],
            ));
            let (mut manager, _, intent) = manager(device)?;
            manager.add(
                intent,
                Bounds::after(&*manager.clock, Duration::from_secs(5))?,
            )?;
            let mut events = Vec::new();
            drain(&mut manager, &mut events).await?;
            let requests = router.await??;
            assert_eq!(requests.len(), 3);
            assert!(requests[1].contains("<u:GetSpecificPortMappingEntry "));
            assert!(requests[2].contains("<u:DeletePortMapping "));
            let marker = field(&requests[0], "NewPortMappingDescription")?;
            assert_eq!(marker.len(), 39);
            assert!(marker.starts_with("GNUnet "));
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(event, Event::Failed { .. }))
                    .count(),
                1
            );
            assert!(
                events
                    .iter()
                    .any(|event| matches!(event, Event::MappingUnknown { .. }))
            );
            assert!(
                events
                    .iter()
                    .any(|event| matches!(event, Event::MappingRemoved { .. }))
            );
            assert_eq!(manager.unresolved(), 0);
            assert_eq!(manager.pending(), 0);
        }
        Ok(())
    })
}
#[test]
fn confirmed_mapping_retirement_verifies_ownership_and_handles_observed_absence()
-> Result<(), Failure> {
    run(async {
        for absent in [false, true] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let device = device(listener.local_addr()?)?;
            let replies = if absent {
                vec![Reply::Added, Reply::External, Reply::Absent]
            } else {
                vec![Reply::Added, Reply::External, Reply::Own, Reply::Deleted]
            };
            let router = tokio::spawn(router(listener, replies));
            let (mut manager, source, intent) = manager(device)?;
            manager.add(
                intent,
                Bounds::after(&*manager.clock, Duration::from_secs(5))?,
            )?;
            let mut events = Vec::new();
            drain(&mut manager, &mut events).await?;
            assert_eq!(manager.leases.len(), 1);
            manager.source_stopped(source, &mut |event| events.push(event))?;
            drain(&mut manager, &mut events).await?;
            let requests = router.await??;
            assert!(requests[2].contains("<u:GetSpecificPortMappingEntry "));
            assert_eq!(
                requests
                    .iter()
                    .filter(|request| request.contains("<u:DeletePortMapping "))
                    .count(),
                usize::from(!absent)
            );
            assert!(
                !events.iter().any(|event| matches!(
                    event,
                    Event::Failed { .. } | Event::MappingUnknown { .. }
                ))
            );
            assert!(
                events
                    .iter()
                    .any(|event| matches!(event, Event::MappingRemoved { .. }))
            );
            assert_eq!(manager.unresolved(), 0);
            assert_eq!(manager.pending(), 0);
        }
        Ok(())
    })
}
#[test]
fn absence_while_the_original_add_is_still_processing_does_not_settle_unknown()
-> Result<(), Failure> {
    run(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let device = device(listener.local_addr()?)?;
        let router = tokio::spawn(async move {
            let (mut add, _) = listener.accept().await?;
            let add_request = request(&mut add).await?;
            let marker = field(&add_request, "NewPortMappingDescription")?;
            // Keep the original request's server connection and work alive
            // beyond the caller's original bound. The cleanup probe can arrive
            // on its separate connection before that Add has been applied.
            let (mut probe, _) = listener.accept().await?;
            let probe_request = request(&mut probe).await?;
            let absent = "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><s:Fault><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>714</errorCode><errorDescription>NoSuchEntryInArray</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>";
            response(&mut probe, 500, absent).await?;
            // Model the router finishing the already received Add after its
            // absent response. A late write is recorded only as native IO: the
            // caller has already retired this original request, so no success
            // receipt is inferred from this server-side response attempt.
            let added = format!(
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:AddPortMappingResponse xmlns:u=\"{SERVICE}\"/></s:Body></s:Envelope>"
            );
            let late_response = response(&mut add, 200, &added).await;
            Ok::<_, io::Error>((add_request, probe_request, marker, late_response))
        });
        let (mut manager, _, intent) = manager(device)?;
        manager.add(
            intent,
            Bounds::after(&*manager.clock, Duration::from_millis(500))?,
        )?;
        let mut events = Vec::new();
        drain(&mut manager, &mut events).await?;
        let (add, probe, marker, _late_response) = router.await??;
        assert!(add.contains("<u:AddPortMapping "));
        assert!(probe.contains("<u:GetSpecificPortMappingEntry "));
        assert_eq!(marker.len(), 39);
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::Failed { .. }))
                .count(),
            1
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Event::MappingRemoved { .. }))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Event::MappingUnknown { .. }))
        );
        assert_eq!(manager.pending(), 0);
        assert_eq!(manager.unresolved(), 1);
        Ok(())
    })
}
#[test]
fn fully_received_add_and_delete_facts_survive_an_independent_post_response_clock_failure()
-> Result<(), Failure> {
    run(async {
        for rejected in [false, true] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let device = device(listener.local_addr()?)?;
            let router = tokio::spawn(router(
                listener,
                vec![if rejected {
                    Reply::Conflict
                } else {
                    Reply::Added
                }],
            ));
            let (mut manager, _, intent) = manager_with_clock(device, Arc::new(PostResponseClock))?;
            manager.add(
                intent,
                Bounds::after(&*manager.clock, Duration::from_secs(5))?,
            )?;
            let attempt = match &manager.jobs.first().ok_or("missing real Add job")?.kind {
                Kind::Add { attempt, .. } => attempt.clone(),
                _ => return Err("unexpected job kind".into()),
            };
            let _watch = watch(WatchedResponse::Add(attempt.clone()));
            let mut events = Vec::new();
            let error = drain(&mut manager, &mut events)
                .await
                .err()
                .ok_or("post-response clock refusal was ignored")?;
            assert_eq!(error.downcast_ref::<Fault>(), Some(&Fault::TimeUncertain));
            let requests = router.await??;
            assert_eq!(requests.len(), 1);
            let (result, cause) = events
                .iter()
                .find_map(|event| match event {
                    Event::Failed { error, .. } => match error.downcast_ref::<upnp::Error>() {
                        Some(upnp::Error::PostResponse { result, cause }) => Some((result, cause)),
                        _ => None,
                    },
                    _ => None,
                })
                .ok_or("complete SOAP facts or the independent clock cause were discarded")?;
            assert!(matches!(cause, Error::Clock(Fault::TimeUncertain)));
            if rejected {
                assert!(
                    matches!(result, Err(error) if matches!(error.as_ref(), upnp::Error::Soap { code: 718, .. }))
                );
            } else {
                assert!(result.is_ok());
            }
            assert_eq!(
                attempt.outcome(),
                if rejected {
                    upnp::AddOutcome::KnownRejected
                } else {
                    upnp::AddOutcome::Committed
                }
            );
            assert_eq!(manager.unresolved(), usize::from(!rejected));
            assert_eq!(manager.pending(), 0);
            assert_eq!(
                events
                    .iter()
                    .any(|event| matches!(event, Event::MappingUnknown { .. })),
                !rejected
            );
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let device = device(listener.local_addr()?)?;
        let router = tokio::spawn(router(
            listener,
            vec![Reply::Added, Reply::External, Reply::Own, Reply::Deleted],
        ));
        let (mut manager, source, intent) =
            manager_with_clock(device, Arc::new(PostResponseClock))?;
        manager.add(
            intent,
            Bounds::after(&*manager.clock, Duration::from_secs(5))?,
        )?;
        let mut events = Vec::new();
        drain(&mut manager, &mut events).await?;
        manager.source_stopped(source, &mut |event| events.push(event))?;
        // This turn admits only the already queued cleanup future. Record its
        // actual shared observation owner before allowing that future to run.
        poll_fn(|cx| manager.poll(cx, &mut |event| events.push(event))).await?;
        let attempt = match &manager.jobs.first().ok_or("missing real cleanup job")?.kind {
            Kind::Delete { attempt, .. } => attempt.clone(),
            _ => return Err("unexpected cleanup job kind".into()),
        };
        let _watch = watch(WatchedResponse::Delete(attempt.clone()));
        drain(&mut manager, &mut events).await?;
        let requests = router.await??;
        assert_eq!(requests.len(), 4);
        assert!(requests[3].contains("<u:DeletePortMapping "));
        assert_eq!(attempt.removal(), Some(upnp::Removal::Removed));
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Event::MappingRemoved { .. }))
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::MappingUnknown { .. }))
        );
        assert!(events.iter().any(|event| matches!(event, Event::Failed { error, .. }
            if matches!(error.downcast_ref::<upnp::Error>(), Some(upnp::Error::PostResponse { result: Ok(()), cause: Error::Clock(Fault::TimeUncertain) }))
        )));
        manager.abort(&mut |event| events.push(event));
        assert_eq!(manager.unresolved(), 0);
        assert_eq!(manager.pending(), 0);
        Ok(())
    })
}
