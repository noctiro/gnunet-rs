//! Actual descriptor and read-only SOAP selection through the normal Manager.
//! Caller-supplied numeric loopback locations replace only LAN SSDP discovery.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

const IP2: &str = "urn:schemas-upnp-org:service:WANIPConnection:2";
const PPP: &str = "urn:schemas-upnp-org:service:WANPPPConnection:1";
enum Answer {
    Description(String),
    Soap {
        service: &'static str,
        action: &'static str,
        fields: String,
    },
    Fault(u16),
    Lost,
    StopClock(Arc<AtomicBool>),
    Own,
    Foreign,
}
struct Exchange {
    path: &'static str,
    method: &'static str,
    answer: Answer,
}
fn description(services: &[(&str, &str)]) -> String {
    let mut xml = String::from("<root><device><serviceList>");
    for (service, control) in services {
        xml.push_str(&format!("<service><serviceType>{service}</serviceType><controlURL>{control}</controlURL></service>"));
    }
    xml.push_str("</serviceList></device></root>");
    xml
}
fn soap(
    path: &'static str,
    service: &'static str,
    action: &'static str,
    fields: String,
) -> Exchange {
    Exchange {
        path,
        method: "POST",
        answer: Answer::Soap {
            service,
            action,
            fields,
        },
    }
}
fn status(path: &'static str, service: &'static str, value: &str) -> Exchange {
    soap(
        path,
        service,
        "GetStatusInfo",
        format!(
            "<NewConnectionStatus>{value}</NewConnectionStatus><NewLastConnectionError>ERROR_NONE</NewLastConnectionError><NewUptime>1</NewUptime>"
        ),
    )
}
fn external(path: &'static str, service: &'static str, ip: &str) -> Exchange {
    soap(
        path,
        service,
        "GetExternalIPAddress",
        format!("<NewExternalIPAddress>{ip}</NewExternalIPAddress>"),
    )
}
async fn selected_router(
    listener: TcpListener,
    exchanges: Vec<Exchange>,
) -> io::Result<Vec<String>> {
    let mut requests = Vec::new();
    let mut ownership = None;
    for exchange in exchanges {
        let (mut stream, _) = listener.accept().await?;
        let request = request(&mut stream).await?;
        let start = format!("{} {} HTTP/1.1\r\n", exchange.method, exchange.path);
        if !request.starts_with(start.as_str()) {
            return Err(io::Error::other(
                "selection dispatched to an unexpected candidate",
            ));
        }
        if request.contains("<u:AddPortMapping ") {
            ownership = Some(field(&request, "NewPortMappingDescription")?);
        }
        let reply = |service, action, fields: String| {
            format!(
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:{action}Response xmlns:u=\"{service}\">{fields}</u:{action}Response></s:Body></s:Envelope>"
            )
        };
        let (code, body) = match exchange.answer {
            Answer::Description(body) => (200, body),
            Answer::Soap {
                service,
                action,
                fields,
            } => {
                let opening = format!("<u:{action} ");
                if !request.contains(opening.as_str()) {
                    return Err(io::Error::other("unexpected SOAP operation in selection"));
                }
                (200, reply(service, action, fields))
            }
            Answer::Fault(code) => (
                500,
                format!(
                    "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><s:Fault><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>{code}</errorCode><errorDescription>explicit fixture refusal</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"
                ),
            ),
            Answer::Lost => {
                requests.push(request);
                continue;
            }
            answer @ (Answer::Own | Answer::Foreign) => {
                let marker = if matches!(answer, Answer::Own) {
                    ownership
                        .as_deref()
                        .ok_or_else(|| io::Error::other("ownership probe preceded Add"))?
                } else {
                    "Other owner"
                };
                (
                    200,
                    reply(
                        SERVICE,
                        "GetSpecificPortMappingEntry",
                        format!(
                            "<NewInternalClient>{INTERNAL}</NewInternalClient><NewInternalPort>{PORT}</NewInternalPort><NewEnabled>1</NewEnabled><NewPortMappingDescription>{marker}</NewPortMappingDescription>"
                        ),
                    ),
                )
            }
            Answer::StopClock(flag) => {
                flag.store(true, Ordering::SeqCst);
                let body = reply(
                    SERVICE,
                    "GetStatusInfo",
                    "<NewConnectionStatus>Connected</NewConnectionStatus>".to_string(),
                );
                // The original caller may close immediately after its actual
                // source refusal; a server write here is never a client receipt.
                let _late_write = response(&mut stream, 200, &body).await;
                requests.push(request);
                continue;
            }
        };
        response(&mut stream, code, &body).await?;
        requests.push(request);
    }
    Ok(requests)
}
fn start(
    manager: &mut Manager,
    intent: Intent,
    locations: Vec<crate::http::Url>,
    bounds: Bounds,
) -> Result<(), Failure> {
    let observations = upnp::ReadObservations::new(upnp::Limits::default())?;
    let progress = observations.clone();
    let mut gate = Gate::new(manager.clock.clone(), bounds)?;
    let resolver = manager.resolver.clone();
    let future = Box::pin(async move {
        Ok(Output::Selected(Box::new(
            upnp::select_from_locations(&resolver, &mut gate, locations, progress).await?,
        )))
    });
    manager.admit(
        Kind::Discover {
            source: intent.source,
            provider: intent.provider,
            internal: intent.internal,
            port: intent.port,
            protocol: intent.protocol,
            observations,
        },
        bounds,
        future,
    )?;
    Ok(())
}
fn locations(address: SocketAddr, paths: &[&str]) -> Result<Vec<crate::http::Url>, Failure> {
    paths
        .iter()
        .map(|path| crate::http::Url::parse(&format!("http://{address}{path}")).map_err(Into::into))
        .collect()
}
fn actual_606(events: &[Event]) -> usize {
    events.iter().filter(|event| matches!(event, Event::Failed { error, .. }
        if error.downcast_ref::<upnp::ReadFailure>().is_some_and(|failure| matches!(failure.error.as_ref(), upnp::Error::Soap { code: 606, .. }))
    )).count()
}
#[test]
fn multiple_services_and_devices_choose_connected_public_before_one_exposed_add()
-> Result<(), Failure> {
    run(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let router = tokio::spawn(selected_router(
            listener,
            vec![
                Exchange {
                    path: "/first.xml",
                    method: "GET",
                    answer: Answer::Description(description(&[
                        (IP2, "/denied"),
                        (SERVICE, "/off"),
                        (PPP, "/ppp"),
                    ])),
                },
                Exchange {
                    path: "/second.xml",
                    method: "GET",
                    answer: Answer::Description(description(&[(SERVICE, "/public")])),
                },
                Exchange {
                    path: "/denied",
                    method: "POST",
                    answer: Answer::Fault(606),
                },
                status("/off", SERVICE, "Disconnected"),
                status("/ppp", PPP, "Up"),
                external("/ppp", PPP, "100.64.1.2"),
                status("/public", SERVICE, "Connected"),
                external("/public", SERVICE, "8.8.8.8"),
                Exchange {
                    path: "/public",
                    method: "POST",
                    answer: Answer::Lost,
                },
                Exchange {
                    path: "/public",
                    method: "POST",
                    answer: Answer::Foreign,
                },
            ],
        ));
        let (mut manager, _, intent) = manager(device(address)?)?;
        let bounds = Bounds::after(&*manager.clock, Duration::from_secs(5))?;
        start(
            &mut manager,
            intent,
            locations(address, &["/first.xml", "/second.xml"])?,
            bounds,
        )?;
        let mut events = Vec::new();
        drain(&mut manager, &mut events).await?;
        let requests = router.await??;
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.contains("<u:AddPortMapping "))
                .count(),
            1
        );
        assert!(requests[8].starts_with("POST /public "));
        assert!(requests[9].contains("<u:GetSpecificPortMappingEntry "));
        assert_eq!(actual_606(&events), 1);
        assert_eq!(manager.unresolved(), 1);
        assert_eq!(manager.pending(), 0);
        manager.abort(&mut |event| events.push(event));
        assert_eq!(actual_606(&events), 1);
        Ok(())
    })
}
#[test]
fn connected_fallback_keeps_external_read_error_and_announces_cgnat_as_lan() -> Result<(), Failure>
{
    run(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let router = tokio::spawn(selected_router(
            listener,
            vec![
                Exchange {
                    path: "/gateway.xml",
                    method: "GET",
                    answer: Answer::Description(description(&[(SERVICE, "/mapping")])),
                },
                status("/mapping", SERVICE, "Connected"),
                Exchange {
                    path: "/mapping",
                    method: "POST",
                    answer: Answer::Fault(606),
                },
                soap("/mapping", SERVICE, "AddPortMapping", String::new()),
                external("/mapping", SERVICE, "100.64.1.2"),
                Exchange {
                    path: "/mapping",
                    method: "POST",
                    answer: Answer::Own,
                },
                soap("/mapping", SERVICE, "DeletePortMapping", String::new()),
            ],
        ));
        let (mut manager, source, intent) = manager(device(address)?)?;
        let bounds = Bounds::after(&*manager.clock, Duration::from_secs(5))?;
        start(
            &mut manager,
            intent,
            locations(address, &["/gateway.xml"])?,
            bounds,
        )?;
        let mut events = Vec::new();
        drain(&mut manager, &mut events).await?;
        assert_eq!(actual_606(&events), 1);
        assert_eq!(
            manager
                .core
                .registration(source)?
                .ok_or(Fault::NotReady)?
                .advertised,
            &[Advertised {
                address: SocketAddress::V4 {
                    ip: [100, 64, 1, 2],
                    port: PORT
                },
                class: AddressClass::LAN
            }]
        );
        manager.source_stopped(source, &mut |event| events.push(event))?;
        drain(&mut manager, &mut events).await?;
        let requests = router.await??;
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.contains("<u:AddPortMapping "))
                .count(),
            1
        );
        assert_eq!(manager.pending(), 0);
        assert_eq!(manager.unresolved(), 0);
        Ok(())
    })
}
struct RefusingClock(Arc<AtomicBool>);
impl RuntimeClock for RefusingClock {
    fn sample(&self) -> Result<clock::ClockSample, Fault> {
        if self.0.load(Ordering::SeqCst) {
            Err(Fault::TimeUncertain)
        } else {
            SystemClock.sample()
        }
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Fault> {
        SystemClock.subscribe()
    }
}
#[test]
fn source_refusal_aborts_candidate_io_and_preserves_earlier_read_error_once() -> Result<(), Failure>
{
    run(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let refused = Arc::new(AtomicBool::new(false));
        let router = tokio::spawn(selected_router(
            listener,
            vec![
                Exchange {
                    path: "/gateway.xml",
                    method: "GET",
                    answer: Answer::Description(description(&[
                        (SERVICE, "/denied"),
                        (SERVICE, "/current"),
                        (PPP, "/later"),
                    ])),
                },
                Exchange {
                    path: "/denied",
                    method: "POST",
                    answer: Answer::Fault(606),
                },
                Exchange {
                    path: "/current",
                    method: "POST",
                    answer: Answer::StopClock(refused.clone()),
                },
            ],
        ));
        let (mut manager, _, intent) =
            manager_with_clock(device(address)?, Arc::new(RefusingClock(refused)))?;
        let bounds = Bounds::after(&*manager.clock, Duration::from_secs(5))?;
        start(
            &mut manager,
            intent,
            locations(address, &["/gateway.xml"])?,
            bounds,
        )?;
        let mut events = Vec::new();
        let _source_failure = drain(&mut manager, &mut events)
            .await
            .err()
            .ok_or("source refusal was ignored")?;
        manager.abort(&mut |event| events.push(event));
        let requests = router.await??;
        assert_eq!(requests.len(), 3);
        assert!(
            !requests
                .iter()
                .any(|request| request.contains("<u:AddPortMapping ")
                    || request.starts_with("POST /later "))
        );
        assert_eq!(actual_606(&events), 1);
        assert_eq!(manager.pending(), 0);
        manager.abort(&mut |event| events.push(event));
        assert_eq!(actual_606(&events), 1);
        Ok(())
    })
}
