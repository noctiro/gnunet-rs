use super::*;

#[tokio::test(flavor = "current_thread")]
async fn queued_early_exit_prevents_publication() -> Result<(), Box<dyn Error>> {
    let (phase, _) = watch::channel(Phase::Foundation);
    let (send, events) = mpsc::channel(EVENT_CAPACITY);
    let peer = [1; 32];
    for ready in [
        ReadyNotice::Resolver,
        ReadyNotice::Pils(peer),
        ReadyNotice::Transport(peer),
        ReadyNotice::Nat,
        ReadyNotice::Core(peer),
        ReadyNotice::Nse(peer),
        ReadyNotice::Dht(peer),
        ReadyNotice::Tcp {
            peer,
            endpoints: Vec::new(),
        },
        ReadyNotice::Udp {
            peer,
            endpoints: Vec::new(),
        },
        ReadyNotice::Cadet(peer),
    ] {
        send.try_send(Notice::Ready(ready))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
    }
    for service in SERVICES.into_iter().filter(|service| {
        !matches!(
            service,
            Service::Quic | Service::Http3 | Service::Unix | Service::Regex | Service::Vpn
        )
    }) {
        let result = if service == Service::Cadet {
            ChildExit::Finished {
                result: Ok(()),
                stopping: false,
            }
        } else {
            ChildExit::Skipped
        };
        send.try_send(Notice::Exited { service, result })
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
    }

    let published = Cell::new(false);
    let result = supervise(
        phase,
        events,
        Instant::now() + std::time::Duration::from_secs(1),
        OptionalServices {
            udp: true,
            regex: false,
            vpn: false,
            quic: false,
            http3: false,
            unix: false,
        },
        std::future::pending(),
        |_| {
            published.set(true);
            Ok(())
        },
    )
    .await;
    if !published.get()
        && matches!(
            result,
            Err(Failure {
                cause: FailureCause::Service(ServiceFailure {
                    service: Service::Cadet,
                    ..
                }),
                ..
            })
        )
    {
        return Ok(());
    }
    Err(format!("queued service exit lost startup failure: {result:?}").into())
}
