//! Source-bound native-driver observer for unchanged normal C CORE IPC profiles.
use gnunet_core_client_host::{
    ClassOrder, Client, Direction, EndpointSource, Inbound, Instance, Limits, Message, Monitor,
    MonitorEvent, MonitorProgress, OwnedTraffic, Progress, SendOutcome,
};
use gnunet_wire::official::core::{FULL_OUTBOUND, HEADER_INBOUND, HEADER_OUTBOUND};
use std::{
    error::Error,
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};
use tokio::time::Instant;
type Failure = Box<dyn Error + Send + Sync>;
const MSG: [u8; 8] = [0, 8, 0, 0, 0, 0, 0, 1];
async fn app(path: PathBuf, mode: &str) -> Result<(), Failure> {
    let headers = mode == "probe-headers";
    let options = if headers {
        HEADER_INBOUND | HEADER_OUTBOUND
    } else if mode == "probe-outbound" {
        FULL_OUTBOUND
    } else {
        0
    };
    let types = if headers { &[1][..] } else { &[0][..] };
    let rounds = if mode == "probe-reconnect" { 2 } else { 1 };
    let mut instance = Instance::new();
    let mut client = Client::<8, 4>::new(
        &mut instance,
        EndpointSource::unix(path),
        ClassOrder::Little,
        options,
        types,
        Limits {
            sends: 4,
            io_slice_bytes: 3,
            ..Limits::default()
        },
    )?;
    let mut ready = 0;
    let mut sent = 0;
    let mut received = 0;
    let mut outbound = 0;
    let mut inbound_header = 0;
    let mut outbound_header = 0;
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut epoch = None;
    for round in 0..rounds {
        let local = loop {
            match client.drive(Some(deadline)).await? {
                Progress::Inbound {
                    epoch: current,
                    event: Inbound::Ready { local, .. },
                } => {
                    if epoch == Some(current) {
                        return Err("reused epoch".into());
                    }
                    epoch = Some(current);
                    ready += 1;
                    break local;
                }
                Progress::Connected(_) | Progress::Activity { .. } | Progress::PeerLost { .. } => {}
                _ => return Err("native init failed".into()),
            }
        };
        let source = Message::copy_from(&MSG)?;
        let pointer = source.as_ref().as_ptr();
        let operation = client
            .send(local, 0, u64::MAX, source)
            .map_err(|r| r.reason)?;
        loop {
            match client.drive(Some(deadline)).await? {
                Progress::Finished {
                    send, completion, ..
                } => {
                    if send != operation
                        || completion.outcome != SendOutcome::Written
                        || completion.source.as_ref() != MSG
                        || completion.source.as_ref().as_ptr() != pointer
                    {
                        return Err("wrong original completion".into());
                    }
                    sent += 1;
                }
                Progress::Inbound {
                    event:
                        Inbound::Traffic {
                            peer,
                            connection,
                            direction,
                            traffic,
                        },
                    ..
                } => {
                    if peer != local.identity() || connection != Some(local) {
                        return Err("traffic peer authority".into());
                    }
                    match (direction, traffic) {
                        (Direction::Inbound, OwnedTraffic::Full(bytes)) => {
                            if bytes.as_ref() != MSG {
                                return Err("inbound bytes".into());
                            }
                            received += 1;
                        }
                        (Direction::Outbound, OwnedTraffic::Full(bytes)) => {
                            if bytes.as_ref() != MSG {
                                return Err("outbound bytes".into());
                            }
                            outbound += 1;
                        }
                        (Direction::Inbound, OwnedTraffic::Header(_)) => inbound_header += 1,
                        (Direction::Outbound, OwnedTraffic::Header(_)) => outbound_header += 1,
                    }
                }
                Progress::Activity { .. }
                | Progress::Inbound {
                    event: Inbound::SendReady { .. } | Inbound::IgnoredSelfNotification,
                    ..
                } => {}
                _ => return Err("native application failed".into()),
            }
            let expected = round + 1;
            if sent == expected
                && if headers {
                    inbound_header == expected && outbound_header == expected
                } else {
                    received == expected && (options == 0 || outbound == expected)
                }
            {
                break;
            }
        }
        if round + 1 < rounds {
            let _retired = client.reconnect()?;
        }
    }
    let _closed = client.close()?;
    loop {
        if matches!(client.drive(None).await?, Progress::Closed) {
            break;
        }
    }
    let result = format!(
        "{{\"ready\":{ready},\"sent\":{sent},\"received\":{received},\"outbound\":{outbound},\"inbound_header\":{inbound_header},\"outbound_header\":{outbound_header}}}\n"
    );
    io::stdout().write_all(result.as_bytes())?;
    Ok(())
}
async fn monitor(path: PathBuf) -> Result<(), Failure> {
    let mut instance = Instance::new();
    let mut monitor = Monitor::new(
        &mut instance,
        EndpointSource::unix(path),
        Limits {
            io_slice_bytes: 3,
            ..Limits::default()
        },
    )?;
    let mut updates = 0;
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        match monitor.drive(Some(deadline)).await? {
            MonitorProgress::Inbound {
                event: MonitorEvent::SnapshotFinished,
                ..
            } => break,
            MonitorProgress::Inbound {
                event: MonitorEvent::Update { .. },
                ..
            } => updates += 1,
            MonitorProgress::Connected(_) | MonitorProgress::Activity { .. } => {}
            _ => return Err("native monitor failed".into()),
        }
    }
    let _closed = monitor.close()?;
    io::stdout().write_all(
        format!("{{\"monitor_request\":1,\"updates\":{updates},\"snapshot\":1}}\n").as_bytes(),
    )?;
    Ok(())
}
fn main() -> Result<(), Failure> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().ok_or("mode")?;
    let path = PathBuf::from(args.next().ok_or("socket path")?);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        if mode == "probe-monitor" {
            monitor(path).await
        } else {
            app(path, &mode).await
        }
    })
}
