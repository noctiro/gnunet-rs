//! Compare this native Rust client with an independently started official DHT.

use gnunet_dht_client_host::{
    Action, Client, EndpointSource, Event, Get, Instance, Limits, LossCause, Monitor, MonitorKind,
    Outcome, Progress, ipc,
};
use gnunet_wire::official::AbsoluteTime;
use std::{
    error::Error,
    io::Write,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;
fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: normal_dht UNIXPATH")?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(run(path.into()))
}
async fn run(path: std::path::PathBuf) -> Result<(), Box<dyn Error>> {
    let mut instance = Instance::new();
    let mut client = Client::new(
        &mut instance,
        EndpointSource::unix(path),
        Limits {
            io_slice_bytes: 1,
            ..Limits::default()
        },
    )?;
    let key = [44; 64];
    let query = client.get(Get {
        key: &key,
        block_type: 8,
        options: 0,
        replication: 1,
        extended_query: &[],
    })?;
    client.known(query, &[gnunet_crypto::hash512(b"unseen prefilter")])?;
    let monitor = client.monitor(Monitor {
        block_type: 0,
        get: 1,
        result: 1,
        put: 1,
        key: None,
    })?;
    let hello = client.hello()?;
    let deadline = Instant::now() + Duration::from_secs(12);
    let (
        mut result,
        mut put_written,
        mut hello_seen,
        mut monitor_get,
        mut monitor_put,
        mut offer_written,
    ) = (false, false, false, false, false, false);
    let (mut put_operation, mut offer_operation) = (None, None);
    loop {
        match client.drive(Some(deadline)).await? {
            Progress::Connected(epoch) => {
                writeln!(std::io::stdout(), "RUST_CONNECTED {}", epoch.diagnostic())?;
                assert_eq!(client.request_id(query)?.0, [0; 8]);
                assert!(put_operation.is_none());
                put_operation = Some(client.put(ipc::Put {
                    block_type: 8,
                    options: 0,
                    replication: 1,
                    expiration: AbsoluteTime::NEVER,
                    key: &[45; 64],
                    payload: b"native Rust PUT",
                })?);
            }
            Progress::Completed(n) if Some(n.operation) == put_operation => {
                assert_eq!(n.outcome, Outcome::Written);
                put_written = true;
                writeln!(std::io::stdout(), "RUST_PUT_LOCAL_WRITTEN")?;
            }
            Progress::Completed(n) if Some(n.operation) == offer_operation => {
                assert_eq!(n.outcome, Outcome::Written);
                offer_written = true;
                writeln!(
                    std::io::stdout(),
                    "RUST_HELLO_OFFER_LOCAL_WRITTEN coverage=MetadataOnly"
                )?;
            }
            Progress::Written {
                action: Action::Known { .. },
                ..
            } => writeln!(std::io::stdout(), "RUST_KNOWN_LOCAL_WRITTEN")?,
            Progress::Inbound(received) => match received.event() {
                Event::Result {
                    get,
                    duplicate,
                    remembered,
                } => {
                    assert_eq!(*get, query);
                    let answer = received.result()?;
                    assert_eq!(answer.key, &key);
                    assert_eq!(answer.block_type, 8);
                    assert_eq!(answer.id.0, [0; 8]);
                    assert_eq!(answer.payload, b"public C API PUT");
                    result = true;
                    writeln!(
                        std::io::stdout(),
                        "RUST_RESULT key=44 id=0000000000000000 duplicate={duplicate} remembered={remembered}"
                    )?;
                }
                Event::Hello { requests } => {
                    assert_eq!(requests, &vec![hello]);
                    let url = received
                        .hello_url()?
                        .ok_or("profile requires an actual HELLO URL")?;
                    let mut address_storage = [0; 8192];
                    let parsed = gnunet_hello::Hello::parse_url(
                        url,
                        &mut address_storage,
                        gnunet_hello::Limits {
                            maximum_input_bytes: 65535,
                            maximum_address_bytes: 8192,
                            maximum_addresses: 128,
                        },
                    )?;
                    let expected = [
                        0xc4, 0x28, 0x4f, 0xfe, 0xb1, 0x1b, 0xaf, 0x71, 0x3a, 0xe3, 0xe3, 0x6d,
                        0x04, 0xca, 0x58, 0x3b, 0x6a, 0x86, 0x7e, 0x45, 0x4d, 0xaf, 0x64, 0x53,
                        0xab, 0x20, 0x69, 0x16, 0x79, 0xcf, 0xf6, 0x15,
                    ];
                    assert_eq!(parsed.peer().as_bytes(), &expected);
                    writeln!(
                        std::io::stdout(),
                        "RUST_ACTUAL_HELLO_PID c4284ffeb11baf713ae3e36d04ca583b6a867e454daf6453ab20691679cff615"
                    )?;
                    let micros =
                        u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros())?;
                    let (operation, coverage) =
                        client.offer_hello(url, AbsoluteTime::from_micros(micros))?;
                    assert_eq!(coverage, gnunet_hello::SignatureCoverage::MetadataOnly);
                    offer_operation = Some(operation);
                    hello_seen = true;
                    writeln!(
                        std::io::stdout(),
                        "RUST_HELLO present=true signature=MetadataOnly"
                    )?;
                }
                Event::Monitor { kind, monitors } => {
                    assert_eq!(monitors, &vec![monitor]);
                    match kind {
                        MonitorKind::Get => monitor_get = true,
                        MonitorKind::Put => monitor_put = true,
                        MonitorKind::Result => {}
                    }
                    writeln!(std::io::stdout(), "RUST_MONITOR {kind:?}")?;
                }
                Event::Ignored(reason) => writeln!(std::io::stdout(), "RUST_IGNORED {reason:?}")?,
            },
            Progress::Activity { .. } | Progress::Written { .. } => {}
            Progress::WaitDeadline => return Err("DHT observation deadline".into()),
            Progress::Lost { cause, .. } => {
                return Err(format!("actual DHT MQ loss: {cause:?}").into());
            }
            _ => return Err("unexpected DHT drive state".into()),
        }
        if result && put_written && hello_seen && monitor_get && monitor_put && offer_written {
            break;
        }
    }
    let old = client.epoch().ok_or("old epoch missing")?;
    assert!(
        matches!(client.reconnect()?,Progress::Lost{epoch,cause:LossCause::Requested,..}if epoch==old)
    );
    let hello_again = client.hello()?;
    let (mut fresh, mut got_get, mut got_known, mut got_monitor, mut got_hello) =
        (None, false, false, false, false);
    while !(got_get && got_known && got_monitor && got_hello) {
        match client.drive(Some(deadline)).await? {
            Progress::Connected(epoch) => {
                assert_ne!(old, epoch);
                fresh = Some(epoch);
                writeln!(std::io::stdout(), "RUST_RECONNECTED {}", epoch.diagnostic())?;
            }
            Progress::Written { epoch, action } => {
                assert_eq!(Some(epoch), fresh);
                match action {
                    Action::Get(id) => {
                        assert_eq!(id, query);
                        got_get = true
                    }
                    Action::Known { get, count } => {
                        assert_eq!(get, query);
                        assert_eq!(count, 2);
                        got_known = true
                    }
                    Action::MonitorStart(id) => {
                        assert_eq!(id, monitor);
                        got_monitor = true
                    }
                    Action::Hello(id) => assert_eq!(id, hello_again),
                    _ => return Err("one-shot replayed on replacement MQ".into()),
                }
            }
            Progress::Inbound(received) => {
                assert_eq!(Some(received.epoch()), fresh);
                match received.event() {
                    Event::Hello { requests } => {
                        assert_eq!(requests, &vec![hello_again]);
                        assert!(received.hello_url()?.is_some());
                        got_hello = true
                    }
                    Event::Result { get, duplicate, .. } => {
                        assert_eq!(*get, query);
                        assert!(*duplicate);
                        assert_eq!(received.result()?.payload, b"public C API PUT");
                        writeln!(std::io::stdout(), "RUST_RESTORED_DUPLICATE_OBSERVED")?;
                    }
                    Event::Monitor { monitors, .. } => assert_eq!(monitors, &vec![monitor]),
                    Event::Ignored(_) => {}
                }
            }
            Progress::Activity { .. } => {}
            Progress::WaitDeadline => return Err("restoration deadline".into()),
            _ => return Err("actual replacement MQ failed".into()),
        }
    }
    client.stop(query)?;
    client.stop_monitor(monitor)?;
    let mut stops = 0;
    while stops < 2 {
        match client.drive(Some(deadline)).await? {
            Progress::Written {
                action: Action::Stop(_) | Action::MonitorStop(_),
                ..
            } => stops += 1,
            Progress::Activity { .. } | Progress::Inbound(_) => {}
            Progress::WaitDeadline => return Err("STOP deadline".into()),
            _ => return Err("STOP loss".into()),
        }
    }
    client.close();
    writeln!(
        std::io::stdout(),
        "RUST_SUCCESS local_IPC_only result=true put_local=true hello=true hello_offer_local=true monitor_get=true monitor_put=true restored_GET_known_monitor=true stop_local=true"
    )?;
    Ok(())
}
