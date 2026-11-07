//! Finite native UDP communicator session against actual normal C local services.
//! This is an owned one-peer observer, not a standalone complete Rust node.
#![expect(
    clippy::print_stdout,
    reason = "Finite observer emits only actual public identities and protocol/cleanup counters."
)]
use gnunet_crypto::Entropy;
use gnunet_pils::{
    HelloLimits, Profile,
    client::{Inbound, Instance},
};
use gnunet_pils_host::{
    client::{Client, EndpointSource, Limits, Progress},
    identity::load_existing,
};
use gnunet_types::Error;
use gnunet_udp_communicator_core::{PeerId, send::Mode};
use gnunet_udp_communicator_host::{
    driver::{Activity, Capacity, Configuration, Driver, Time},
    identity::IdentityEpoch,
    replay::Journal,
    socket::DatagramSocket,
    transport,
};
use gnunet_wire::official::AbsoluteTime;
use std::{
    future::{Future, poll_fn},
    path::PathBuf,
    pin::pin,
    task::Poll,
    time::Duration,
};
use tokio::{net::UnixStream, time::Instant};
struct Random;
impl Entropy for Random {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(bytes).map_err(|_| Error::Entropy)
    }
}
fn peer(text: &str) -> Result<PeerId, Error> {
    if text.len() != 64 || !text.is_ascii() {
        return Err(Error::InvalidInput);
    }
    let mut peer = [0; 32];
    for (index, byte) in peer.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| Error::InvalidInput)?;
    }
    Ok(peer)
}
fn hex(peer: PeerId) -> String {
    peer.iter().map(|byte| format!("{byte:02x}")).collect()
}
#[derive(Default)]
struct Counts {
    sent_initial: u64,
    sent_box: u64,
    sent_rekey: u64,
    received_initial: u64,
    received_box: u64,
    received_rekey: u64,
    discarded: u64,
    commands: u64,
    steps: u64,
    pils_updates: u64,
}
async fn run(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 8 {
        return Err("expected PILS TRANSPORT IKM STATE PEER UDP_ADDRESS READY STOP".into());
    }
    let source = EndpointSource::unix(PathBuf::from(&args[0]));
    let clock = source.clock();
    let mut instance = Instance::new();
    let mut pils = Client::<32>::new(
        &mut instance,
        source,
        Profile::Reference029,
        Limits {
            io_slice_bytes: 1024,
            ..Limits::default()
        },
        HelloLimits {
            maximum_input_bytes: 65535,
            maximum_address_bytes: 65535,
            maximum_addresses: 128,
        },
    )?;
    pils.enable_local_key(load_existing(&PathBuf::from(&args[2]))?)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while pils.identity().is_none() {
        match pils.drive(Some(deadline)).await? {
            Progress::Connected(_) | Progress::Activity { .. } => {}
            Progress::Inbound(Inbound::Identity { .. }) => {}
            _ => return Err("PILS failed before actual verified local identity".into()),
        }
    }
    let now = clock.sample()?.now.as_micros();
    let mut binding = IdentityEpoch::from_native(&pils, AbsoluteTime::from_micros(now))?;
    let local = binding.peer();
    let remote = peer(&args[4])?;
    let target = transport::parse_address(args[5].as_bytes())?;
    let socket = DatagramSocket::bind(
        if target.is_ipv4() {
            "127.0.0.1:0"
        } else {
            "[::1]:0"
        }
        .parse()?,
    )?;
    let configuration = Configuration {
        local,
        peer: remote,
        target,
        network: 1,
        capacity: Capacity::default(),
        transmit: socket.profile().sender_policy(),
    };
    let state = PathBuf::from(&args[3]);
    std::fs::create_dir(&state)?;
    let mut journal = Journal::open(&state, local, 64)?;
    let connection = gnunet_service_runtime::connection::Connection::from_unix(
        UnixStream::connect(&args[1]).await?,
    );
    let mut driver = Driver::new(connection, socket, configuration, now)?;
    std::fs::write(
        &args[6],
        format!("{}\n{}\n", driver.local_address().port(), hex(local)),
    )?;
    let stop = PathBuf::from(&args[7]);
    let end = Instant::now() + Duration::from_secs(40);
    let mut random = Random;
    let mut counts = Counts::default();
    let mut closing = false;
    loop {
        if !closing && stop.exists() {
            driver.finish()?;
            closing = true;
        }
        if driver.is_quiescent() {
            break;
        }
        if Instant::now() >= end {
            return Err("normal peer profile deadline".into());
        }
        let wait = Instant::now() + Duration::from_millis(25);
        let mut timer = pin!(tokio::time::sleep_until(wait));
        poll_fn(|cx| {
            // A cancelled PILS waiting future retains the actual original native owner.
            // Its mutable borrow ends before the current-key borrow at the UDP step.
            {
                let mut wait = pin!(pils.drive(None));
                if let Poll::Ready(result) = wait.as_mut().poll(cx) {
                    match result? {
                        Progress::Activity { .. } => return Poll::Ready(Ok(())),
                        Progress::Inbound(Inbound::Identity { .. }) => {
                            counts.pils_updates += 1;
                            return Poll::Ready(Ok(()));
                        }
                        _ => {
                            return Poll::Ready(Err::<(), Box<dyn std::error::Error>>(
                                "actual PILS owner changed/lost during direct profile".into(),
                            ));
                        }
                    }
                }
            }
            let sample = clock.sample()?;
            let time = Time {
                now: sample.now.as_micros(),
                utc: sample.now,
            };
            if let Poll::Ready(result) =
                driver.poll_bound(cx, &binding, &pils, &mut journal, time, &mut random)
            {
                match result? {
                    Activity::NativeSent {
                        mode: Mode::Initial,
                        ..
                    } => counts.sent_initial += 1,
                    Activity::NativeSent {
                        mode: Mode::Box { rekey, .. },
                        ..
                    } => {
                        counts.sent_box += 1;
                        counts.sent_rekey += u64::from(rekey);
                    }
                    Activity::Incoming { boxed, rekey, .. } => {
                        if boxed {
                            counts.received_box += 1;
                        } else {
                            counts.received_initial += 1;
                        }
                        counts.received_rekey += u64::from(rekey);
                    }
                    Activity::Discarded(_) => counts.discarded += 1,
                    Activity::Command => counts.commands += 1,
                    _ => {}
                }
                counts.steps += 1;
                return Poll::Ready(Ok(()));
            }
            if timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok(()));
            }
            Poll::Pending
        })
        .await?;
    }
    let quiescent = driver.is_quiescent() && journal.quiescent()?;
    binding.close();
    let retired = pils.close();
    if retired.into_iter().any(|operation| operation.is_some()) || pils.pending() != 0 {
        return Err("PILS retained logical operations during controlled close".into());
    }
    if !quiescent || counts.sent_initial == 0 || counts.received_initial == 0 {
        return Err("actual initial directions/owned teardown missing".into());
    }
    println!(
        "{{\"kind\":\"native-one-peer-UDP-normal-services\",\"status\":\"passed\",\"sent_initial\":{},\"sent_box\":{},\"sent_rekey\":{},\"received_initial\":{},\"received_box\":{},\"received_rekey\":{},\"discarded\":{},\"commands\":{},\"steps\":{},\"pils_updates_after_binding\":{},\"durable_commits\":{},\"quiescent\":{},\"full_UDP_or_Node_verified\":false}}",
        counts.sent_initial,
        counts.sent_box,
        counts.sent_rekey,
        counts.received_initial,
        counts.received_box,
        counts.received_rekey,
        counts.discarded,
        counts.commands,
        counts.steps,
        counts.pils_updates,
        journal.commits(),
        quiescent
    );
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect();
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?
        .block_on(run(args))
}
