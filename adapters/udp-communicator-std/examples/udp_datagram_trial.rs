//! Finite actual C/Rust loopback packet observer, not a communicator service.
#![expect(
    clippy::print_stdout,
    reason = "Finite public endpoint/packet count observations are the test harness output."
)]
use gnunet_crypto::Entropy;
use gnunet_types::Error;
use gnunet_udp_communicator_core::{
    Identity,
    receive::{Policy as RxPolicy, Receiver},
    send::{Policy as TxPolicy, Sender},
};
use gnunet_udp_communicator_host::{replay::Journal, socket::DatagramSocket};
use std::{io::Write as _, net::SocketAddr, path::Path, time::Duration};
struct Random;
impl Entropy for Random {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(output).map_err(|_| Error::Entropy)
    }
}
fn message(n: u32) -> [u8; 8] {
    let mut b = [0; 8];
    b[..2].copy_from_slice(&8u16.to_be_bytes());
    b[4..].copy_from_slice(&n.to_be_bytes());
    b
}
async fn run(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 4 {
        return Err(
            "receive FAMILY NEW_JOURNAL NEW_CAPTURE or send FAMILY NEW_JOURNAL PORT".into(),
        );
    }
    let family = args[1].as_str();
    let bind: SocketAddr = match family {
        "4" => "127.0.0.1:0",
        "6" => "[::1]:0",
        _ => return Err("family4/6".into()),
    }
    .parse()?;
    let mut socket = DatagramSocket::bind(bind)?;
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    std::fs::create_dir(&args[2])?;
    if args[0] == "receive" {
        let dir = Path::new(&args[3]);
        std::fs::create_dir(dir)?;
        let mut journal = Journal::open(&args[2], b.peer(), 4)?;
        let mut receiver = Receiver::new(b.peer(), a.peer(), RxPolicy::default())?;
        let mut scratch = vec![0; 65536];
        println!(
            "{{\"status\":\"ready\",\"port\":{},\"family\":{}}}",
            socket.local_address().port(),
            family
        );
        std::io::stdout().flush()?;
        let mut seen = [false; 3];
        for _ in 0..3 {
            let receipt = socket.receive().await?;
            let packet = socket.bytes(receipt)?;
            let received = match receiver.boxed(&b, packet, &mut scratch) {
                Ok(ready) => ready,
                Err(Error::NotFound) => receiver.initial(&b, packet, &mut scratch, &mut journal)?,
                Err(error) => return Err(error.into()),
            };
            let msg = received.message().ok_or(Error::Malformed)?;
            let Some(index) = (1..=3u32).position(|sequence| msg == message(sequence)) else {
                return Err(Error::Malformed.into());
            };
            if seen[index] {
                return Err(Error::Replay.into());
            }
            seen[index] = true;
            std::fs::write(dir.join(format!("received-{}.bin", index + 1)), packet)?;
            socket.consume(receipt)?;
        }
        if seen != [true; 3] {
            return Err(Error::Malformed.into());
        }
        socket.close();
        println!(
            "{{\"status\":\"passed\",\"received_initial\":1,\"received_box\":1,\"received_rekey_box\":1}}"
        );
    } else if args[0] == "send" {
        let port: u16 = args[3].parse()?;
        let target = SocketAddr::new(bind.ip(), port);
        let mut journal = Journal::open(&args[2], a.peer(), 4)?;
        let (first, end) = journal.reserve_monotime(1, 3)?;
        if (first, end) != (1, 3) {
            return Err(Error::Replay.into());
        }
        let mut sender = Sender::new(
            a.peer(),
            b.peer(),
            TxPolicy {
                datagram_bytes: 192,
                secrets: 4,
                ..TxPolicy::default()
            },
            100,
        )?;
        for seq in 1..=3 {
            let packet = sender.initial(
                &a,
                &message(seq),
                u64::from(seq),
                100 + u64::from(seq),
                &mut Random,
            )?;
            std::fs::write(
                Path::new(&args[2]).join(format!("sent-{seq}.bin")),
                packet.bytes(),
            )?;
            socket.queue(target, packet).map_err(|r| r.reason)?;
            if socket.send().await?.bytes != 192 {
                return Err(Error::Malformed.into());
            }
        }
        socket.close();
        println!("{{\"status\":\"passed\",\"sent_initial\":3}}");
    } else {
        return Err("unknown command".into());
    }
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    runtime.block_on(async { tokio::time::timeout(Duration::from_secs(12), run(args)).await? })
}
