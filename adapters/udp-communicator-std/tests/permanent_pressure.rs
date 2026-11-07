//! Actual native receipt retained across a move into the original driver.
#![cfg(feature = "transport")]
#![expect(
    clippy::print_stderr,
    reason = "Finite regression records actual native send/receive stages and admission outcome only."
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite native regression asserts original bytes, explicit refusal and durable recovery."
)]
use gnunet_crypto::Entropy;
use gnunet_service_runtime::connection::Connection;
use gnunet_types::Error;
use gnunet_udp_communicator_core::{
    Identity,
    send::{Policy, Sender},
};
use gnunet_udp_communicator_host::{
    driver::{Activity, Capacity, Configuration, Driver},
    replay::Journal,
    socket::DatagramSocket,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{future::poll_fn, path::PathBuf, time::Duration};
use tokio::net::UnixStream;
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}
struct Random;
impl Entropy for Random {
    fn fill(&mut self, b: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(b).map_err(|_| Error::Entropy)
    }
}
#[tokio::test(flavor = "current_thread")]
async fn impossible_empty_effect_budget_discards_original_large_receipt_then_accepts_next_kx()
-> Result<(), Box<dyn std::error::Error>> {
    let local = Identity::from_seed([3; 32]);
    let remote = Identity::from_seed([5; 32]);
    let scratch = Scratch(
        std::env::temp_dir().join(format!("udp-permanent-pressure-{}", std::process::id())),
    );
    std::fs::create_dir(&scratch.0)?;
    let raw = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let buffer = raw.set_send_buffer_size(262144);
    eprintln!("ACTUAL_RAW_SEND_BUFFER_SET {buffer:?}");
    buffer?;
    raw.bind(&"127.0.0.1:0".parse::<std::net::SocketAddr>()?.into())?;
    let mut socket = DatagramSocket::bind("127.0.0.1:0".parse()?)?;
    let local_address = socket.local_address();
    let huge = vec![0; 65495];
    let sent = raw.send_to(&huge, &local_address.into());
    eprintln!("ACTUAL_NATIVE_SEND_65495 {sent:?}");
    assert_eq!(sent?, huge.len());
    let received = tokio::time::timeout(Duration::from_secs(2), socket.receive()).await;
    eprintln!("ACTUAL_NATIVE_RECEIVE_65495 {received:?}");
    let receipt = received??;
    assert_eq!(receipt.len(), huge.len());
    assert_eq!(socket.bytes(receipt)?, huge);
    eprintln!("ORIGINAL_RECEIPT_BYTES_MATCH 65495");
    // The actual socket already holds this original receipt. No private input
    // injection is involved; its checked SocketId survives this owner move.
    let (service, communicator) = UnixStream::pair()?;
    let configuration = Configuration {
        local: local.peer(),
        peer: remote.peer(),
        target: raw.local_addr()?.as_socket().ok_or(Error::Malformed)?,
        network: 1,
        capacity: Capacity {
            frames: 4,
            bytes: 65535,
            io_slice: 65535,
        },
        transmit: socket.profile().sender_policy(),
    };
    let mut driver = Driver::new(
        Connection::from_unix(communicator),
        socket,
        configuration,
        100,
    )?;
    let mut journal = Journal::open(&scratch.0, local.peer(), 2)?;
    let admission = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let activity =
                poll_fn(|cx| driver.poll_step(cx, &local, &mut journal, 100, &mut Random)).await?;
            if let Activity::Discarded(cause) = activity {
                assert_eq!(cause, Error::Capacity);
                break;
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await;
    eprintln!("ACTUAL_DRIVER_ADMISSION {admission:?}");
    admission??;
    assert_eq!(journal.commits(), 0);
    let mut sender = Sender::new(
        remote.peer(),
        local.peer(),
        Policy {
            datagram_bytes: 192,
            ..Policy::default()
        },
        100,
    )?;
    let message = [0, 8, 0, 0, 0, 0, 0, 1];
    let packet = sender.initial(&remote, &message, 1, 100, &mut Random)?;
    assert_eq!(
        raw.send_to(packet.bytes(), &local_address.into())?,
        packet.bytes().len()
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let activity =
                poll_fn(|cx| driver.poll_step(cx, &local, &mut journal, 100, &mut Random)).await?;
            if let Activity::Incoming { boxed: false, .. } = activity {
                break;
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await??;
    assert_eq!(journal.latest(remote.peer())?, Some(1));
    eprintln!("ACTUAL_NEXT_SIGNED_KX_ADMITTED durable_stamp1");
    driver.close();
    assert!(driver.is_quiescent());
    drop(service);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn transient_effect_pressure_retains_original_signed_receipt_until_registration_drains()
-> Result<(), Box<dyn std::error::Error>> {
    let local = Identity::from_seed([3; 32]);
    let remote = Identity::from_seed([5; 32]);
    let scratch = Scratch(
        std::env::temp_dir().join(format!("udp-transient-pressure-{}", std::process::id())),
    );
    std::fs::create_dir(&scratch.0)?;
    let raw = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    raw.bind(&"127.0.0.1:0".parse::<std::net::SocketAddr>()?.into())?;
    let mut socket = DatagramSocket::bind("127.0.0.1:0".parse()?)?;
    let mut sender = Sender::new(
        remote.peer(),
        local.peer(),
        Policy {
            datagram_bytes: 192,
            ..Policy::default()
        },
        100,
    )?;
    let message = [0, 8, 0, 0, 0, 0, 0, 2];
    let packet = sender.initial(&remote, &message, 2, 100, &mut Random)?;
    assert_eq!(
        raw.send_to(packet.bytes(), &socket.local_address().into())?,
        packet.bytes().len()
    );
    let receipt = tokio::time::timeout(Duration::from_secs(2), socket.receive()).await??;
    assert_eq!(socket.bytes(receipt)?, packet.bytes());
    let (service, communicator) = UnixStream::pair()?;
    let configuration = Configuration {
        local: local.peer(),
        peer: remote.peer(),
        target: raw.local_addr()?.as_socket().ok_or(Error::Malformed)?,
        network: 1,
        capacity: Capacity {
            frames: 4,
            bytes: 65535,
            io_slice: 65535,
        },
        transmit: socket.profile().sender_policy(),
    };
    let mut driver = Driver::new(
        Connection::from_unix(communicator),
        socket,
        configuration,
        100,
    )?;
    let mut journal = Journal::open(&scratch.0, local.peer(), 2)?;
    let mut admitted = 0;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match poll_fn(|cx| driver.poll_step(cx, &local, &mut journal, 100, &mut Random)).await?
            {
                Activity::Admitted => {
                    admitted += 1;
                    if admitted == 2 {
                        assert_eq!(journal.commits(), 0);
                    }
                }
                Activity::Incoming { boxed: false, .. } => break,
                Activity::Discarded(cause) => {
                    return Err(format!("transient original receipt discarded: {cause}").into());
                }
                _ => {}
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await??;
    assert_eq!(admitted, 2);
    assert_eq!(journal.latest(remote.peer())?, Some(2));
    eprintln!("ACTUAL_TRANSIENT_ORIGINAL_SIGNED_RECEIPT_RETAINED durable_stamp2");
    driver.close();
    assert!(driver.is_quiescent());
    drop(service);
    Ok(())
}
