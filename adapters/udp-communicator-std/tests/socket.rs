//! Real Rust UDP socket/packet/journal composition. ACKs are deliberately applied
//! through the public component API; this is not official IPC/backchannel credit.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite native socket and durable replay witnesses assert actual IO outcomes."
)]
use gnunet_crypto::Entropy;
use gnunet_types::Error;
use gnunet_udp_communicator_core::{
    Identity,
    receive::{Policy as RxPolicy, Receiver},
    send::{Mode, Sender},
};
use gnunet_udp_communicator_host::{
    replay::Journal,
    socket::{DatagramSocket, Profile},
};
use std::{
    future::Future,
    net::{SocketAddr, UdpSocket},
    path::PathBuf,
    pin::pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll, Waker},
    time::Duration,
};
type Test = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "udp-socket-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
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
fn message(seq: u32) -> [u8; 8] {
    let mut b = [0; 8];
    b[..2].copy_from_slice(&8u16.to_be_bytes());
    b[4..].copy_from_slice(&seq.to_be_bytes());
    b
}
async fn scenario(bind: SocketAddr, profile: Profile) -> Test {
    let scratch = Scratch::new()?;
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let mut outbound = DatagramSocket::bind(bind)?;
    let mut inbound = DatagramSocket::bind(bind)?;
    assert_eq!(outbound.profile(), profile);
    assert_eq!(inbound.profile(), profile);
    assert_eq!(
        profile.initial_mtu(),
        if profile == Profile::Ipv4 { 1300 } else { 1080 }
    );
    assert_eq!(
        profile.boxed_mtu(),
        if profile == Profile::Ipv4 { 1404 } else { 1184 }
    );
    let mut policy = profile.sender_policy();
    policy.secrets = 4;
    // This component profile deliberately selects one ordinary BOX, one REKEY
    // and exhaustion of the original master before the next BOX. Initial KX
    // bytes are not BOX-master traffic; ACK does not change the byte budget.
    policy.maximum_secret_bytes = profile.datagram_bytes() as u64 * 2;
    policy.rekey_after_bytes = profile.datagram_bytes() as u64;
    let mut sender = Sender::new(a.peer(), b.peer(), policy, 100)?;
    let mut receiver = Receiver::new(b.peer(), a.peer(), RxPolicy::default())?;
    let mut journal = Journal::open(&scratch.0, b.peer(), 4)?;
    let (time, _end) = journal.reserve_monotime(100, 64)?;
    let first = sender.initial(&a, &message(1), time, 100, &mut Random)?;
    let captured = first.bytes().to_vec();
    {
        let mut future = pin!(inbound.receive());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
    }
    let target = inbound.local_address();
    let original_source = outbound.local_address();
    outbound.queue(target, first).map_err(|r| r.reason)?;
    let pending_hash = gnunet_crypto::hash256(outbound.pending().ok_or(Error::Stale)?.1.bytes());
    // Merely constructing and dropping a send wait performs no syscall and leaves
    // precisely the same immutable bytes/operation at the original owner.
    drop(outbound.send());
    assert_eq!(
        gnunet_crypto::hash256(outbound.pending().ok_or(Error::Stale)?.1.bytes()),
        pending_hash
    );
    let sent = outbound.send().await?;
    assert_eq!(sent.bytes, profile.datagram_bytes());
    assert!(outbound.is_quiescent());
    let receipt = inbound.receive().await?;
    assert_eq!(receipt.address(), original_source);
    assert_eq!(receipt.len(), profile.datagram_bytes());
    let repeated = inbound.receive().await?;
    assert_eq!(receipt, repeated);
    let mut plain = vec![0xa5; 65536];
    let accepted = receiver.initial(&b, inbound.bytes(receipt)?, &mut plain, &mut journal)?;
    assert_eq!(accepted.message(), Some(message(1).as_slice()));
    let ack = accepted.acknowledgements[0].ok_or(Error::Stale)?;
    inbound.consume(receipt)?;
    assert!(matches!(inbound.bytes(receipt), Err(Error::Stale)));
    assert!(matches!(inbound.consume(repeated), Err(Error::Stale)));
    sender.acknowledge(b.peer(), ack, 101)?;
    for seq in 2..=4 {
        let boxed = sender.boxed(&a, &message(seq), 100 + u64::from(seq), &mut Random)?;
        assert_eq!(
            boxed.mode(),
            match seq {
                2 => Mode::Box {
                    sequence: 1,
                    rekey: false
                },
                3 => Mode::Box {
                    sequence: 2,
                    rekey: true
                },
                _ => Mode::Box {
                    sequence: 1,
                    rekey: false
                },
            }
        );
        let expected = profile.datagram_bytes() + usize::from(seq == 3) * 36;
        assert_eq!(boxed.bytes().len(), expected);
        outbound.queue(target, boxed).map_err(|r| r.reason)?;
        assert_eq!(outbound.send().await?.bytes, expected);
        let receipt = inbound.receive().await?;
        let accepted = receiver.boxed(&b, inbound.bytes(receipt)?, &mut plain)?;
        assert_eq!(accepted.message(), Some(message(seq).as_slice()));
        for ack in accepted.acknowledgements.into_iter().flatten() {
            sender.acknowledge(b.peer(), ack, 100 + u64::from(seq))?;
        }
        inbound.consume(receipt)?;
    }
    // Real restart closes the old replay writer and all volatile receive keys.
    drop(journal);
    drop(receiver);
    let mut journal = Journal::open(&scratch.0, b.peer(), 4)?;
    let mut receiver = Receiver::new(b.peer(), a.peer(), RxPolicy::default())?;
    let raw = UdpSocket::bind(bind)?;
    assert_eq!(raw.send_to(&captured, target)?, captured.len());
    let receipt = inbound.receive().await?;
    assert!(matches!(
        receiver.initial(&b, inbound.bytes(receipt)?, &mut plain, &mut journal),
        Err(Error::Replay)
    ));
    assert_eq!(receiver.available(), 0);
    assert_eq!(receiver.secrets(), 0);
    inbound.consume(receipt)?;
    assert!(inbound.is_quiescent());
    outbound.close();
    inbound.close();
    assert!(outbound.is_quiescent());
    assert!(inbound.is_quiescent());
    assert!(matches!(inbound.bytes(receipt), Err(Error::Stale)));
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn actual_ipv4_initial_box_rekey_atomic_extent_and_durable_replay_restart() -> Test {
    tokio::time::timeout(
        Duration::from_secs(5),
        scenario("127.0.0.1:0".parse()?, Profile::Ipv4),
    )
    .await?
}
#[tokio::test(flavor = "current_thread")]
async fn actual_ipv6_initial_box_rekey_atomic_extent_and_durable_replay_restart() -> Test {
    tokio::time::timeout(
        Duration::from_secs(5),
        scenario("[::1]:0".parse()?, Profile::Ipv6),
    )
    .await?
}
#[tokio::test(flavor = "current_thread")]
async fn native_refusal_returns_original_packet_and_cancellation_never_restores_core_sequence()
-> Test {
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let mut socket = DatagramSocket::bind("127.0.0.1:0".parse()?)?;
    let mut sender = Sender::new(a.peer(), b.peer(), socket.profile().sender_policy(), 100)?;
    let packet = sender.initial(&a, &message(1), 1, 100, &mut Random)?;
    let hash = gnunet_crypto::hash256(packet.bytes());
    let operation = packet.operation();
    let refused = match socket.queue("[::1]:1".parse()?, packet) {
        Ok(()) => return Err(Error::Malformed.into()),
        Err(r) => r,
    };
    assert_eq!(refused.reason, Error::InvalidInput);
    assert_eq!(gnunet_crypto::hash256(refused.value.bytes()), hash);
    assert_eq!(refused.value.operation(), operation);
    socket
        .queue("127.0.0.1:1".parse()?, refused.value)
        .map_err(|r| r.reason)?;
    let second = sender.initial(&a, &message(2), 2, 101, &mut Random)?;
    let refused = match socket.queue("127.0.0.1:1".parse()?, second) {
        Ok(()) => return Err(Error::Malformed.into()),
        Err(r) => r,
    };
    assert_eq!(refused.reason, Error::Capacity);
    drop(refused.value);
    let (_, original) = socket.cancel_send().ok_or(Error::Stale)?;
    assert_eq!(gnunet_crypto::hash256(original.bytes()), hash);
    assert!(socket.is_quiescent());
    socket.close();
    let refused = match socket.queue("127.0.0.1:1".parse()?, original) {
        Ok(()) => return Err(Error::Malformed.into()),
        Err(r) => r,
    };
    assert_eq!(refused.reason, Error::Stale);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn foreign_socket_receipt_cannot_read_or_consume_equal_metadata() -> Test {
    tokio::time::timeout(Duration::from_secs(5), async {
        let source = UdpSocket::bind("127.0.0.1:0")?;
        let mut first = DatagramSocket::bind("127.0.0.1:0".parse()?)?;
        let mut second = DatagramSocket::bind("127.0.0.1:0".parse()?)?;
        let first_message = message(11);
        let second_message = message(22);
        source.send_to(&first_message, first.local_address())?;
        source.send_to(&second_message, second.local_address())?;
        let first_receipt = first.receive().await?;
        let second_receipt = second.receive().await?;
        assert_eq!(first_receipt.address(), second_receipt.address());
        assert_eq!(first_receipt.len(), second_receipt.len());
        assert!(matches!(second.bytes(first_receipt), Err(Error::Stale)));
        assert!(matches!(first.bytes(second_receipt), Err(Error::Stale)));
        assert!(matches!(second.consume(first_receipt), Err(Error::Stale)));
        assert!(matches!(first.consume(second_receipt), Err(Error::Stale)));
        assert_eq!(first.bytes(first_receipt)?, first_message);
        assert_eq!(second.bytes(second_receipt)?, second_message);
        let mut moved = second;
        assert_eq!(moved.bytes(second_receipt)?, second_message);
        first.consume(first_receipt)?;
        moved.consume(second_receipt)?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}
