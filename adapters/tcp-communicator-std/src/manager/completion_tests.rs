//! Local completion admission over real Unix streams; no normal/C-peer claim.
use super::*;
use gnunet_crypto::EddsaPrivateKey;
use gnunet_tcp_communicator_core::session::Role;
use tokio::{io::AsyncReadExt, net::UnixStream};

type Failure = Box<dyn std::error::Error>;
const QID: u32 = 0x0102_0304;
const MID: [u8; 8] = [0x91; 8];
fn check(value: bool) -> Result<(), Failure> {
    if value {
        Ok(())
    } else {
        Err("TCP completion admission regression".into())
    }
}
fn original(peer: EddsaPublicKey) -> Send {
    Send {
        qid: QID.to_be_bytes(),
        mid: MID,
        peer,
        epoch: 7,
        result_queued: false,
    }
}
async fn flush(link: &mut Link) -> Result<(), Failure> {
    while !link.empty() {
        poll_fn(|cx| link.poll_tx(cx)).await?;
    }
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn finite_capacity_and_one_slot_completion_never_duplicate_ack() -> Result<(), Failure> {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let peer = EddsaPrivateKey::from_seed([9; 32]).public_key();
        let queue = services::Queue::new(peer, QID, 1, Role::Outbound, b"tcp-127.0.0.1:1");
        let mut scratch = [0; 128];
        let n = queue.setup(3, &mut scratch)?;
        check(n > 64 && scratch[48..56] == 3u64.to_be_bytes())?;
        check(queue.setup(0, &mut scratch) == Err(Error::InvalidInput))?;
        check(queue.setup(u64::MAX, &mut scratch) == Err(Error::InvalidInput))?;
        let (client, mut service) = UnixStream::pair()?;
        let mut link = Link::new(Connection::from_unix(client), 65535, 1)?;
        let mut send = original(peer);
        check(!send.complete(&mut link, 7, true, &queue, &mut scratch)?)?;
        check(send.result_queued)?;
        for _ in 0..3 {
            check(
                send.complete(&mut link, 7, true, &queue, &mut scratch) == Err(Error::WouldBlock),
            )?;
        }
        flush(&mut link).await?;
        let mut ack = [0; 52];
        service.read_exact(&mut ack).await?;
        check(ack[..4] == [0, 52, 4, 186])?;
        check(ack[4..8] == 1i32.to_be_bytes() && ack[8..16] == MID)?;
        check(ack[16..20] == QID.to_be_bytes() && ack[20..52] == *peer.as_bytes())?;
        check(send.complete(&mut link, 7, true, &queue, &mut scratch)?)?;
        flush(&mut link).await?;
        let mut update = [0; 64];
        service.read_exact(&mut update).await?;
        check(update[..2] == 64u16.to_be_bytes() && update[2..4] == 1222u16.to_be_bytes())?;
        check(update[4..8] == QID.to_be_bytes() && update[48..56] == 1u64.to_be_bytes())?;
        check(
            service
                .try_read(&mut [0; 1])
                .is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock),
        )?;
        Ok::<_, Failure>(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn old_completion_and_terminal_queue_cannot_grant_replacement_credit() -> Result<(), Failure>
{
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let peer = EddsaPrivateKey::from_seed([9; 32]).public_key();
        let queue = services::Queue::new(peer, QID, 1, Role::Outbound, b"tcp-127.0.0.1:1");
        let mut scratch = [0; 128];
        // Retire each original stage: before ACK, ACK queued, ACK wholly written.
        for stage in 0..3 {
            let (client, mut old_service) = UnixStream::pair()?;
            let mut link = Link::new(Connection::from_unix(client), 65535, 1)?;
            let mut send = original(peer);
            if stage > 0 {
                check(!send.complete(&mut link, 7, true, &queue, &mut scratch)?)?;
            }
            if stage == 2 {
                flush(&mut link).await?;
                old_service.read_exact(&mut [0; 52]).await?;
            }
            link.disconnect();
            let (client, service) = UnixStream::pair()?;
            link.attach(Connection::from_unix(client))
                .map_err(|rejected| rejected.reason)?;
            check(send.complete(&mut link, 8, true, &queue, &mut scratch)?)?;
            check(link.empty())?;
            check(
                service
                    .try_read(&mut [0; 1])
                    .is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock),
            )?;
        }
        // Same-source route withdrawal after ACK must not return capacity either.
        let (client, mut service) = UnixStream::pair()?;
        let mut link = Link::new(Connection::from_unix(client), 65535, 1)?;
        let mut send = original(peer);
        check(!send.complete(&mut link, 7, true, &queue, &mut scratch)?)?;
        flush(&mut link).await?;
        service.read_exact(&mut [0; 52]).await?;
        check(send.complete(&mut link, 7, false, &queue, &mut scratch)?)?;
        check(link.empty())?;
        Ok::<_, Failure>(())
    })
    .await?
}
