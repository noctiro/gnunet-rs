//! Native failure witnesses only; no peer agreement or525 producer is inferred.
use super::*;
use std::{error::Error as StdError, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
type Failure = Box<dyn StdError>;
static NEXT_DIRECTORY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Failure> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let serial = NEXT_DIRECTORY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir();
        let path = root.join(format!(
            "gconsensus-{}-{stamp}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
fn runtime() -> Result<tokio::runtime::Runtime, Failure> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}
fn client(directory: &Directory, limits: Limits) -> Result<(Client, UnixListener), Failure> {
    let path = directory.0.join("consensus.sock");
    let listener = UnixListener::bind(&path)?;
    let source = EndpointSource::unix(path);
    let bounds = Bounds::new(source.clock().as_ref(), Duration::from_secs(30))?;
    let join = Join {
        session: [7; 64],
        start: bounds.expires - 1_000_000,
        deadline: bounds.expires,
        peers: &[],
    };
    Ok((Client::new(source, join, limits, bounds)?, listener))
}
async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let n = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if n < 4 {
        return Err("short native fixture frame".into());
    }
    let mut data = vec![0; n];
    data[..4].copy_from_slice(&header);
    stream.read_exact(&mut data[4..]).await?;
    Ok(data)
}
async fn joined(client: &mut Client, listener: &UnixListener) -> Result<UnixStream, Failure> {
    let mut accept = std::pin::pin!(listener.accept());
    let mut stream = None;
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| -> Poll<Result<UnixStream, Failure>> {
            if stream.is_none()
                && let Poll::Ready(result) = accept.as_mut().poll(cx)
            {
                stream = Some(result?.0);
            }
            match client.poll_progress(cx) {
                Poll::Ready(Ok(
                    Progress::Attached(_) | Progress::Activity | Progress::Written(_),
                )) => cx.waker().wake_by_ref(),
                Poll::Ready(Ok(_)) => {
                    return Poll::Ready(Err("unexpected original JOIN result".into()));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Pending => {}
            }
            if client.joined
                && let Some(stream) = stream.take()
            {
                return Poll::Ready(Ok(stream));
            }
            Poll::Pending
        }),
    )
    .await??;
    let mut result = result;
    if !matches!(
        ClientRequest::decode(&frame(&mut result).await?)?,
        ClientRequest::Join(_)
    ) {
        return Err("native JOIN was not actually written".into());
    }
    Ok(result)
}
async fn loss(client: &mut Client) -> Result<Loss, Failure> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match client.progress().await? {
                Progress::Lost(loss) => return Ok(loss),
                Progress::Done { .. } => return Err("source failure became successful525".into()),
                _ => {}
            }
        }
    })
    .await?
}
fn check_closed(client: &mut Client, lost: &Loss) -> Result<(), Failure> {
    if !lost.joined
        || lost.concluded
        || lost.epoch.as_ref().is_none_or(Epoch::live)
        || client.insert(0, b"after-loss").is_ok()
        || client.conclude().is_ok()
    {
        return Err("old source or uncertain operation revived".into());
    }
    Ok(())
}

#[test]
fn native_eof_after_whole_join_is_observed_without_conclude_or_new_input() -> Result<(), Failure> {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let (mut client, listener) = client(&directory, Limits::default())?;
        let peer = joined(&mut client, &listener).await?;
        let original = client.native_deadline();
        drop(peer);
        let lost = loss(&mut client).await?;
        if !matches!(lost.cause, Cause::Eof)
            || !lost.pending.is_empty()
            || Instant::now() >= original
        {
            return Err("pre-CONCLUDE EOF was delayed or changed into a deadline".into());
        }
        check_closed(&mut client, &lost)
    })
}
#[test]
fn native_malformed_input_before_conclude_reports_actual_failure() -> Result<(), Failure> {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let (mut client, listener) = client(&directory, Limits::default())?;
        let mut peer = joined(&mut client, &listener).await?;
        peer.write_all(&[0, 3, 2, 13]).await?; // actual impossible3-byte header extent
        let lost = loss(&mut client).await?;
        if !matches!(lost.cause, Cause::Failure(_)) || lost.partial_input != 4 {
            return Err("native malformed input was not retained as failure".into());
        }
        check_closed(&mut client, &lost)
    })
}
#[test]
fn premature_real525_is_refused_without_certifying_unwritten524() -> Result<(), Failure> {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let (mut client, listener) = client(&directory, Limits::default())?;
        let mut peer = joined(&mut client, &listener).await?;
        let mut bytes = [0; 4];
        ClientResponse::Done.encode(&mut bytes)?;
        peer.write_all(&bytes).await?;
        let lost = loss(&mut client).await?;
        if !matches!(
            lost.cause,
            Cause::Failure(Error::Protocol(Fault::Malformed))
        ) || lost.partial_input != 4
        {
            return Err("premature525 did not preserve its actual original prefix/refusal".into());
        }
        check_closed(&mut client, &lost)
    })
}
#[test]
fn actual_backpressured_insert_fifo_keeps_all_original_prefix_and_unknown_facts()
-> Result<(), Failure> {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let (mut client, listener) = client(
            &directory,
            Limits {
                queued_bytes: 4 << 20,
                retained_bytes: 8 << 20,
                io_slice_bytes: 31,
                ..Limits::default()
            },
        )?;
        let mut peer = joined(&mut client, &listener).await?;
        let payload = vec![17; 60_000];
        for _ in 0..64 {
            client.insert(0, &payload)?;
        }
        let admitted: Vec<_> = client
            .queue
            .iter()
            .map(|p| (p.kind.clone(), p.length, p.original))
            .collect();
        let original_epoch = client.epoch.clone().ok_or("original epoch missing")?;
        let encoded = encode(ClientRequest::Insert {
            element_type: 0,
            data: &payload,
        })?;
        let mut turns = 0usize;
        // Deliberately do not read INSERT from the real peer. This reaches the
        // native writer's actual Pending, not a fabricated completion/credit.
        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| -> Poll<Result<(), Failure>> {
                for _ in 0..4096 {
                    turns += 1;
                    if turns > 200_000 {
                        return Poll::Ready(Err("no bounded native TX pressure".into()));
                    }
                    match client.poll_output(cx) {
                        Poll::Ready(Ok(Progress::Written(_) | Progress::Activity)) => {}
                        Poll::Ready(Ok(_)) => {
                            return Poll::Ready(Err("unexpected TX result".into()));
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                        Poll::Pending
                            if client.inserts_written > 0
                                || client.queue.front().is_some_and(|p| p.written > 0) =>
                        {
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                    if client.queue.is_empty() {
                        return Poll::Ready(Err("native fixture did not reach TX pressure".into()));
                    }
                }
                cx.waker().wake_by_ref();
                Poll::Pending
            }),
        )
        .await??;
        let earlier_whole = usize::try_from(client.inserts_written)?;
        let earlier_prefix = client
            .queue
            .front()
            .ok_or("pending original INSERT missing")?
            .written;
        let earlier_bytes = earlier_whole
            .checked_mul(encoded.len())
            .and_then(|n| n.checked_add(earlier_prefix))
            .ok_or("earlier original prefix overflow")?;
        // Closing only the peer's write half preserves the blocked original TX
        // direction while making the same original RX report actual EOF.
        peer.shutdown().await?;
        // A previous native Pending is not permanent: this required TX-first
        // turn may write more actual bytes before the next RX turn sees EOF.
        client.io_class = 0;
        let lost = loss(&mut client).await?;
        if !matches!(lost.cause, Cause::Eof)
            || lost.epoch.as_ref() != Some(&original_epoch)
            || lost.partial_input != 0
            || lost.elements != 0
        {
            return Err("blocked TX hid the original RX EOF/source facts".into());
        }
        // The SDK has physically closed before loss exposure. Drain only now,
        // so the fixture cannot release the pressure before the tested RX turn.
        // Native bytes independently determine every whole and partial INSERT;
        // an earlier queue snapshot cannot forbid legitimate later TX progress.
        let maximum = admitted
            .len()
            .checked_mul(encoded.len())
            .ok_or("original native extent overflow")?;
        if maximum >= 4 << 20 {
            return Err("native witness exceeds fixed4MiB cap".into());
        }
        let mut received = vec![0; maximum + 1];
        let mut used = 0usize;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let bytes = peer.read(&mut received[used..]).await?;
                if bytes == 0 {
                    return Ok::<(), Failure>(());
                }
                used = used.checked_add(bytes).ok_or("native witness overflow")?;
                if used > maximum {
                    return Err("old MQ sent beyond admitted original INSERT bytes".into());
                }
            }
        })
        .await??;
        received.truncate(used);
        if used < earlier_bytes
            || !received
                .chunks(encoded.len())
                .all(|chunk| chunk == &encoded[..chunk.len()])
        {
            return Err("actual native stream changed the admitted INSERT concatenation".into());
        }
        let whole = used / encoded.len();
        let partial = used % encoded.len();
        if whole >= admitted.len()
            || lost.inserts_written != u64::try_from(whole)?
            || lost.pending.len() != admitted.len() - whole
        {
            return Err("loss whole count/FIFO differs from actual original native bytes".into());
        }
        for (position, (actual, expected)) in
            lost.pending.iter().zip(&admitted[whole..]).enumerate()
        {
            let written = if position == 0 { partial } else { 0 };
            if actual.kind != expected.0
                || actual.length != expected.1
                || actual.written != written
                || actual.original.hard != expected.2.hard
                || actual.original.expires != expected.2.expires
                || actual.whole
                || actual.bytes.is_some()
                || actual.bound.is_some()
            {
                return Err(
                    "original pending INSERT differs from native prefix/source/bound facts".into(),
                );
            }
        }
        check_closed(&mut client, &lost)
    })
}
#[test]
fn actual523_owner_survives_later525_after_whole_conclude() -> Result<(), Failure> {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let (mut client, listener) = client(&directory, Limits::default())?;
        let mut peer = joined(&mut client, &listener).await?;
        client.conclude()?;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if matches!(
                    client.progress().await?,
                    Progress::Written(Receipt {
                        kind: Kind::Conclude,
                        ..
                    })
                ) {
                    break;
                }
            }
            Ok::<(), Failure>(())
        })
        .await??;
        if !matches!(
            ClientRequest::decode(&frame(&mut peer).await?)?,
            ClientRequest::Conclude
        ) {
            return Err("whole original524 missing".into());
        }
        let value = ClientResponse::Element {
            element_type: 3,
            data: b"remote-owned",
        };
        let mut data = vec![0; value.encoded_len()?];
        value.encode(&mut data)?;
        peer.write_all(&data).await?;
        let observation = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Progress::Element(value) = client.progress().await? {
                    return Ok::<_, Failure>(value);
                }
            }
        })
        .await??;
        let mut done = [0; 4];
        ClientResponse::Done.encode(&mut done)?;
        peer.write_all(&done).await?;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Progress::Done { epoch, elements } = client.progress().await? {
                    if epoch.live() || elements != 1 {
                        return Err("completed source was not actually retired".into());
                    }
                    break;
                }
            }
            Ok::<(), Failure>(())
        })
        .await??;
        if !matches!(
            observation.response()?,
            ClientResponse::Element {
                element_type: 3,
                data: b"remote-owned"
            }
        ) {
            return Err("owned original523 changed when native source retired".into());
        }
        Ok(())
    })
}

#[test]
fn dropping_original_client_retires_held_epoch_and_closes_actual_peer() -> Result<(), Failure> {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let (mut client, listener) = client(&directory, Limits::default())?;
        let mut peer = joined(&mut client, &listener).await?;
        let epoch = client
            .epoch
            .clone()
            .ok_or("actual attached epoch missing")?;
        if !epoch.live() {
            return Err("original epoch retired before drop".into());
        }
        drop(client);
        let mut byte = [0; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), peer.read(&mut byte)).await??;
        if n != 0 || epoch.live() {
            return Err(
                "physical client drop left its public epoch live or peer socket open".into(),
            );
        }
        Ok(())
    })
}

#[test]
fn early_remote_element_and_held_owner_do_not_block_actual_transmit_or_consume_next_rx()
-> Result<(), Failure> {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let (mut client, listener) = client(&directory, Limits::default())?;
        let mut peer = joined(&mut client, &listener).await?;
        let value = ClientResponse::Element {
            element_type: 3,
            data: b"before-local-conclude",
        };
        let mut bytes = vec![0; value.encoded_len()?];
        value.encode(&mut bytes)?;
        peer.write_all(&bytes).await?;
        let first = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Progress::Element(value) = client.progress().await? {
                    return Ok::<_, Failure>(value);
                }
            }
        })
        .await??;
        if client.concluded || !client.joined {
            return Err("early element became conclude or lost JOIN context".into());
        }
        let insertion = client.insert(0, b"actual-local-during-validation")?;
        let value = ClientResponse::Element {
            element_type: 4,
            data: b"second-stays-native",
        };
        let mut bytes = vec![0; value.encoded_len()?];
        value.encode(&mut bytes)?;
        peer.write_all(&bytes).await?;
        let written = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match poll_fn(|cx| client.poll_transmit(cx)).await? {
                    Progress::Written(receipt) => return Ok::<_, Failure>(receipt),
                    Progress::Activity => {}
                    _ => return Err("transmit-only consumed RX or invented completion".into()),
                }
            }
        })
        .await??;
        if written.kind != Kind::Insert(insertion) || client.concluded || client.conclude_queued {
            return Err("wrong original whole write or invented conclude".into());
        }
        if !matches!(
            ClientRequest::decode(&frame(&mut peer).await?)?,
            ClientRequest::Insert {
                element_type: 0,
                data: b"actual-local-during-validation"
            }
        ) {
            return Err("native peer did not receive actual INSERT".into());
        }
        let second = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Progress::Element(value) = client.progress().await? {
                    return Ok::<_, Failure>(value);
                }
            }
        })
        .await??;
        if !matches!(
            first.response()?,
            ClientResponse::Element {
                element_type: 3,
                data: b"before-local-conclude"
            }
        ) || !matches!(
            second.response()?,
            ClientResponse::Element {
                element_type: 4,
                data: b"second-stays-native"
            }
        ) || first.epoch() != second.epoch()
            || first.ordinal() != 1
            || second.ordinal() != 2
        {
            return Err("retained original observation or queued RX was replaced".into());
        }
        drop(peer);
        let lost = loss(&mut client).await?;
        if lost.elements != 2 || lost.inserts_written != 1 || first.epoch().live() {
            return Err("actual original source facts were lost".into());
        }
        check_closed(&mut client, &lost)
    })
}
