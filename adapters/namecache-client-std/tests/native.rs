//! One controlled original-MQ model using existing public ciphertext/query
//! fixtures only. No zone/private seed, key generation, decryption or C service.
//! Source preparation did not execute this model or its signature verification.
#![cfg(unix)]
use gnunet_namecache_client_host::{
    Cancellation, Client, EndpointSource, Instance, Limits, LocalReason, LossCause, Outcome,
    Progress, Submission,
    clock::{RuntimeClock, SystemClock},
    ipc::{Request, Response},
};
use gnunet_types::{AbsoluteTime, Error as Fault};
use gnunet_wire::official::MessageHeader;
use std::{error::Error, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::Instant,
};
type Failure = Box<dyn Error + Send + Sync>;
// Existing published ciphertext-only vectors. No private_input/key file is
// included, opened, hashed, generated or required by this model.
const CIPHER: &[u8] =
    include_bytes!("../../../crates/gnunet-gnscrypto/tests/fixtures/edkey_ascii-block.bin");
const QUERY: &[u8; 64] =
    include_bytes!("../../../crates/gnunet-gnscrypto/tests/fixtures/edkey_ascii-query.bin");
const EXPIRATION: AbsoluteTime = AbsoluteTime::from_micros(17_999_736_901_000_000);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self, Failure> {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!("gncc-{}-{n}", std::process::id()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let mut bytes = vec![0; MessageHeader::decode(&header)?.size()];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn send(stream: &mut UnixStream, response: Response<'_>) -> Result<(), Failure> {
    let mut bytes = vec![0; response.encoded_len()?];
    response.encode(&mut bytes)?;
    for part in bytes.chunks(5) {
        stream.write_all(part).await?;
    }
    Ok(())
}
async fn actor(listener: UnixListener) -> Result<(), Failure> {
    let (mut stream, _) = listener.accept().await?;
    let first = frame(&mut stream).await?;
    let Request::Lookup { rid: lookup, query } = Request::decode(&first)? else {
        return Err(Fault::Malformed.into());
    };
    assert_eq!(query, QUERY);
    let second = frame(&mut stream).await?;
    let Request::Delete { rid: delete, query } = Request::decode(&second)? else {
        return Err(Fault::Malformed.into());
    };
    assert_eq!(query, QUERY);
    assert_ne!(lookup, delete);
    // Replies are keyed by actual original RID, not FIFO/callback order.
    send(
        &mut stream,
        Response::Delete {
            rid: delete,
            result: 0,
        },
    )
    .await?;
    send(
        &mut stream,
        Response::Lookup {
            rid: lookup,
            expiration: EXPIRATION,
            block: CIPHER,
        },
    )
    .await?;
    let bytes = frame(&mut stream).await?;
    let Request::Cache {
        rid: cache,
        expiration,
        block,
    } = Request::decode(&bytes)?
    else {
        return Err(Fault::Malformed.into());
    };
    assert_eq!(expiration, AbsoluteTime::UNIX_EPOCH);
    assert_eq!(block, CIPHER);
    send(
        &mut stream,
        Response::Cache {
            rid: cache,
            result: 1,
        },
    )
    .await?;
    let bytes = frame(&mut stream).await?;
    let Request::Lookup { rid: miss, .. } = Request::decode(&bytes)? else {
        return Err(Fault::Malformed.into());
    };
    send(
        &mut stream,
        Response::Lookup {
            rid: miss,
            expiration: AbsoluteTime::UNIX_EPOCH,
            block: b"ignored official miss tail",
        },
    )
    .await?;
    let bytes = frame(&mut stream).await?;
    let Request::Delete { rid: cancelled, .. } = Request::decode(&bytes)? else {
        return Err(Fault::Malformed.into());
    };
    send(
        &mut stream,
        Response::Delete {
            rid: cancelled,
            result: -1,
        },
    )
    .await?;
    send(
        &mut stream,
        Response::Delete {
            rid: u32::MAX,
            result: -7,
        },
    )
    .await?;
    let bytes = frame(&mut stream).await?;
    let Request::Cache {
        rid: lost, block, ..
    } = Request::decode(&bytes)?
    else {
        return Err(Fault::Malformed.into());
    };
    assert_eq!(block, CIPHER);
    assert!(lost > cache);
    drop(stream); // No cache result. Do not silently repeat this unknown write.
    let (mut fresh, _) = listener.accept().await?;
    let bytes = frame(&mut fresh).await?;
    let Request::Lookup { rid: new, query } = Request::decode(&bytes)? else {
        return Err(Fault::Malformed.into());
    };
    assert_eq!(query, QUERY);
    assert!(new > lost);
    let mut corrupted = CIPHER.to_vec();
    let last = corrupted.last_mut().ok_or(Fault::Malformed)?;
    *last ^= 1;
    send(
        &mut fresh,
        Response::Lookup {
            rid: new,
            expiration: EXPIRATION,
            block: &corrupted,
        },
    )
    .await?;
    let mut byte = [0];
    assert_eq!(fresh.read(&mut byte).await?, 0); // Validation stopped original MQ.
    Ok(())
}
async fn model() -> Result<(), Failure> {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("s");
    let listener = UnixListener::bind(&path)?;
    let actor = tokio::spawn(actor(listener));
    let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
    let domain = Instance::new();
    let limits = Limits {
        io_slice_bytes: 1,
        retirement_grace: Duration::from_secs(2),
        ..Limits::default()
    };
    let mut client = Client::new(
        &domain,
        EndpointSource::unix_with_clock(path, clock.clone()),
        limits,
    )?;
    let until = clock
        .sample()?
        .now
        .as_micros()
        .checked_add(6_000_000)
        .ok_or(Fault::Overflow)?;
    let budget = Some(Instant::now() + Duration::from_secs(7));
    let zero = client.delete(QUERY, until)?;
    assert_eq!(client.cancel(zero)?, Cancellation::Unsent);
    loop {
        if let Progress::Completed(c) = client.drive(budget).await? {
            assert_eq!(c.operation, zero);
            assert!(matches!(
                c.outcome,
                Outcome::Local {
                    reason: LocalReason::Cancelled,
                    submission: Submission::Unsent
                }
            ));
            break;
        }
    }
    let lookup = client.lookup(QUERY, until)?;
    let delete = client.delete(QUERY, until)?;
    let mut got_lookup = false;
    let mut got_delete = false;
    while !got_lookup || !got_delete {
        if let Progress::Completed(c) = client.drive(budget).await? {
            if c.operation == lookup {
                let Outcome::Lookup(Some(block)) = c.outcome else {
                    return Err(Fault::Malformed.into());
                };
                assert_eq!(block.bytes(), CIPHER);
                assert_eq!(block.query(), QUERY);
                assert_eq!(block.expiration(), EXPIRATION);
                got_lookup = true;
            } else {
                assert_eq!(c.operation, delete);
                assert!(matches!(c.outcome, Outcome::Delete(0)));
                got_delete = true;
            }
        }
    }
    let cache = client.cache(CIPHER, until)?;
    loop {
        if let Progress::Completed(c) = client.drive(budget).await? {
            assert_eq!(c.operation, cache);
            assert!(matches!(c.outcome, Outcome::Cache(1)));
            break;
        }
    }
    let miss = client.lookup(&[7; 64], until)?;
    loop {
        if let Progress::Completed(c) = client.drive(budget).await? {
            assert_eq!(c.operation, miss);
            assert!(matches!(c.outcome, Outcome::Lookup(None)));
            break;
        }
    }
    let cancelled = client.delete(QUERY, until)?;
    let cancelled_rid = client.request_id(cancelled)?;
    loop {
        if matches!(
            client.drive(budget).await?,
            Progress::Activity {
                written_bytes: 1,
                ..
            }
        ) {
            break;
        }
    }
    assert_eq!(client.cancel(cancelled)?, Cancellation::Draining);
    loop {
        if let Progress::Completed(c) = client.drive(budget).await? {
            assert_eq!(c.operation, cancelled);
            assert!(matches!(
                c.outcome,
                Outcome::Local {
                    reason: LocalReason::Cancelled,
                    submission: Submission::Written { .. }
                }
            ));
            break;
        }
    }
    let (mut late, mut unknown) = (false, false);
    while !late || !unknown {
        if let Progress::Ignored { request_id, .. } = client.drive(budget).await? {
            if request_id == cancelled_rid {
                late = true;
            } else {
                assert_eq!(request_id, u32::MAX);
                unknown = true;
            }
        }
    }
    let old = client.epoch();
    let lost = client.cache(CIPHER, until)?;
    loop {
        if let Progress::Completed(c) = client.drive(budget).await? {
            assert_eq!(c.operation, lost);
            assert!(matches!(
                c.outcome,
                Outcome::Local {
                    reason: LocalReason::Lost,
                    submission: Submission::Written { .. }
                }
            ));
            break;
        }
    }
    loop {
        if let Progress::Connected(epoch) = client.drive(budget).await? {
            assert_ne!(Some(epoch), old);
            break;
        }
    }
    let bad = client.lookup(QUERY, until)?;
    let mut rejected = false;
    loop {
        match client.drive(budget).await? {
            Progress::Lost {
                cause: LossCause::Protocol(_),
                ..
            } => rejected = true,
            Progress::Completed(c) => {
                assert_eq!(c.operation, bad);
                assert!(rejected);
                assert!(matches!(
                    c.outcome,
                    Outcome::Local {
                        reason: LocalReason::Lost,
                        ..
                    }
                ));
                break;
            }
            _ => {}
        }
    }
    let _loss = client.close();
    actor.await??;
    Ok(())
}
#[test]
fn actual_rid_cipher_validation_cancel_and_unknown_write() -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async { tokio::time::timeout(Duration::from_secs(8), model()).await? })
}
