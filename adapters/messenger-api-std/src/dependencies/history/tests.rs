use super::*;
use gnunet_wire::official::MessageHeader;
use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
use wire::{Request, Response, body::Body, message::Message, padding};

type Failure = Box<dyn std::error::Error + Send + Sync>;
const ROOM: Hash = [31; 64];
const MISSING: Hash = [79; 64];
const HINT: Hash = [88; 64];
const MEMBER: ShortHash = [17; 32];
const PROFILE: native::Profile = native::Profile::LITTLE_255;
const TIMEOUT: Duration = Duration::from_secs(5);

async fn during<T>(
    stage: &'static str,
    step: impl Future<Output = Result<T, Failure>>,
) -> Result<T, Failure> {
    tokio::time::timeout(TIMEOUT, step)
        .await
        .map_err(|_| format!("Messenger test timed out waiting for {stage}"))?
}

struct Scratch(PathBuf);

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
    response.encode(PROFILE, &mut bytes)?;
    stream.write_all(&bytes).await?;
    Ok(())
}

async fn daemon(listener: UnixListener, public: PublicKey) -> Result<(), Failure> {
    let (mut stream, _) = listener.accept().await?;
    if !matches!(
        Request::decode(&frame(&mut stream).await?)?,
        Request::Create
    ) {
        return Err(Fault::Conflict.into());
    }
    if !matches!(
        Request::decode(&frame(&mut stream).await?)?,
        Request::Open { room, .. } if room.key == &ROOM
    ) {
        return Err(Fault::Conflict.into());
    }
    send(
        &mut stream,
        Response::MemberId {
            key: &ROOM,
            id: &MEMBER,
            reset: 1,
        },
    )
    .await?;
    send(
        &mut stream,
        Response::Open(wire::Room {
            door: &[0; 32],
            key: &ROOM,
            previous: &[0; 64],
            epoch: &[0; 64],
        }),
    )
    .await?;
    let bytes = frame(&mut stream).await?;
    let Request::Send { key, message } = Request::decode(&bytes)? else {
        return Err(Fault::Conflict.into());
    };
    let pubkey = wire::PublicKey::new(&public)?;
    let join = Message::decode(message.expose(), PROFILE, padding::Decode::Absent)?;
    let checked = crypto::signature::verify_member(join, pubkey)?;
    if key != &ROOM || !matches!(join.body(), Body::Join { .. }) {
        return Err(Fault::Authentication.into());
    }
    let head = checked.digest();
    send(
        &mut stream,
        Response::Receive {
            key: &ROOM,
            sender: &gnunet_crypto::hash512(&public),
            context: &[0; 64],
            hash: head,
            epoch: head,
            flags: 8,
            message,
        },
    )
    .await?;
    if !matches!(
        Request::decode(&frame(&mut stream).await?)?,
        Request::Get { key, hash } if key == &ROOM && hash == &MISSING
    ) {
        return Err(Fault::Conflict.into());
    }
    send(
        &mut stream,
        Response::Missing {
            key: &ROOM,
            hash: &MISSING,
        },
    )
    .await?;
    let bytes = frame(&mut stream).await?;
    let Request::Send { key, message } = Request::decode(&bytes)? else {
        return Err(Fault::Conflict.into());
    };
    let request = Message::decode(message.expose(), PROFILE, padding::Decode::Absent)?;
    let checked_request = crypto::signature::verify_member(request, pubkey)?;
    if key != &ROOM
        || request.header().sender_id != &MEMBER
        || request.header().previous != head
        || !matches!(request.body(), Body::Request { hash } if hash == &MISSING)
    {
        return Err(Fault::Authentication.into());
    }
    send(
        &mut stream,
        Response::Receive {
            key: &ROOM,
            sender: &gnunet_crypto::hash512(&public),
            context: &[0; 64],
            hash: checked_request.digest(),
            epoch: head,
            flags: 8,
            message,
        },
    )
    .await?;
    // A duplicate correlated result, a stale room notice and a duplicate
    // live hint must leave exactly one independently signed second request.
    for (key, hash) in [
        (&ROOM, &MISSING),
        (&[0; 64], &HINT),
        (&ROOM, &HINT),
        (&ROOM, &HINT),
    ] {
        send(&mut stream, Response::Missing { key, hash }).await?;
    }
    let bytes = frame(&mut stream).await?;
    let Request::Send { key, message } = Request::decode(&bytes)? else {
        return Err(Fault::Conflict.into());
    };
    let request = Message::decode(message.expose(), PROFILE, padding::Decode::Absent)?;
    crypto::signature::verify_member(request, pubkey)?;
    if key != &ROOM
        || request.header().sender_id != &MEMBER
        || !matches!(request.body(), Body::Request { hash } if hash == &HINT)
    {
        return Err(Fault::Authentication.into());
    }
    if stream.read(&mut [0]).await? != 0 {
        return Err(Fault::Replay.into());
    }
    Ok(())
}

#[test]
fn written_get_missing_prepares_one_member_signed_request() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(scenario())
}

async fn scenario() -> Result<(), Failure> {
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = std::env::temp_dir().join(format!("gm-{}-{n}", std::process::id()));
    std::fs::create_dir(&path)?;
    let scratch = Scratch(path);
    let path = scratch.0.join("s");
    let listener = UnixListener::bind(&path)?;
    let mut core = domain::Instance::new();
    let instance = native::Instance::new();
    let mut api = Api::<OsEntropy, 1024>::anonymous(
        &mut core,
        &instance,
        EndpointSource::unix(path),
        OsEntropy::new(),
        Limits {
            native: native::Limits {
                profile: PROFILE,
                ..native::Limits::default()
            },
            operations: 4,
            automatic_epochs: false,
            ..Limits::default()
        },
    )?;
    let server = tokio::spawn(daemon(
        listener,
        *api.identity_public(api.default_identity()?)?,
    ));
    let epoch = during("CREATE", async {
        loop {
            match api.progress().await? {
                Progress::Ready(epoch) => return Ok(epoch),
                Progress::Lost(_) => return Err(Fault::Closed.into()),
                _ => {}
            }
        }
    })
    .await?;
    let (room, open) = api.open_room(ROOM, TIMEOUT)?;
    during("signed JOIN echo", async {
        while api.sending(room).is_err() {
            if matches!(api.progress().await?, Progress::Lost(_)) {
                return Err(Fault::Closed.into());
            }
        }
        Ok(())
    })
    .await?;
    api.retire(open)?;
    let (index, source, _) = api.live_source(room)?;
    let now = api.sample()?;
    let span = Span::new(now, TIMEOUT)?;
    // Use the dependency lane with all ordinary host capacity held. The
    // native source, operation receipts and member signatures remain real.
    api.reservations = api.limits.operations - 2;
    let get = api.admit_history_get(index, MISSING, span, now, Intent::Dependency)?;
    if api.missing_history_get(source, epoch, &MISSING).is_some() {
        return Err(Fault::Replay.into());
    }
    let mut observed = false;
    let mut wrote_correlated = false;
    loop {
        match during(
            if wrote_correlated {
                "hint REQUEST"
            } else {
                "correlated REQUEST"
            },
            async { Ok(api.progress().await?) },
        )
        .await?
        {
            Progress::Written {
                kind: native::Kind::Get,
                binding: Some(binding),
                ..
            } if binding.operation() == get => {
                if api.missing_history_get(source, epoch, &MISSING) != Some(get)
                    || api.missing_history_get(source, epoch, &[1; 64]).is_some()
                {
                    return Err(domain::Error::AttributionConflict.into());
                }
            }
            Progress::State(domain::Event::Missing(original_room, hash)) => {
                if observed || original_room != room || hash != MISSING {
                    return Err(Fault::Replay.into());
                }
                observed = true;
            }
            Progress::Written {
                kind: native::Kind::Send,
                binding: Some(binding),
                ..
            } => {
                let job = api
                    .leases
                    .iter()
                    .find(|job| job.operation == binding.operation())
                    .ok_or(Fault::StaleGeneration)?;
                if !observed || !matches!(job.intent, Intent::HistoryRequest { dependency: true }) {
                    return Err(Fault::Conflict.into());
                }
                if wrote_correlated {
                    break;
                }
                if job.span.hard != span.hard || job.span.logical != span.logical {
                    return Err(Fault::Conflict.into());
                }
                wrote_correlated = true;
            }
            Progress::Lost(_) => return Err(Fault::Closed.into()),
            _ => {}
        }
    }
    api.close();
    during("daemon receipt", async { server.await? }).await?;
    Ok(())
}
