//! The native client and a local official PEERSTORE framing model.
use super::{EndpointSource, Event, Instance, Limits, LoadedBalance, Outcome, Store, Submission};
use gnunet_peerstore_client_host::{
    Reason, Record,
    ipc::{Envelope, Request, Response},
};
use gnunet_wire::official::MessageHeader;
use std::{
    error::Error,
    future::poll_fn,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};

type Failure = Box<dyn Error + Send + Sync>;
const PEER: [u8; 32] = [0x29; 32];
const LOADED: u32 = 0x1234_5678;
const SAVED: u32 = 0x90ab_cdef;

struct SocketDirectory(PathBuf);

impl SocketDirectory {
    fn new() -> Result<Self, Failure> {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!("gfr-{}-{stamp:x}", std::process::id()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for SocketDirectory {
    fn drop(&mut self) {
        let _socket = std::fs::remove_file(self.0.join("p"));
        let _directory = std::fs::remove_dir(&self.0);
    }
}

async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    let _read = stream.read_exact(&mut header).await?;
    let mut bytes = vec![0; MessageHeader::decode(&header)?.size()];
    bytes[..4].copy_from_slice(&header);
    let _read = stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}

async fn reply(stream: &mut UnixStream, response: Response<'_>) -> Result<(), Failure> {
    let mut bytes = vec![0; response.encoded_len()?];
    let _encoded = response.encode(&mut bytes)?;
    stream.write_all(&bytes).await?;
    Ok(())
}

async fn actor(listener: UnixListener) -> Result<(), Failure> {
    let (mut stream, _) = listener.accept().await?;
    let request = frame(&mut stream).await?;
    let Request::IterateStart(start) = Request::decode(&request)? else {
        return Err("expected respect ITERATE_START".into());
    };
    assert_eq!(start.filter.peer, Some(PEER));
    assert_eq!(start.filter.subsystem, Some(b"fs".as_slice()));
    assert_eq!(start.filter.key, Some(b"respect".as_slice()));
    reply(
        &mut stream,
        Response::Record(Envelope {
            rid: start.rid,
            options: 0,
            reserved: 0,
            record: Record {
                peer: PEER,
                expiry: u64::MAX,
                subsystem: Some(b"fs"),
                key: Some(b"respect"),
                value: &LOADED.to_ne_bytes(),
            },
        }),
    )
    .await?;
    assert_eq!(
        Request::decode(&frame(&mut stream).await?)?,
        Request::IterateStop { rid: start.rid }
    );

    let request = frame(&mut stream).await?;
    let Request::Store(store) = Request::decode(&request)? else {
        return Err("expected respect STORE".into());
    };
    assert_ne!(store.rid, start.rid);
    assert_eq!(store.options, 1);
    assert_eq!(store.record.peer, PEER);
    assert_eq!(store.record.subsystem, Some(b"fs".as_slice()));
    assert_eq!(store.record.key, Some(b"respect".as_slice()));
    assert_eq!(store.record.expiry, u64::MAX);
    assert_eq!(store.record.value, SAVED.to_ne_bytes());
    reply(
        &mut stream,
        Response::StoreResult {
            rid: store.rid,
            result: 1,
        },
    )
    .await
}

async fn completion(store: &mut Store<'_>) -> Result<Event, Failure> {
    loop {
        let event = poll_fn(|cx| store.poll(cx)).await?;
        if !matches!(event, Event::Activity) {
            return Ok(event);
        }
    }
}

async fn exercise(store: &mut Store<'_>) -> Result<(), Failure> {
    let expires = store
        .clock()
        .sample()?
        .now
        .as_micros()
        .checked_add(10_000_000)
        .ok_or("deadline overflow")?;
    store.load(23, PEER, expires)?;
    let Event::Loaded {
        token,
        peer,
        value,
        outcome,
    } = completion(store).await?
    else {
        return Err("missing original respect load terminal".into());
    };
    assert_eq!(
        (token, peer, value),
        (23, PEER, LoadedBalance::Value(LOADED))
    );
    assert_eq!(
        outcome,
        Outcome::Local {
            reason: Reason::Cancelled,
            submission: Submission::StopSubmitted
        }
    );
    assert_eq!(store.pending(), 0);

    store.save(24, PEER, SAVED, expires)?;
    let Event::Saved {
        token,
        peer,
        balance,
        outcome,
    } = completion(store).await?
    else {
        return Err("missing original respect save terminal".into());
    };
    assert_eq!(
        (token, peer, balance, outcome),
        (24, PEER, SAVED, Outcome::StoreResult(1))
    );
    store.close()?;
    Ok(())
}

#[test]
fn respect_native_framing_load_stop_and_replace() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let scratch = SocketDirectory::new()?;
            let path = scratch.0.join("p");
            let listener = UnixListener::bind(&path)?;
            let mut instance = Instance::new();
            let limits = Limits {
                operations: 1,
                io_slice_bytes: 7,
                ..Limits::default()
            };
            let mut store = Store::new(&mut instance, EndpointSource::unix(path), limits)?;
            let ((), ()) = timeout(Duration::from_secs(5), async {
                tokio::try_join!(actor(listener), exercise(&mut store))
            })
            .await??;
            Ok(())
        })
}
