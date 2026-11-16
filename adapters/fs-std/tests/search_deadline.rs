//! Original search timing across pending IO and staged authenticated advertisements.
#![cfg(all(unix, feature = "service"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible native fixtures assert exact timing and original MQ retirement"
)]
use gnunet_fs::{Content, Keyword, Keywords, Uri, client::Instance, ublock};
use gnunet_fs_host::{
    ipc::EndpointSource,
    search::{self, Session},
};
use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, RuntimeClock, SystemClock};
use gnunet_types::{AbsoluteTime, Error};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 5_000_000_000_000_000;
struct Frozen(AtomicU64);
impl Frozen {
    fn new() -> Self {
        Self(AtomicU64::new(NOW))
    }
}
impl RuntimeClock for Frozen {
    fn sample(&self) -> std::result::Result<ClockSample, Error> {
        Ok(ClockSample {
            now: AbsoluteTime::from_micros(self.0.load(Ordering::Relaxed)),
            revision: 0,
        })
    }
    fn subscribe(&self) -> std::result::Result<Box<dyn ClockSubscription>, Error> {
        SystemClock.subscribe()
    }
}
struct Socket(PathBuf);
impl Socket {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(std::env::temp_dir().join(format!(
            "fs-search-time-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_file(&self.0);
    }
}
fn policy() -> search::Options {
    search::Options {
        anonymity: 1,
        local_only: true,
        deadline: AbsoluteTime::from_micros(NOW + 500_000),
        limits: Default::default(),
        block: Default::default(),
        protocol: Default::default(),
        native: Default::default(),
    }
}
#[test]
fn search_preparation_and_cancel_need_no_tokio_runtime() -> Result {
    let terms = [Keyword::new(b"scope", false)?];
    let mut identities = [Instance::new()];
    let path = Socket::new();
    let mut session = Session::<_, 4>::new(
        Uri::Keywords(Keywords::new(&terms)?),
        &mut identities,
        || {
            Ok(EndpointSource::unix_with_clock(
                path.0.clone(),
                Arc::new(Frozen::new()),
            ))
        },
        policy(),
    )?;
    assert_eq!(session.query_count(), 1);
    session.cancel()?;
    Ok(())
}

#[tokio::test]
async fn frozen_source_cannot_extend_pending_or_staged_search_work() -> Result {
    use gnunet_fs_host::search::observation::Staged;
    use gnunet_wire::official::fs::{BlockType, ClientPut, Request, Response};
    for staged in [false, true] {
        let socket = Socket::new();
        let listener = UnixListener::bind(&socket.0)?;
        let terms = [Keyword::new(b"scope", false)?];
        let content = Content {
            key: [1; 64],
            query: [2; 64],
            size: 3,
        };
        let publisher = ublock::Publisher::keyword(b"scope", Default::default())?;
        let mut storage = vec![0; 1024];
        let block = publisher
            .seal(b"", content.uri(), None, &mut storage)?
            .bytes()
            .to_vec();
        let (entered, observed) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0; 112];
            stream.read_exact(&mut request).await?;
            assert!(matches!(Request::decode(&request)?, Request::Search(_)));
            if staged {
                let response = Response::Put(ClientPut {
                    block_type: BlockType::UBLOCK,
                    expiration: AbsoluteTime::NEVER,
                    last_transmission: AbsoluteTime::from_micros(0),
                    num_transmissions: 0,
                    respect_offered: 0,
                    block: &block,
                });
                let mut wire = vec![0; response.encoded_len()?];
                response.encode(&mut wire)?;
                stream.write_all(&wire).await?;
            }
            entered
                .send(())
                .map_err(|_| std::io::Error::other("original receiver dropped"))?;
            let mut byte = [0];
            assert_eq!(
                stream.read(&mut byte).await?,
                0,
                "expiry must close the original query MQ"
            );
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let mut identities = [Instance::new()];
        let mut session = Session::<_, 4>::new(
            Uri::Keywords(Keywords::new(&terms)?),
            &mut identities,
            || {
                Ok(EndpointSource::unix_with_clock(
                    socket.0.clone(),
                    Arc::new(Frozen::new()),
                ))
            },
            policy(),
        )?;
        if staged {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if matches!(session.drive_staged(None).await?, Staged::Advertisement) {
                        break;
                    }
                }
                Ok::<_, search::Error>(())
            })
            .await??;
            observed.await?;
            assert!(
                session.observation().is_some(),
                "the advertisement was authenticated before expiry"
            );
        } else {
            let mut observed = std::pin::pin!(observed);
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    tokio::select! {
                        ready=&mut observed => { ready?; break; }
                        step=session.drive(None) => { step?; }
                    }
                }
                Ok::<_, Box<dyn std::error::Error>>(())
            })
            .await??;
        }
        // Freeze only after real IO completed, so no virtual-time auto-advance
        // can substitute for the native request or staged advertisement above.
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(1)).await;
        let refusal = if staged {
            session.accept_staged().map(|_| ())
        } else {
            tokio::time::timeout(Duration::from_millis(10), session.drive(None))
                .await
                .map_or(Err(search::Error::Protocol(Error::WouldBlock)), |result| {
                    result.map(|_| ())
                })
        };
        tokio::time::resume();
        assert!(
            matches!(refusal, Err(search::Error::Protocol(Error::Deadline))),
            "stalled logical time cannot grant another native allowance: {refusal:?}"
        );
        assert!(
            session.results().is_empty(),
            "late staged input cannot become a result"
        );
        tokio::time::timeout(Duration::from_secs(2), peer)
            .await??
            .map_err(|error| std::io::Error::other(error.to_string()))?;
    }
    Ok(())
}

#[test]
fn source_preparation_cannot_admit_a_probe_after_its_parent_search_expires() -> Result {
    use gnunet_fs_host::search::{Step, observation::Observation, probe};
    let clock = Arc::new(Frozen::new());
    let terms = [Keyword::new(b"scope", false)?];
    let content = Content {
        key: [1; 64],
        query: [2; 64],
        size: 3,
    };
    let publisher = ublock::Publisher::keyword(b"scope", Default::default())?;
    let mut storage = vec![0; 1024];
    let block = publisher.seal(b"", content.uri(), None, &mut storage)?;
    let opener = ublock::Context::keyword(b"scope", Default::default())?.into_opener();
    let mut identities = [Instance::new()];
    let socket = Socket::new();
    let mut calls = 0;
    let mut session = Session::<_, 4>::new(
        Uri::Keywords(Keywords::new(&terms)?),
        &mut identities,
        || {
            calls += 1;
            if calls == 2 {
                clock.0.store(NOW + 500_000, Ordering::Relaxed);
            }
            Ok(EndpointSource::unix_with_clock(
                socket.0.clone(),
                clock.clone(),
            ))
        },
        policy(),
    )?;
    let replayed = session.replay(Observation {
        query_id: 0,
        kind: ublock::Kind::Keyword,
        namespace: opener.namespace_key(),
        label: b"scope",
        lookup_key: opener.query(),
        wire: block.bytes(),
        expiration: AbsoluteTime::NEVER,
        observed_at: AbsoluteTime::from_micros(NOW),
    })?;
    let Step::Result { result } = replayed else {
        return Err("authenticated replay did not expose its result".into());
    };
    // The independently selected probe deadline is still in the future. Only
    // the original parent admission limit expired during source preparation.
    assert!(matches!(
        session.begin_probe(
            result,
            0,
            probe::Options::new(AbsoluteTime::from_micros(NOW + 1_000_000))
        ),
        Err(search::Error::Protocol(Error::Deadline))
    ));
    assert!(
        session.availability_summary(result).is_none(),
        "refused admission cannot publish a new probe attempt"
    );
    Ok(())
}
