//! One source-only controlled actual-Unix-MQ model using PUBLIC NONSECRET mock
//! key-shaped bytes. No key generation/import provider, hash, crypto, key file,
//! credential verification, ticket backend, database or real RECLAIM service.
#![cfg(unix)]
use gnunet_gnsrecord::{ZoneKey, ZoneKeyType};
use gnunet_reclaim_client_host::{
    Attribute, AttributeList, AttributeType, Cancellation, Client, ControlKind, Credential,
    CredentialType, EndpointSource, Identifier, Instance, Iterator, Limits, LocalReason, Name,
    Operation, Outcome, PresentationList, Progress, RelativeTime, Reply, SecretKeyView, Sensitive,
    Submission, Ticket, Uri,
    clock::{RuntimeClock, SystemClock},
    ipc::{self, Request, Response},
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::MessageHeader;
use std::{error::Error, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::Instant,
};
use zeroize::Zeroizing;
type Failure = Box<dyn Error + Send + Sync>;
const PUBLIC_MOCK: [u8; 36] = [
    0, 1, 0, 20, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3,
];
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self, Failure> {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let p = std::env::temp_dir().join(format!("grcl-{}-{n}", std::process::id()));
        std::fs::create_dir(&p)?;
        Ok(Self(p))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
fn attribute() -> Result<Attribute<'static>, Fault> {
    Ok(Attribute::new(
        Identifier::new([1; 32]),
        Identifier::ZERO,
        AttributeType::STRING,
        Name::new(b"public-mock")?,
        Sensitive::new(b"VALUE\0"),
    ))
}
fn credential() -> Result<Credential<'static>, Fault> {
    Ok(Credential::new(
        Identifier::new([2; 32]),
        CredentialType::JWT,
        Name::new(b"mock")?,
        Sensitive::new(b"NOT-A-JWT\0"),
    ))
}
fn identity() -> ZoneKey {
    ZoneKey::new(ZoneKeyType::Edkey, [4; 32])
}
async fn frame(s: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut h = [0; 4];
    s.read_exact(&mut h).await?;
    let mut b = Zeroizing::new(vec![0; MessageHeader::decode(&h)?.size()]);
    b[..4].copy_from_slice(&h);
    s.read_exact(&mut b[4..]).await?;
    Ok(b)
}
async fn send(s: &mut UnixStream, r: Response<'_>) -> Result<(), Failure> {
    let mut b = Zeroizing::new(vec![0; r.encoded_len()?]);
    r.encode(&mut b)?;
    for c in b.chunks(3) {
        s.write_all(c).await?;
    }
    Ok(())
}
async fn eof(s: &mut UnixStream) -> Result<(), Failure> {
    let mut b = [0];
    assert_eq!(s.read(&mut b).await?, 0);
    Ok(())
}
async fn actor(listener: UnixListener) -> Result<(), Failure> {
    let (mut general, _) = listener.accept().await?;
    for index in 0..7 {
        let b = frame(&mut general).await?;
        let request = Request::decode(&b)?;
        let rid = request.request_id();
        let response = match (index, request) {
            (0, Request::StoreAttribute { .. })
            | (1, Request::StoreCredential { .. })
            | (2, Request::DeleteAttribute { .. })
            | (3, Request::DeleteCredential { .. }) => Response::Success { rid, result: 1 },
            (4, Request::IssueTicket { uri, .. }) => {
                assert_eq!(uri.expose(), b"urn:example:mock");
                Response::Ticket {
                    rid,
                    ticket: Some(Ticket::new(b"MOCK.example.invalid")?),
                    uri: None,
                    presentations: PresentationList::empty(),
                }
            }
            (5, Request::RevokeTicket { .. }) => Response::Revoked { rid, result: 1 },
            (6, Request::ConsumeTicket { .. }) => Response::Consumed {
                rid,
                result: 0x100,
                reserved: 0,
                identity: Some(identity()),
                attributes: AttributeList::empty(),
                presentations: PresentationList::empty(),
            },
            _ => return Err(Fault::Malformed.into()),
        };
        send(&mut general, response).await?;
    }
    let b = frame(&mut general).await?;
    let old = Request::decode(&b)?.request_id();
    send(
        &mut general,
        Response::Success {
            rid: old,
            result: 1,
        },
    )
    .await?;
    let b = frame(&mut general).await?;
    let fresh = Request::decode(&b)?.request_id();
    assert_ne!(old, fresh);
    send(
        &mut general,
        Response::Success {
            rid: fresh,
            result: 1,
        },
    )
    .await?;
    drop(general);
    let (mut attrs, _) = listener.accept().await?;
    let b = frame(&mut attrs).await?;
    let Request::IterateStart {
        kind: ipc::Iteration::Attributes,
        rid,
        ..
    } = Request::decode(&b)?
    else {
        return Err(Fault::Malformed.into());
    };
    send(
        &mut attrs,
        Response::Attribute {
            rid,
            reserved: 0,
            credential_len: 0,
            identity: Some(identity()),
            attribute: Some(attribute()?),
        },
    )
    .await?;
    let b = frame(&mut attrs).await?;
    assert!(
        matches!(Request::decode(&b)?,Request::IterateNext{kind:ipc::Iteration::Attributes,rid:r}if r==rid)
    );
    send(
        &mut attrs,
        Response::Attribute {
            rid,
            reserved: 0,
            credential_len: 0,
            identity: None,
            attribute: None,
        },
    )
    .await?;
    eof(&mut attrs).await?;
    let (mut creds, _) = listener.accept().await?;
    let b = frame(&mut creds).await?;
    let Request::IterateStart {
        kind: ipc::Iteration::Credentials,
        rid,
        ..
    } = Request::decode(&b)?
    else {
        return Err(Fault::Malformed.into());
    };
    send(
        &mut creds,
        Response::Credential {
            rid,
            identity: Some(identity()),
            credential: Some(credential()?),
        },
    )
    .await?;
    let b = frame(&mut creds).await?;
    assert!(
        matches!(Request::decode(&b)?,Request::IterateStop{kind:ipc::Iteration::Credentials,rid:r}if r==rid)
    );
    eof(&mut creds).await?;
    let (mut tickets, _) = listener.accept().await?;
    let b = frame(&mut tickets).await?;
    let Request::IterateStart {
        kind: ipc::Iteration::Tickets,
        rid,
        ..
    } = Request::decode(&b)?
    else {
        return Err(Fault::Malformed.into());
    };
    // Matches active C collect_tickets_cb: a second real item can be pushed
    // WITHOUT another client NEXT. No counterfeit grant or result is supplied.
    for name in [
        b"MOCK1.example.invalid".as_slice(),
        b"MOCK2.example.invalid".as_slice(),
    ] {
        send(
            &mut tickets,
            Response::Ticket {
                rid,
                ticket: Some(Ticket::new(name)?),
                uri: Some(Uri::new(b"urn:example:mock")?),
                presentations: PresentationList::empty(),
            },
        )
        .await?;
    }
    send(
        &mut tickets,
        Response::Ticket {
            rid,
            ticket: None,
            uri: None,
            presentations: PresentationList::empty(),
        },
    )
    .await?;
    eof(&mut tickets).await?;
    Ok(())
}
async fn done<'id>(
    c: &mut Client<'id>,
    operation: Operation<'id>,
    wait: Option<Instant>,
) -> Result<Reply, Failure> {
    loop {
        match c.drive(wait).await? {
            Progress::Completed(c) => {
                assert_eq!(c.operation, operation);
                let Outcome::Reply(r) = c.outcome else {
                    return Err(Fault::Malformed.into());
                };
                return Ok(r);
            }
            Progress::WaitDeadline | Progress::Closed => return Err(Fault::Deadline.into()),
            Progress::Lost { .. } => return Err(Fault::Io.into()),
            _ => tokio::task::yield_now().await,
        }
    }
}
async fn client_flow(path: PathBuf) -> Result<(), Failure> {
    let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
    let instance = Instance::new();
    let limits = Limits {
        io_slice_bytes: 1,
        retirement_grace: Duration::from_secs(1),
        ..Limits::default()
    };
    let until = clock
        .sample()?
        .now
        .as_micros()
        .checked_add(6_000_000)
        .ok_or(Fault::Overflow)?;
    let wait = Some(Instant::now() + Duration::from_secs(7));
    let source = || EndpointSource::unix_with_clock(path.clone(), clock.clone());
    let key = SecretKeyView::new(&PUBLIC_MOCK)?;
    let attr = attribute()?;
    let cred = credential()?;
    let ticket = Ticket::new(b"MOCK.example.invalid")?;
    let uri = Uri::new(b"urn:example:mock")?;
    let mut c = Client::new(&instance, source(), limits)?;
    let op = c.store_attribute(key, attr, RelativeTime::FOREVER, until)?;
    assert!(matches!(
        done(&mut c, op, wait).await?.view()?,
        Response::Success { result: 1, .. }
    ));
    let op = c.store_credential(key, cred, RelativeTime::FOREVER, until)?;
    done(&mut c, op, wait).await?;
    let op = c.delete_attribute(key, attr, until)?;
    done(&mut c, op, wait).await?;
    let op = c.delete_credential(key, cred, until)?;
    done(&mut c, op, wait).await?;
    let op = c.issue_ticket(key, uri, AttributeList::empty(), until)?;
    assert!(matches!(
        done(&mut c, op, wait).await?.view()?,
        Response::Ticket {
            ticket: Some(_),
            ..
        }
    ));
    let op = c.revoke_ticket(key, ticket, until)?;
    done(&mut c, op, wait).await?;
    let op = c.consume_ticket(ticket, uri, until)?;
    assert!(matches!(
        done(&mut c, op, wait).await?.view()?,
        Response::Consumed { result: 0x100, .. }
    ));
    let old = c.store_attribute(key, attr, RelativeTime::FOREVER, until)?;
    loop {
        if matches!(
            c.drive(wait).await?,
            Progress::Activity {
                written_bytes: 1,
                ..
            }
        ) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(c.cancel(old)?, Cancellation::Draining);
    loop {
        if let Progress::Completed(done) = c.drive(wait).await? {
            assert_eq!(done.operation, old);
            assert!(matches!(
                done.outcome,
                Outcome::Local {
                    reason: LocalReason::Cancelled,
                    submission: Submission::Written { .. }
                }
            ));
            break;
        }
        tokio::task::yield_now().await;
    }
    let fresh = c.store_attribute(key, attr, RelativeTime::FOREVER, until)?;
    done(&mut c, fresh, wait).await?;
    loop {
        if matches!(c.drive(wait).await?, Progress::Lost { .. }) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(c.epoch().is_none());
    let _closed = c.close();
    let mut attrs = Iterator::new(
        &instance,
        source(),
        key,
        ipc::Iteration::Attributes,
        until,
        limits,
    )?;
    let mut next = false;
    loop {
        match attrs.drive(wait).await? {
            Progress::Item { reply, .. } => {
                assert!(matches!(
                    reply.view()?,
                    Response::Attribute {
                        attribute: Some(_),
                        ..
                    }
                ));
                attrs.next(until)?;
                next = true;
            }
            Progress::Completed(c) => {
                assert!(next);
                assert!(matches!(c.outcome, Outcome::Reply(_)));
                assert!(attrs.epoch().is_none());
                break;
            }
            Progress::WaitDeadline => return Err(Fault::Deadline.into()),
            _ => tokio::task::yield_now().await,
        }
    }
    let mut creds = Iterator::new(
        &instance,
        source(),
        key,
        ipc::Iteration::Credentials,
        until,
        limits,
    )?;
    let mut stop_written = false;
    loop {
        match creds.drive(wait).await? {
            Progress::Item { reply, .. } => {
                assert!(matches!(
                    reply.view()?,
                    Response::Credential {
                        credential: Some(_),
                        ..
                    }
                ));
                creds.stop(until)?;
            }
            Progress::ControlWritten {
                kind: ControlKind::Stop,
                ..
            } => stop_written = true,
            Progress::Completed(c) => {
                assert!(stop_written);
                assert!(matches!(
                    c.outcome,
                    Outcome::Local {
                        reason: LocalReason::Cancelled,
                        ..
                    }
                ));
                assert!(creds.epoch().is_none());
                break;
            }
            Progress::WaitDeadline => return Err(Fault::Deadline.into()),
            _ => tokio::task::yield_now().await,
        }
    }
    let mut tickets = Iterator::new(
        &instance,
        source(),
        key,
        ipc::Iteration::Tickets,
        until,
        limits,
    )?;
    let mut count = 0;
    loop {
        match tickets.drive(wait).await? {
            Progress::Item { reply, .. } => {
                assert!(matches!(
                    reply.view()?,
                    Response::Ticket {
                        ticket: Some(_),
                        ..
                    }
                ));
                count += 1;
            }
            Progress::Completed(c) => {
                assert_eq!(count, 2);
                assert!(matches!(c.outcome, Outcome::Reply(_)));
                assert!(tickets.epoch().is_none());
                break;
            }
            Progress::WaitDeadline => return Err(Fault::Deadline.into()),
            _ => tokio::task::yield_now().await,
        }
    }
    Ok(())
}
async fn model() -> Result<(), Failure> {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("s");
    let listener = UnixListener::bind(&path)?;
    let mut actor = tokio::spawn(actor(listener));
    let result = tokio::time::timeout(Duration::from_secs(8), client_flow(path)).await;
    if !matches!(&result, Ok(Ok(()))) {
        actor.abort();
        let _joined = actor.await;
        return match result {
            Ok(v) => v,
            Err(e) => Err(e.into()),
        };
    }
    match tokio::time::timeout(Duration::from_secs(1), &mut actor).await {
        Ok(result) => result??,
        Err(error) => {
            actor.abort();
            let _joined = actor.await;
            return Err(error.into());
        }
    }
    Ok(())
}
#[test]
fn controlled_original_mq_model() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(model())
}
