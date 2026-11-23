use super::{Arguments, OutputMode, Result, execute_actions};
use crate::reclaim::Action;
use gnunet::{
    clients::reclaim::{
        Attribute, AttributeType, EndpointSource, Identifier, Name, PresentationList, Sensitive,
        Ticket, ipc,
    },
    gnsrecord::{ZoneKey, ZoneKeyType},
    wire::{
        MessageHeader,
        identity::{self, SecretKeyView},
    },
};
use gnunet_program_host::helpers::Target;
use std::{
    ffi::OsString,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
use zeroize::Zeroizing;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self> {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.subsec_nanos();
        let directory = std::env::temp_dir().join(format!("gr-{}-{stamp:x}", std::process::id()));
        std::fs::create_dir(&directory)?;
        Ok(Self(directory))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}

async fn request(stream: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = MessageHeader::decode(&header)?.size();
    let mut frame = Zeroizing::new(vec![0; length]);
    frame[..4].copy_from_slice(&header);
    stream.read_exact(&mut frame[4..]).await?;
    Ok(frame)
}

async fn reply(stream: &mut UnixStream, response: ipc::Response<'_>) -> Result<()> {
    let mut frame = Zeroizing::new(vec![0; response.encoded_len()?]);
    response.encode(&mut frame)?;
    stream.write_all(&frame).await?;
    Ok(())
}

async fn attributes(listener: &UnixListener, object: Option<Attribute<'_>>) -> Result<()> {
    let (mut stream, _) = listener.accept().await?;
    let frame = request(&mut stream).await?;
    let ipc::Request::IterateStart {
        kind: ipc::Iteration::Attributes,
        rid,
        ..
    } = ipc::Request::decode(&frame)?
    else {
        return Err("expected the original attribute iterator".into());
    };
    if let Some(attribute) = object {
        reply(
            &mut stream,
            ipc::Response::Attribute {
                rid,
                reserved: 0,
                credential_len: 0,
                identity: Some(ZoneKey::new(ZoneKeyType::Edkey, [4; 32])),
                attribute: Some(attribute),
            },
        )
        .await?;
        let frame = request(&mut stream).await?;
        if !matches!(ipc::Request::decode(&frame)?, ipc::Request::IterateNext { kind: ipc::Iteration::Attributes, rid: next } if next == rid)
        {
            return Err("missing matching iterator credit".into());
        }
    }
    reply(
        &mut stream,
        ipc::Response::Attribute {
            rid,
            reserved: 0,
            credential_len: 0,
            identity: None,
            attribute: None,
        },
    )
    .await?;
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Exact native message order and checked ticket selection are fixture assertions"
)]
fn combined_store_issue_and_list_use_one_identity_and_original_service_replies() -> Result<()> {
    let args = Arguments::new();
    let parsed = args.options(Target::new(3_600_000_000)).run(
        b"gnunet-reclaim",
        [
            "gnunet-reclaim",
            "-T",
            "-i",
            "nickname,NICKNAME",
            "-U",
            "urn:local:test",
            "-a",
            "Nickname",
            "-V",
            "Public",
            "-e",
            "demo",
        ]
        .map(OsString::from),
        false,
    );
    assert!(parsed.remaining().is_some_and(<[_]>::is_empty));
    let plan = args.plan(900_000_000)?;
    assert_eq!(
        plan.commands
            .iter()
            .map(|command| command.action)
            .collect::<Vec<_>>(),
        [
            Action::AttributeStore,
            Action::TicketIssue,
            Action::TicketList
        ]
    );
    let dir = Directory::new()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let identity_path = dir.0.join("id");
            let service_path = dir.0.join("rc");
            let identity_listener = UnixListener::bind(&identity_path)?;
            let service_listener = UnixListener::bind(&service_path)?;
            let original_identity = async {
                let (mut stream, _) = identity_listener.accept().await?;
                let frame = request(&mut stream).await?;
                assert_eq!(
                    match identity::Request::decode(&frame)? {
                        identity::Request::Lookup { name } => name,
                        _ => return Err("expected exact ego lookup".into()),
                    },
                    b"demo"
                );
                let mut mock_key = Zeroizing::new([3; 36]);
                mock_key[..4].copy_from_slice(&[0, 1, 0, 20]);
                let update = identity::Response::Update {
                    name: Some(b"demo"),
                    key: SecretKeyView::new(&*mock_key)?,
                };
                let mut encoded = Zeroizing::new(vec![0; update.encoded_len()?]);
                update.encode(&mut encoded)?;
                stream.write_all(&encoded).await?;
                assert_eq!(stream.read(&mut [0]).await?, 0);
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            let reclaim = async {
                attributes(&service_listener, None).await?;
                let (mut store, _) = service_listener.accept().await?;
                let frame = request(&mut store).await?;
                let ipc::Request::StoreAttribute {
                    rid,
                    attribute,
                    expiration,
                    ..
                } = ipc::Request::decode(&frame)?
                else {
                    return Err("store did not follow its own natural END".into());
                };
                assert_eq!(attribute.name.bytes(), b"nickname");
                assert_eq!(expiration.as_micros(), 900_000_000);
                reply(&mut store, ipc::Response::Success { rid, result: 1 }).await?;
                let assigned = Identifier::new([1; 32]);
                let persisted = Attribute::new(
                    assigned,
                    Identifier::ZERO,
                    AttributeType::STRING,
                    Name::new(b"nickname")?,
                    Sensitive::new(b"Public\0"),
                );
                attributes(&service_listener, Some(persisted)).await?;
                let (mut issue, _) = service_listener.accept().await?;
                let frame = request(&mut issue).await?;
                let ipc::Request::IssueTicket {
                    rid,
                    uri,
                    attributes,
                    ..
                } = ipc::Request::decode(&frame)?
                else {
                    return Err("issue did not use the fresh scan".into());
                };
                assert_eq!(uri.expose(), b"urn:local:test");
                assert_eq!(
                    attributes.iter().map(|item| item.id).collect::<Vec<_>>(),
                    [assigned]
                );
                reply(
                    &mut issue,
                    ipc::Response::Ticket {
                        rid,
                        ticket: Some(Ticket::new(b"mock-ticket")?),
                        uri: None,
                        presentations: PresentationList::empty(),
                    },
                )
                .await?;
                let (mut tickets, _) = service_listener.accept().await?;
                let frame = request(&mut tickets).await?;
                let ipc::Request::IterateStart {
                    rid,
                    kind: ipc::Iteration::Tickets,
                    ..
                } = ipc::Request::decode(&frame)?
                else {
                    return Err("ticket listing did not follow issuance".into());
                };
                reply(
                    &mut tickets,
                    ipc::Response::Ticket {
                        rid,
                        ticket: None,
                        uri: None,
                        presentations: PresentationList::empty(),
                    },
                )
                .await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            let mut output = Vec::new();
            let command = execute_actions(
                &plan.commands,
                &plan.ego,
                EndpointSource::unix(service_path),
                Some(EndpointSource::unix(identity_path)),
                OutputMode::Text,
                &mut output,
            );
            let (identity_result, reclaim_result, command_result) =
                tokio::time::timeout(Duration::from_secs(3), async {
                    tokio::join!(original_identity, reclaim, command)
                })
                .await?;
            identity_result?;
            reclaim_result?;
            command_result?;
            assert_eq!(output, b"mock-ticket\n");
            Ok(())
        })
}
