//! Original-clock control and real authenticated SKS resolution.
use super::{TreeDownloadOptions, TreeDownloadProgress};
use crate::{Control, Error, Result};
use gnunet_client_host::EndpointSource;
use gnunet_fs::{Content, Namespace, Uri};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use std::time::Duration;
pub(crate) fn checkpoint(
    source: &EndpointSource,
    deadline: AbsoluteTime,
    last: &mut Option<AbsoluteTime>,
    progress: TreeDownloadProgress,
    control: &mut impl FnMut(TreeDownloadProgress) -> Control,
) -> Result<()> {
    let now = source.clock().sample()?.now;
    if last.is_some_and(|previous| now < previous) {
        return Err(ProtocolError::TimeUncertain.into());
    }
    *last = Some(now);
    if now >= deadline {
        return Err(ProtocolError::Deadline.into());
    }
    if control(progress) == Control::Cancel {
        return Err(Error::Cancelled);
    }
    Ok(())
}

pub(super) async fn resolve_namespace(
    source: &EndpointSource,
    namespace: Namespace<'_>,
    options: TreeDownloadOptions,
    progress: TreeDownloadProgress,
    last: &mut Option<AbsoluteTime>,
    control: &mut impl FnMut(TreeDownloadProgress) -> Control,
    cleanup: &mut Option<crate::search::Error>,
) -> Result<(Content, [u8; 32])> {
    let mut identities: [crate::ipc::Instance; 64] =
        std::array::from_fn(|_| crate::ipc::Instance::new());
    let policy = crate::search::Options {
        anonymity: options.transfer.anonymity,
        local_only: options.transfer.local_only,
        deadline: options.transfer.deadline,
        limits: options.namespace,
        block: gnunet_fs::ublock::Limits {
            uri: options.directory.uri,
            ..Default::default()
        },
        protocol: Default::default(),
        native: Default::default(),
    };
    let mut session = crate::search::Session::<_, 32>::new(
        Uri::Namespace(namespace),
        &mut identities,
        || source.duplicate(),
        policy,
    )?;
    let result = async {
        loop {
            checkpoint(source, options.transfer.deadline, last, progress, control)?;
            match session
                .drive(Some(
                    tokio::time::Instant::now() + Duration::from_millis(50),
                ))
                .await?
            {
                crate::search::Step::Result { result } | crate::search::Step::Update { result } => {
                    match session
                        .result(result)
                        .ok_or(Error::Corrupt)?
                        .uri(options.directory.uri)?
                    {
                        Uri::Content(c) => return Ok((c, [0; 32])),
                        Uri::Location(loc) => return Ok((loc.content(), *loc.peer().as_bytes())),
                        _ => {}
                    }
                }
                crate::search::Step::Failed { cause, .. } => {
                    return Err(crate::search::Error::Transport(cause).into());
                }
                _ => {}
            }
        }
    }
    .await;
    let retirement = session.cancel().err();
    match (result, retirement) {
        (Err(error), retirement) => {
            *cleanup = retirement;
            Err(error)
        }
        (Ok(_), Some(error)) => Err(error.into()),
        (Ok(resolved), None) => Ok(resolved),
    }
}
