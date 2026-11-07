//! First observed authenticated namespace selection with original signed lineage.
use crate::network::tree_download::{
    TreeDownloadOptions, TreeDownloadProgress, namespace::checkpoint,
};
use crate::search::{self, proof::NamespaceSelection};
use crate::{Control, Error};
use gnunet_client_host::EndpointSource;
use gnunet_fs::{Namespace, Uri};
use gnunet_types::AbsoluteTime;
use std::time::Duration;

pub(super) async fn select(
    source: &EndpointSource,
    namespace: Namespace<'_>,
    options: TreeDownloadOptions,
    progress: TreeDownloadProgress,
    last: &mut Option<AbsoluteTime>,
    control: &mut impl FnMut(TreeDownloadProgress) -> Control,
    cleanup: &mut Option<search::Error>,
) -> Result<NamespaceSelection, Error> {
    let mut identities: [crate::ipc::Instance; 64] =
        std::array::from_fn(|_| crate::ipc::Instance::new());
    let policy = search::Options {
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
    let mut session = search::Session::<_, 32>::new_with_namespace_proof(
        Uri::Namespace(namespace),
        &mut identities,
        || source.duplicate(),
        policy,
    )?;
    let selected = async {
        loop {
            checkpoint(source, options.transfer.deadline, last, progress, control)?;
            match session
                .drive(Some(
                    tokio::time::Instant::now() + Duration::from_millis(50),
                ))
                .await?
            {
                search::Step::Result { result } | search::Step::Update { result } => {
                    if matches!(
                        session
                            .result(result)
                            .ok_or(Error::Corrupt)?
                            .uri(options.directory.uri)?,
                        Uri::Content(_) | Uri::Location(_)
                    ) {
                        return Ok(result);
                    }
                }
                search::Step::Failed { cause, .. } => {
                    return Err(Error::from(search::Error::Transport(cause)));
                }
                _ => {}
            }
        }
    }
    .await;
    match selected {
        Ok(result) => session
            .finish_namespace_selection(result)
            .map_err(Error::from),
        Err(error) => {
            *cleanup = session.cancel().err();
            Err(error)
        }
    }
}
