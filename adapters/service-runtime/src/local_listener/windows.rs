//! Windows original-node ACL and bounded stale-probe ownership before listen.
use super::PreparedLocalListener;
use crate::local::Stream;
use gnunet_native::{
    local_path::{
        EndpointAccess, EndpointPrincipals, ListenerBinding, LocalPath, ObservedLocalPath,
        validate_parent,
    },
    process::PrimaryToken,
};
use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};

const PROBE_LIMIT: Duration = Duration::from_secs(5);

struct StaleNode(ObservedLocalPath);
impl StaleNode {
    fn after_probe(original: ObservedLocalPath, probe: io::Result<()>) -> io::Result<Self> {
        match probe {
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                original.verify_current()?;
                Ok(Self(original))
            }
            Ok(()) => Err(io::ErrorKind::AddrInUse.into()),
            Err(error) => Err(error),
        }
    }

    fn reclaim(mut self) -> io::Result<()> {
        self.0.verify_current()?;
        self.0.remove()
    }
}

fn inspect(path: &Path) -> io::Result<Option<ObservedLocalPath>> {
    match LocalPath::inspect(path.to_owned()) {
        Ok(old) => Ok(Some(old)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn listen(
    binding: ListenerBinding,
    stale: Option<StaleNode>,
    backlog: i32,
) -> io::Result<PreparedLocalListener> {
    if let Some(stale) = stale {
        stale.reclaim()?;
    }
    let listener = binding.listen(backlog)?;
    Ok(PreparedLocalListener { listener })
}

pub(super) async fn prepare(
    path: PathBuf,
    principals: EndpointPrincipals,
    backlog: i32,
) -> io::Result<PreparedLocalListener> {
    let binding = ListenerBinding::new(path, principals)?;
    binding.prepare_parents()?;
    let stale = if let Some(original) = inspect(binding.path())? {
        let probe = tokio::time::timeout(PROBE_LIMIT, Stream::connect(binding.path()))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)?
            .map(drop);
        Some(StaleNode::after_probe(original, probe)?)
    } else {
        None
    };
    listen(binding, stale, backlog)
}

/// A bind authorized by the selected target token, retaining any observed
/// stale node without cleanup authority on drop.
pub struct AccountBind {
    binding: ListenerBinding,
    stale: Option<StaleNode>,
}

impl AccountBind {
    /// Select Windows access and check liveness under the verified account.
    /// Run on the account worker, with namespace and ACL mutation excluded.
    /// This stage never creates directories, removes a node or listens.
    pub fn select(path: PathBuf, access: EndpointAccess, token: &PrimaryToken) -> io::Result<Self> {
        let binding = ListenerBinding::new(path, EndpointPrincipals::for_account(token, access)?)?;
        let stale = if let Some(original) = inspect(binding.path())? {
            validate_parent(binding.path())?;
            original.verify_current()?;
            let probe = token.probe_local(binding.path(), PROBE_LIMIT);
            Some(StaleNode::after_probe(original, probe)?)
        } else {
            None
        };
        Ok(Self { binding, stale })
    }

    /// Recheck the original path, reclaim any proven stale node, and install
    /// the selected token's ACL before listening. Call with the namespace
    /// still under the supervisor's control.
    pub fn listen(self, backlog: i32) -> io::Result<PreparedLocalListener> {
        self.binding.prepare_parents()?;
        listen(self.binding, self.stale, backlog)
    }
}
