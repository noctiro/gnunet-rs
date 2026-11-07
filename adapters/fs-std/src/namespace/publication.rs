//! Bind real single-label native acceptance to local namespace update bookkeeping.
use super::{
    graph::{self, Graph, Prepared, Record, RecordId},
    key::{self, KeyFile},
};
use crate::network::ublock::{PublishedUblocks, UblockFailure, UblockOptions, UblockProgress};
use crate::{Buffers, Control};
use gnunet_datastore_host::Client;
use gnunet_fs::{Uri, metadata};
use gnunet_types::Error as ProtocolError;
use std::fmt;

/// An actual acknowledged namespace publication with its local graph disposition.
pub struct PublishedNamespace {
    /// Original accepted STATUS bytes, exact metadata selection and native cleanup.
    pub publication: PublishedUblocks,
    /// Original update-graph record; None means the caller supplied no update.
    pub record: Option<RecordId>,
}
/// Actual nonnegative PUT STATUS acceptance whose independent local graph barrier failed.
/// Keep this value to retry only graph bookkeeping after reopening the original
/// graph; no method here submits a DATASTORE request.
pub struct AcceptedPending {
    /// Complete real accepted publication, including independent MQ cleanup.
    pub publication: PublishedUblocks,
    update: Prepared,
}
impl AcceptedPending {
    /// Original exact selected metadata and labels awaiting local recording.
    #[must_use]
    pub fn update(&self) -> &Prepared {
        &self.update
    }
    /// Reconcile the original graph record only. An already complete identical
    /// original WAL record is confirmed without appending another record or PUT.
    pub fn record(self, graph: &mut Graph) -> Result<PublishedNamespace, Box<Failure>> {
        match graph.append_accepted(&self.update) {
            Ok(id) => Ok(PublishedNamespace {
                publication: self.publication,
                record: Some(id),
            }),
            Err(error) => Err(Box::new(Failure {
                cause: FailureCause::Graph(error),
                accepted: Some(self),
                retirement_error: None,
            })),
        }
    }
}
/// The original refusal, independently of acknowledged publication facts.
#[derive(Debug)]
pub enum FailureCause {
    /// Selected key-file authority, bytes, permissions or durability refusal.
    Key(key::Error),
    /// Local namespace binding, graph budget or original WAL failure.
    Graph(graph::Error),
    /// Actual native single-label publication error and retained original reply.
    Publication(Box<UblockFailure>),
    /// Explicit caller resource or checked representation refusal.
    Protocol(ProtocolError),
    /// The caller's actual selected official metadata could not be encoded.
    Metadata(metadata::Error),
}
impl fmt::Display for FailureCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(e) => e.fmt(f),
            Self::Graph(e) => e.fmt(f),
            Self::Publication(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::Metadata(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for FailureCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Key(e) => Some(e),
            Self::Graph(e) => Some(e),
            Self::Publication(e) => Some(e.as_ref()),
            Self::Protocol(e) => Some(e),
            Self::Metadata(e) => Some(e),
        }
    }
}
/// Complete publication failure. A graph error cannot erase an actual nonnegative PUT STATUS,
/// and local preflight failure retains the consumed client's retirement error.
pub struct Failure {
    /// Original native, key, artifact or graph refusal.
    pub cause: FailureCause,
    /// Present only after actual publication acceptance; never a speculative ACK.
    pub accepted: Option<AcceptedPending>,
    /// Independent dedicated-client retirement after local preflight refusal.
    pub retirement_error: Option<gnunet_client_host::ConnectError>,
}
impl fmt::Debug for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NamespacePublicationFailure")
            .field("cause", &self.cause)
            .field("accepted", &self.accepted.as_ref().map(|a| &a.publication))
            .field("retirement_error", &self.retirement_error)
            .finish()
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.accepted.is_some() {
            write!(
                f,
                "namespace publication accepted; graph recording failed: "
            )?;
        }
        self.cause.fmt(f)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
impl Buffers {
    /// Publish through the original single-label owner, then record only an
    /// actual accepted update. `None` and `Some(b"")` have the same wire update
    /// but different local bookkeeping: only Some creates a graph record.
    ///
    /// Metadata is the exact explicit Plan selection sent on the wire, not an
    /// unselected caller container. An ACK-to-journal process crash can leave a
    /// missing graph entry; this immediate API is not a publication task journal.
    #[expect(
        clippy::too_many_arguments,
        reason = "Managed key, graph, publication fields and actual native policy remain explicit"
    )]
    pub async fn store_managed_namespace<'id>(
        &mut self,
        mut store: Client<'id, '_, '_>,
        key: &KeyFile,
        graph: &mut Graph,
        identifier: &[u8],
        update: Option<&[u8]>,
        uri: Uri<'_>,
        metadata: Option<&metadata::Plan<'_>>,
        options: UblockOptions,
        control: impl FnMut(UblockProgress) -> Control,
    ) -> Result<PublishedNamespace, Box<Failure>> {
        let prepared = (|| -> Result<Option<Prepared>, FailureCause> {
            if graph.namespace() != &key.public_key() {
                return Err(FailureCause::Protocol(ProtocolError::InvalidInput));
            }
            key.revalidate().map_err(FailureCause::Key)?;
            let Some(update) = update else {
                return Ok(None);
            };
            let encoded = metadata
                .map(|plan| {
                    let mut bytes = Vec::new();
                    bytes
                        .try_reserve_exact(plan.report().wire_bytes)
                        .map_err(|_| FailureCause::Protocol(ProtocolError::Capacity))?;
                    bytes.resize(plan.report().wire_bytes, 0);
                    plan.write(&mut bytes).map_err(FailureCause::Metadata)?;
                    Ok::<_, FailureCause>(bytes)
                })
                .transpose()?;
            graph
                .prepare(Record {
                    identifier,
                    update,
                    uri,
                    metadata: encoded.as_deref(),
                })
                .map(Some)
                .map_err(FailureCause::Graph)
        })();
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(cause) => {
                return Err(Box::new(Failure {
                    cause,
                    accepted: None,
                    retirement_error: store.close().err(),
                }));
            }
        };
        let publication = self
            .store_namespace(
                store,
                key.secret(),
                identifier,
                update.unwrap_or_default(),
                uri,
                metadata,
                options,
                control,
            )
            .await
            .map_err(|error| {
                Box::new(Failure {
                    cause: FailureCause::Publication(error),
                    accepted: None,
                    retirement_error: None,
                })
            })?;
        match prepared {
            None => Ok(PublishedNamespace {
                publication,
                record: None,
            }),
            Some(update) => AcceptedPending {
                publication,
                update,
            }
            .record(graph),
        }
    }
}
