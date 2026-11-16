//! Original operation outcomes and independent cleanup diagnostics.
use crate::{Failure, stream};
use gnunet_client::datastore::{Interruption, Kind};
use gnunet_datastore_host::{self as host, Completion, Outcome};
use std::io;
use zeroize::Zeroizing;
#[derive(Clone, Copy)]
pub(crate) struct Meta {
    pub(super) kind: Kind,
    pub(super) outcome: Outcome,
    pub(super) interruption: Option<Interruption>,
}
impl std::fmt::Debug for Meta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Completion")
            .field("kind", &self.kind)
            .field("outcome", &self.outcome)
            .field("interruption", &self.interruption)
            .finish()
    }
}
impl From<Completion<'_>> for Meta {
    fn from(c: Completion<'_>) -> Self {
        Self {
            kind: c.kind,
            outcome: c.outcome,
            interruption: c.interruption,
        }
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Report {
    pub(super) dumped: u64,
    pub(super) submitted: u64,
    pub(super) inserted: u64,
    pub(super) next_uid: u64,
    pub(super) last: Option<Meta>,
}
#[derive(Default)]
pub(super) struct Close {
    pub(super) native: Option<host::Error>,
    pub(super) take: Option<host::Error>,
    pub(super) completion: Option<Meta>,
}
impl std::fmt::Debug for Close {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientRetirement")
            .field("native", &self.native)
            .field("take", &self.take)
            .field("completion", &self.completion)
            .finish()
    }
}
#[derive(Debug)]
pub(super) struct Failed {
    pub(super) original: Option<Failure>,
    pub(super) client: Close,
    pub(super) resolver: Option<Failure>,
    pub(super) streams: stream::Cleanup,
    pub(super) logging: Option<io::Error>,
    pub(super) report: Report,
}
impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DATASTORE original={:?}; client={:?}; Resolver={:?}; stream cleanup={:?}; logger={:?}; counters={:?}",
            self.original, self.client, self.resolver, self.streams, self.logging, self.report
        )
    }
}
impl std::error::Error for Failed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| {
                self.client
                    .native
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
            .or_else(|| {
                self.client
                    .take
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
            .or(self.resolver.as_deref())
            .or_else(|| {
                self.streams
                    .first_error()
                    .map(|error| error as &dyn std::error::Error)
            })
            .or_else(|| self.logging.as_ref().map(|e| e as &dyn std::error::Error))
    }
}
#[derive(Debug)]
pub(super) struct Interrupted {
    pub(super) original: Failure,
    pub(super) client: Close,
    pub(super) report: Report,
}
impl std::fmt::Display for Interrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; original operation retirement={:?}; counters={:?}",
            self.original, self.client, self.report
        )
    }
}
impl std::error::Error for Interrupted {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.original)
    }
}
pub(super) struct Diagnostic(pub(super) Zeroizing<Vec<u8>>);
impl std::fmt::Debug for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Diagnostic")
            .field("length", &self.0.len())
            .field("bytes", &"[redacted]")
            .finish()
    }
}
#[derive(Debug)]
pub(super) struct RejectedStatus {
    pub(super) code: i32,
    pub(super) min_expiration: u64,
    pub(super) diagnostic: Option<Diagnostic>,
}
impl std::fmt::Display for RejectedStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "actual DATASTORE STATUS {} min_expiration={} diagnostic={:?}",
            self.code, self.min_expiration, self.diagnostic
        )
    }
}
impl std::error::Error for RejectedStatus {}
#[derive(Debug)]
pub(super) struct Lost(pub(super) host::Loss);
impl std::fmt::Display for Lost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "original DATASTORE source lost: {:?}", self.0)
    }
}
impl std::error::Error for Lost {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            host::Loss::Io(e) => Some(e),
            host::Loss::Protocol(e) => Some(e),
            _ => None,
        }
    }
}
