//! Source-bound query targets and privately assembled native observations.
use crate::{Epoch, Info};
use std::{io, net::IpAddr};
use tokio::time::Instant;
/// Immutable original query authority; no descriptor or route is kept alive.
#[derive(Clone, Debug)]
pub struct RouteQueryTarget {
    pub(crate) epoch: Epoch,
    pub(crate) table: Option<u32>,
    pub(crate) interface: Info,
    pub(crate) destination: IpAddr,
    pub(crate) prefix: u8,
    pub(crate) gateway: Option<IpAddr>,
    pub(crate) deadline: Instant,
}
impl RouteQueryTarget {
    /// Original Linux table or FreeBSD FIB, retained from the physical source.
    /// macOS uses scoped routes and Windows uses its qualified original port; both return None.
    #[must_use]
    pub const fn table(&self) -> Option<u32> {
        self.table
    }

    /// Original physical device generation.
    #[must_use]
    pub const fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    /// Original actual interface name/index.
    #[must_use]
    pub const fn interface(&self) -> &Info {
        &self.interface
    }
    /// Exact canonical requested network/address, never silently masked.
    #[must_use]
    pub const fn destination(&self) -> IpAddr {
        self.destination
    }
    /// Original prefix length.
    #[must_use]
    pub const fn prefix(&self) -> u8 {
        self.prefix
    }
    /// Original requested IP gateway, None means a direct interface route.
    #[must_use]
    pub const fn gateway(&self) -> Option<IpAddr> {
        self.gateway
    }
    /// Original finite native deadline, never reset by waits/progress.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }
}
/// Actual native route fields used for exact matching. Constructor is private;
/// caller configuration cannot be converted into a kernel-observed record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRecord {
    pub(crate) destination: IpAddr,
    pub(crate) prefix: u8,
    pub(crate) interface: u32,
    pub(crate) gateway: Option<IpAddr>,
    pub(crate) direct: bool,
    #[cfg(unix)]
    pub(crate) flags: u32,
    #[cfg(windows)]
    pub(crate) windows_protocol: (i32, i32),
    pub(crate) table: Option<u32>,
    pub(crate) kind: Option<u8>,
    pub(crate) scope: Option<u8>,
    pub(crate) protocol: Option<u8>,
    pub(crate) metric: Option<u32>,
    pub(crate) unsupported: bool,
}
impl RouteRecord {
    /// Actual returned canonical route destination.
    #[must_use]
    pub const fn destination(&self) -> IpAddr {
        self.destination
    }
    /// Actual returned prefix.
    #[must_use]
    pub const fn prefix(&self) -> u8 {
        self.prefix
    }
    /// Actual native output interface, zero only when kernel supplied none.
    #[must_use]
    pub const fn interface(&self) -> u32 {
        self.interface
    }
    /// Actual IP gateway; direct status is separate so an unsupported gateway
    /// cannot accidentally masquerade as a direct interface route.
    #[must_use]
    pub const fn gateway(&self) -> Option<IpAddr> {
        self.gateway
    }
    /// Kernel record uses supported direct-interface gateway semantics.
    #[must_use]
    pub const fn direct(&self) -> bool {
        self.direct
    }
    /// Actual Unix route flags. Windows has protocol/origin values instead.
    #[must_use]
    pub const fn flags(&self) -> Option<u32> {
        #[cfg(unix)]
        {
            Some(self.flags)
        }
        #[cfg(windows)]
        {
            None
        }
    }
    /// Actual Windows native protocol and origin, in that order. Unix returns None.
    #[must_use]
    pub const fn windows_protocol(&self) -> Option<(i32, i32)> {
        #[cfg(unix)]
        {
            None
        }
        #[cfg(windows)]
        {
            Some(self.windows_protocol)
        }
    }
    /// Actual Linux table or FreeBSD FIB; macOS/Windows use their qualified native scope.
    #[must_use]
    pub const fn table(&self) -> Option<u32> {
        self.table
    }
    /// Actual Netlink RTN_* type, when applicable.
    #[must_use]
    pub const fn kind(&self) -> Option<u8> {
        self.kind
    }
    /// Actual Netlink RT_SCOPE_* value, when applicable.
    #[must_use]
    pub const fn scope(&self) -> Option<u8> {
        self.scope
    }
    /// Actual Netlink RTPROT_* value, never treated as proof of our ownership.
    #[must_use]
    pub const fn protocol(&self) -> Option<u8> {
        self.protocol
    }
    /// Actual native route metric; Windows reports the route metric offset.
    #[must_use]
    pub const fn metric(&self) -> Option<u32> {
        self.metric
    }
    /// Native route style is outside supported plain interface/IP-gateway matching.
    #[must_use]
    pub const fn unsupported(&self) -> bool {
        self.unsupported
    }
}
/// Honest reason a read-only result could not be established.
#[derive(Debug)]
pub enum RouteQueryProblem {
    /// Original TUN epoch/name/index retired; never retry on a fresh source.
    SourceRetired,
    /// Original finite query lifetime elapsed.
    Deadline,
    /// Caller explicitly canceled this original query.
    Cancelled,
    /// Actual native errno or checked malformed/truncated/overrun response.
    Kernel(io::Error),
    /// Exact route key has multiple kernel records; no arbitrary first row wins.
    Ambiguous {
        /// Actual matching key records observed in the complete dump.
        records: usize,
    },
    /// Fixed original datagram/byte inventory bound was exceeded.
    Capacity,
}
/// Actual native outcome, bound to its privately constructed completion target.
#[derive(Debug)]
pub enum RouteQueryOutcome {
    /// Canonical network/prefix/OIF/gateway/type/table requirements all matched.
    /// This is observation only and never grants delete/ownership authority.
    Exact(RouteRecord),
    /// Complete actual kernel query proved no requested key in the queried scope.
    Absent,
    /// Kernel supplied a route with different relevant actual fields, including
    /// a broader-prefix fallback on macOS. It is never treated as Exact.
    Different(RouteRecord),
    /// Source/deadline/native/protocol/ambiguity failure, never invented absence.
    Unknown(RouteQueryProblem),
}
/// Actual complete kernel read protocol evidence; local writing is insufficient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteQueryEvidence {
    /// An exact Windows native read returned after original interface/family
    /// qualification. This has no socket sequence or multipart completion.
    WindowsNativeReturn,
    /// Matching Linux multipart dump completed without error/interruption.
    LinuxDump,
    /// Matching FreeBSD multipart FIB dump completed without error/interruption.
    FreeBsdDump,
    /// Matching macOS native RTM_GET reply, including actual native ESRCH absence.
    MacRouteReply,
}
/// Actual exposure of the immutable read-only request, separate from its reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteQuerySubmission {
    /// No query bytes admitted.
    Unsent,
    /// The synchronous native query path was entered. No socket bytes or
    /// corresponding ACK sequence exist for this backend.
    NativeCall,
    /// Complete original query frame was written; no route result implied.
    Whole {
        /// Actual complete native bytes.
        bytes: usize,
    },
    /// Positive short query write; suffix is never retried.
    Partial {
        /// Actual native bytes.
        bytes: usize,
    },
    /// Native write error; original query admission is uncertain.
    Unknown,
}
/// Actual original query settlement. Private fields prevent forging a success
/// receipt or transplanting a RouteRecord onto an unrelated fresh Epoch.
#[derive(Debug)]
pub struct RouteQueryCompletion {
    pub(crate) target: RouteQueryTarget,
    pub(crate) outcome: RouteQueryOutcome,
    pub(crate) submission: RouteQuerySubmission,
    pub(crate) evidence: Option<RouteQueryEvidence>,
    pub(crate) kernel_errno: Option<i32>,
    pub(crate) observed_at: Instant,
    pub(crate) close_error: Option<io::Error>,
    pub(crate) write_error: Option<io::Error>,
}
impl RouteQueryCompletion {
    /// Exact original source/query/deadline.
    #[must_use]
    pub const fn target(&self) -> &RouteQueryTarget {
        &self.target
    }
    /// Actual result, never proof of ownership or permanent route state.
    #[must_use]
    pub const fn outcome(&self) -> &RouteQueryOutcome {
        &self.outcome
    }
    /// Actual original query exposure.
    #[must_use]
    pub const fn submission(&self) -> RouteQuerySubmission {
        self.submission
    }
    /// Complete actual native reply evidence, absent on local/unknown settlement.
    #[must_use]
    pub const fn evidence(&self) -> Option<RouteQueryEvidence> {
        self.evidence
    }
    /// Native errno for a genuine expected absence reply, when supplied.
    #[must_use]
    pub const fn kernel_errno(&self) -> Option<i32> {
        self.kernel_errno
    }
    /// Terminal observation time; a late result is classified Unknown Deadline.
    #[must_use]
    pub const fn observed_at(&self) -> Instant {
        self.observed_at
    }
    /// Actual original write errno, retained even if a correlated error reply
    /// later establishes genuine native absence.
    #[must_use]
    pub const fn write_error(&self) -> Option<&io::Error> {
        self.write_error.as_ref()
    }
    /// Independent actual query socket close errno, never retried.
    #[must_use]
    pub const fn close_error(&self) -> Option<&io::Error> {
        self.close_error.as_ref()
    }
}
/// One bounded caller-driven read-only native action.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "One bounded original terminal kernel receipt stays by value so reporting a completed native operation cannot require another fallible heap allocation"
)]
pub enum RouteQueryProgress {
    /// Native query write returned an error; original admission may have
    /// occurred synchronously. Await its original reply/deadline without retry.
    WriteError,
    /// Complete original query entered kernel; no successful Get implied.
    Submitted {
        /// Actual written native bytes.
        bytes: usize,
    },
    /// One bounded native datagram was consumed while awaiting original completion.
    Activity {
        /// Actual read bytes.
        bytes: usize,
    },
    /// Original query socket physically closed and its actual result retained.
    Complete(RouteQueryCompletion),
    /// Caller wait ended; original query and its deadline remain retained.
    WaitDeadline,
    /// Original result was already consumed.
    Finished,
}
