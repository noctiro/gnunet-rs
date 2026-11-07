use crate::{Error, ipc};
use gnunet_types::Error as Fault;
use std::{
    fmt, io,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use zeroize::Zeroizing;
/// Stable caller-owned domain for bounded independent registrations/queries.
/// Allocation IDs never wrap or bind old tokens to a future source.
#[derive(Debug, Default)]
pub struct Instance {
    next: AtomicU64,
}
impl Instance {
    /// Fresh native domain; opens no socket, runtime, Resolver or task.
    pub const fn new() -> Self {
        Self {
            next: AtomicU64::new(0),
        }
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Brand<'id> {
    owner: &'id Instance,
    allocation: u64,
}
impl<'id> Brand<'id> {
    pub fn new(owner: &'id Instance) -> Result<Self, Fault> {
        let old = owner
            .next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Fault::Overflow)?;
        Ok(Self {
            owner,
            allocation: old.checked_add(1).ok_or(Fault::Overflow)?,
        })
    }
    pub fn owns(self, b: Self) -> bool {
        std::ptr::eq(self.owner, b.owner) && self.allocation == b.allocation
    }
}
macro_rules! token {
    ($name:ident,$doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Copy)]
        pub struct $name<'id> {
            pub(crate) brand: Brand<'id>,
            pub(crate) serial: u64,
        }
        impl PartialEq for $name<'_> {
            fn eq(&self, o: &Self) -> bool {
                self.brand.owns(o.brand) && self.serial == o.serial
            }
        }
        impl Eq for $name<'_> {}
        impl fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&self.brand.allocation)
                    .field(&self.serial)
                    .finish()
            }
        }
        impl $name<'_> {
            /// Diagnostic allocation/serial only; cannot reconstruct authority.
            pub const fn diagnostic(self) -> (u64, u64) {
                (self.brand.allocation, self.serial)
            }
        }
    };
}
token!(
    Session,
    "One original NAT registration or NATauto query, never a wire RID."
);
token!(
    Epoch,
    "One actually attached original physical MQ, never a future reconnect."
);
token!(
    WriteId,
    "One original immutable FIFO request, never a wire request ID."
);
token!(
    AddressId,
    "One original address-add allocation; duplicates remain distinct."
);
/// Exact local producer ABI choices. Neither native family nor endian is guessed
/// from received bytes. The global-length defect uses the request profile too.
#[derive(Clone, Copy, Debug)]
pub struct Profiles {
    /// ABI of client-produced REGISTER/STUN/reversal/global messages.
    pub request: ipc::Profile,
    /// ABI of actual service-produced notifications.
    pub response: ipc::Profile,
}
impl Profiles {
    /// Use one explicitly selected ABI in both directions.
    pub const fn same(profile: ipc::Profile) -> Self {
        Self {
            request: profile,
            response: profile,
        }
    }
}
/// Original canonical targets. Every finite operation retains its native hard
/// bound; only an idle Registration observer may omit the overall source limit.
#[derive(Clone, Copy, Debug)]
pub struct Deadlines {
    /// Complete REGISTER/query local send bound; must remain finite.
    pub send_until: u64,
    /// Optional finite first actual notification/result bound; silence is inconclusive.
    pub first_input_until: Option<u64>,
    /// Original complete session/query lifetime. MAX permits a long-lived
    /// Registration observer only; AutoQuery still requires a finite deadline.
    pub until: u64,
}
/// Independent finite memory/frame resources. No global/native default is selected.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Retained pending original writes, including REGISTER/query.
    pub writes: usize,
    /// Aggregate immutable source frames (physical FIFO included once).
    pub source_bytes: usize,
    /// Maximum complete official frame.
    pub frame_bytes: usize,
    /// Maximum live duplicate address allocations.
    pub addresses: usize,
    /// Syscall byte slice; partial cursors remain original.
    pub io_slice_bytes: usize,
    /// Allocation retry sleep; bounded original deadlines still run first.
    pub capacity_retry: Duration,
    /// For a Registration with no overall deadline, finite first-byte-to-release
    /// budget per original input frame/held notification. It never renews on
    /// later bytes or polls. Finite-overall sources retain their original bounds.
    pub input_lifetime: Duration,
    /// For a Registration with no overall deadline, independent native maximum
    /// for initial REGISTER and each follow-up write. Captured before its clock
    /// sample, it cannot grow when the caller's absolute target spans rollback.
    /// Finite-overall sources retain their original overall/write semantics.
    pub write_lifetime: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            writes: 32,
            source_bytes: 256 * 1024,
            frame_bytes: 65535,
            addresses: 256,
            io_slice_bytes: 65535,
            capacity_retry: Duration::from_millis(100),
            input_lifetime: Duration::from_secs(30),
            write_lifetime: Duration::from_secs(30),
        }
    }
}
impl Limits {
    pub(crate) fn validate(self) -> Result<(), Fault> {
        if self.writes == 0
            || self.writes > 4096
            || self.source_bytes < 4
            || self.frame_bytes < 40
            || self.frame_bytes > 65535
            || self.addresses > 65536
            || self.io_slice_bytes == 0
            || self.capacity_retry.is_zero()
            || self.input_lifetime.is_zero()
            || self.write_lifetime.is_zero()
            || u64::try_from(self.input_lifetime.as_micros()).is_err()
            || std::time::Instant::now()
                .checked_add(self.input_lifetime)
                .is_none()
            || std::time::Instant::now()
                .checked_add(self.write_lifetime)
                .is_none()
            || std::time::Instant::now()
                .checked_add(self.capacity_retry)
                .is_none()
        {
            return Err(Fault::Capacity);
        }
        Ok(())
    }
}
/// Actual local byte exposure, never processing/registration success or NAT truth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Submission {
    /// No original byte written.
    Unsent,
    /// Original positive prefix only; processing outcome is unknown.
    Partial {
        /// Actual cumulative bytes.
        bytes: usize,
        /// Original full frame size.
        total: usize,
    },
    /// Actual whole local write; no protocol ACK exists.
    Written {
        /// Original full bytes.
        bytes: usize,
    },
}
/// Actual immutable request family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    /// Original REGISTER.
    Register,
    /// Forwarded original STUN datagram.
    Stun,
    /// Original IPv4 reversal request.
    Reverse,
    /// Original textual global-address proposal.
    AddGlobal,
    /// Original NATauto serialized configuration request.
    AutoQuery,
}
/// Original local write retirement; no fabricated service status is included.
#[derive(Clone, Copy, Debug)]
pub struct WriteEnd<'id> {
    /// Exact original request.
    pub write: WriteId<'id>,
    /// Its actual command family.
    pub command: Command,
    /// Exact original byte exposure.
    pub submission: Submission,
}
/// Original physical source termination. No variant fabricates a remote refusal.
#[derive(Debug)]
pub enum Cause {
    /// Explicit close.
    Closed,
    /// Explicit original cancellation.
    Cancelled,
    /// Original complete-session deadline.
    Deadline,
    /// Original send/write deadline.
    WriteDeadline,
    /// Original optional first-input bound; no no-match/NAT inference.
    FirstInputDeadline,
    /// Actual native EOF.
    Eof,
    /// Original first-byte input/held-notification budget expired on a
    /// long-lived observer. This is source retirement, not an IPC delete/ACK.
    InputDeadline,
    /// Actual native I/O errno.
    Io(io::Error),
    /// Exact protocol/capacity fault.
    Protocol(Fault),
    /// Original canonical clock failure.
    Clock(Fault),
    /// Exact CLIENT/config/Resolver refusal.
    Ports(gnunet_client_host::ConnectError),
    /// Exact enclosing native error, original owner already stopped.
    Error(Error),
}
/// Actual physical close receipt. Underlying Drop provides no close errno; none
/// is invented. Outstanding writes keep exact original source/byte state.
#[derive(Debug)]
pub struct SourceEnd<'id> {
    /// Original session/job.
    pub session: Session<'id>,
    /// Original actual MQ if one attached.
    pub epoch: Option<Epoch<'id>>,
    /// Exact original cause.
    pub cause: Cause,
    /// Original write responsible for retirement, when applicable.
    pub trigger: Option<WriteId<'id>>,
    /// Actual REGISTER/query byte state.
    pub initial: Submission,
    /// Original incomplete/pending writes, in original order.
    pub writes: Vec<WriteEnd<'id>>,
}
/// Original address row. Raw native bytes are erased when its owner retires.
pub struct AddressEntry<'id> {
    pub(crate) id: AddressId<'id>,
    pub(crate) epoch: Epoch<'id>,
    pub(crate) class: ipc::AddressClass,
    pub(crate) raw: Zeroizing<[u8; 28]>,
    pub(crate) len: usize,
    pub(crate) profile: ipc::Profile,
}
impl fmt::Debug for AddressEntry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NatAddress")
            .field("id", &self.id)
            .field("epoch", &self.epoch)
            .field("class", &self.class)
            .field("native_bytes", &"[REDACTED]")
            .finish()
    }
}
impl<'id> AddressEntry<'id> {
    /// Original allocation, suitable for caller-owned app context.
    pub const fn id(&self) -> AddressId<'id> {
        self.id
    }
    /// Original physical source.
    pub const fn epoch(&self) -> Epoch<'id> {
        self.epoch
    }
    /// Original add-time class bits.
    pub const fn class(&self) -> ipc::AddressClass {
        self.class
    }
    /// Exact original native bytes, including padding and scope.
    pub fn address(&self) -> Result<ipc::RawAddress<'_>, Fault> {
        ipc::RawAddress::decode(&self.raw[..self.len], self.profile)
    }
}
/// One registration physical retirement, distinct from service remove callbacks.
#[derive(Debug)]
pub struct End<'id> {
    /// Actual original source termination.
    pub source: SourceEnd<'id>,
    /// Original unreleased callback, if any. Consume it before retiring its app
    /// context; it remains historical and cannot bind to a new registration.
    pub notification: Option<crate::OwnedNotification<'id>>,
    /// All still-live original address/app-context allocations, now retired.
    pub addresses: Vec<AddressEntry<'id>>,
}
/// Local cancellation observation; no wire CANCEL/ACK exists.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "Original physical-close receipts transfer bounded existing callback/cache owners without allocating after cancellation"
)]
pub enum Cancel<'id> {
    /// Original zero-exposure write was removed from its original FIFO.
    Unsent(WriteEnd<'id>),
    /// Exposed/initial cancellation physically closed the entire registration MQ.
    SessionClosed(End<'id>),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Pure public metadata assertions delimit the allocation-brand model; no native or cryptographic operation occurs"
    )]
    fn checked_allocations_do_not_rebind_original_native_tokens() -> Result<(), Fault> {
        let caller = Instance::new();
        let a = Brand::new(&caller)?;
        let b = Brand::new(&caller)?;
        let old = Session {
            brand: a,
            serial: 0,
        };
        let new = Session {
            brand: b,
            serial: 0,
        };
        assert_ne!(old, new);
        assert!(!old.brand.owns(new.brand));
        assert_ne!(
            WriteId {
                brand: a,
                serial: 1
            },
            WriteId {
                brand: b,
                serial: 1
            }
        );
        assert_ne!(
            AddressId {
                brand: a,
                serial: 1
            },
            AddressId {
                brand: b,
                serial: 1
            }
        );
        let other = Instance::new();
        let independent = Brand::new(&other)?;
        assert_ne!(
            Session {
                brand: a,
                serial: 0
            },
            Session {
                brand: independent,
                serial: 0
            }
        );
        Ok(())
    }
}
