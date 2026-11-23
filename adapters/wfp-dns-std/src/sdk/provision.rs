//! Explicit persistent driver metadata installation under an ordinary FWPM session.
use super::super::{
    contract::{self, CALLOUTS, Callout, same_guid},
    error::{Cleanup, NativeFailure},
};
use std::{
    ffi::c_void,
    fmt,
    marker::PhantomData,
    ptr::{self, NonNull},
    rc::Rc,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::HANDLE, NetworkManagement::WindowsFilteringPlatform as api,
    System::Rpc::RPC_C_AUTHN_WINNT,
};

const MARKER: &[u8] = b"GNUnet DNS WFP metadata\x01";
const BINDING_BYTES: usize = MARKER.len() + 32 + 1;

/// Native BFE transaction-lock wait bound for explicit metadata provisioning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvisionLimits {
    /// Time allowed to acquire the transaction lock, 1ms through 30s.
    /// This is not an RPC deadline or a native callback-retirement bound.
    pub transaction_wait: Duration,
}
impl Default for ProvisionLimits {
    fn default() -> Self {
        Self {
            transaction_wait: Duration::from_secs(2),
        }
    }
}
impl ProvisionLimits {
    fn wait_millis(self) -> Result<u32, Error> {
        if !(Duration::from_millis(1)..=Duration::from_secs(30)).contains(&self.transaction_wait) {
            return Err(Error::InvalidLimits);
        }
        u32::try_from(self.transaction_wait.as_millis()).map_err(|_| Error::InvalidLimits)
    }
}

/// Stable installation identity, independent of BFE's replaceable numeric IDs.
/// Persist this receipt separately for explicit later removal. It is a metadata
/// binding, not a permission token; native access checks still apply.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InstallationReceipt {
    nonce: [u8; 32],
}
impl InstallationReceipt {
    /// Prepare an installation identity before opening or changing BFE.
    ///
    /// # Errors
    /// Returns the original platform entropy failure.
    pub fn generate() -> std::io::Result<Self> {
        let mut nonce = [0; 32];
        gnunet_native::entropy::fill(&mut nonce)?;
        Ok(Self::from_nonce(nonce))
    }

    /// Recover an explicitly persisted installation receipt without native effects.
    #[must_use]
    pub const fn from_nonce(nonce: [u8; 32]) -> Self {
        Self { nonce }
    }
    /// Export the exact stable nonce for the installer's own receipt storage.
    #[must_use]
    pub const fn nonce(self) -> [u8; 32] {
        self.nonce
    }
}
impl fmt::Debug for InstallationReceipt {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("InstallationReceipt")
            .finish_non_exhaustive()
    }
}

/// Persistent metadata verified in one complete native transaction.
#[derive(Debug)]
#[must_use]
pub struct Installed {
    /// Stable nonce to retain for verified removal, including after BFE restart.
    pub receipt: InstallationReceipt,
    /// Callout IDs queried in the committed transaction, in canonical order.
    /// These are observations, not stable installation or driver capabilities.
    pub callout_ids: [u32; CALLOUTS.len()],
}

/// Static object whose queried shape refused an installation receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Object {
    /// The canonical driver metadata provider.
    Provider,
    /// One canonical ALE or datagram callout.
    Callout(Callout),
}

/// Why existing static metadata could not be treated as this installation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Problem {
    /// A fixed key or returned callout identity was different.
    Identity,
    /// The expected provider reference was absent or different.
    Provider,
    /// The callout referenced another native filtering layer.
    Layer,
    /// Persistence or provider-context flags differed from the installed shape.
    Flags,
    /// Version, nonce or object-role bytes did not match the supplied receipt.
    Binding,
    /// The provider was associated with an unexpected Windows service.
    Service,
}

/// Installer validation, catalog or original native failure.
#[derive(Debug)]
pub enum Error {
    /// Transaction wait is outside the explicit supported range.
    InvalidLimits,
    /// This original engine was closed, or its one close attempt failed.
    Closed,
    /// A failed abort left an original transaction unsettled.
    TransactionUncertain,
    /// An original FWPM call returned its exact nonzero DWORD.
    Native(NativeFailure),
    /// A successful SDK call omitted its required output.
    MissingOutput(&'static str),
    /// An existing object's complete ownership-relevant shape did not match.
    Shape {
        /// Exact canonical object under examination.
        object: Object,
        /// Original observed mismatch.
        problem: Problem,
    },
}
impl From<NativeFailure> for Error {
    fn from(error: NativeFailure) -> Self {
        Self::Native(error)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => {
                output.write_str("WFP transaction wait must be 1..=30000 milliseconds")
            }
            Self::Closed => {
                output.write_str("original provisioning engine is closed or has an uncertain close")
            }
            Self::TransactionUncertain => {
                output.write_str("original provisioning transaction is unsettled")
            }
            Self::Native(error) => error.fmt(output),
            Self::MissingOutput(operation) => {
                write!(output, "{operation} returned no native output")
            }
            Self::Shape { object, problem } => {
                write!(output, "WFP metadata {object:?}: {problem:?}")
            }
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Native(error) => Some(error),
            _ => None,
        }
    }
}

/// What a failed metadata transaction establishes about its changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// This operation committed no metadata change.
    NotCommitted,
    /// A commit attempt or failed abort leaves this operation's effects uncertain.
    Unknown,
}

/// Original transaction failure, independent of later abort or close results.
#[derive(Debug)]
#[must_use]
pub struct ChangeFailure {
    /// Original validation, query or native operation failure.
    pub original: Error,
    /// Actual abort of this original transaction, if one began.
    pub abort: Cleanup,
    /// Whether this failure proves that no changes committed.
    pub outcome: Outcome,
    /// Expected installation nonce, even when its commit was not observed.
    /// A candidate receipt alone never establishes that any metadata exists.
    pub receipt: InstallationReceipt,
}
impl fmt::Display for ChangeFailure {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "WFP metadata: {}; {:?}; abort={:?}",
            self.original, self.outcome, self.abort
        )
    }
}
impl std::error::Error for ChangeFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

/// Explicit ordinary-engine installer for persistent provider/callout metadata.
/// It creates no filters, guards, device, service or kernel registration, enables
/// no privileges and never requests elevation or impersonates another identity.
/// There are no native effects on Drop; call `close` to observe engine retirement.
/// BFE checks the calling token's OPEN/transaction rights, container ADD rights,
/// provider/layer ADD_LINK rights, and object READ/DELETE rights as applicable.
/// New objects receive BFE's default security descriptor; this API changes no ACL.
/// See [WFP access control](https://learn.microsoft.com/windows/win32/fwp/access-control).
#[must_use = "retain the original installer and explicitly close its native engine"]
pub struct Provisioner {
    engine: Option<Connection>,
    uncertain_transaction: bool,
    close_result: Option<Cleanup>,
}

#[derive(Clone, Copy)]
enum Access {
    ReadOnly,
    Change,
}
impl fmt::Debug for Provisioner {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("Provisioner")
            .field("has_original_engine", &self.engine.is_some())
            .field("uncertain_transaction", &self.uncertain_transaction)
            .field("close_result", &self.close_result)
            .finish()
    }
}
impl Provisioner {
    /// Open one ordinary local FWPM session under the calling token.
    ///
    /// # Errors
    /// Returns invalid limits or the original native access/open failure. The
    /// calling token needs FWPM_ACTRL_OPEN; opening grants no installation rights.
    pub fn open(limits: ProvisionLimits) -> Result<Self, Error> {
        let wait = limits.wait_millis()?;
        Ok(Self {
            engine: Some(Connection::open(wait)?),
            uncertain_transaction: false,
            close_result: None,
        })
    }

    /// Create the persistent canonical provider and six callouts atomically.
    /// Persist the prepared receipt before calling this method. Existing keys
    /// fail and can be examined by explicitly verifying the original receipt.
    ///
    /// # Errors
    /// Preserves the original failure, commit uncertainty and separate abort
    /// observation. The caller still holds the exact installation receipt.
    pub fn install(&mut self, receipt: InstallationReceipt) -> Result<Installed, ChangeFailure> {
        self.transaction(receipt, Access::Change, |engine| {
            engine.add_provider(receipt)?;
            let mut callout_ids = [0; CALLOUTS.len()];
            for (slot, callout) in CALLOUTS.into_iter().enumerate() {
                let id = engine.add_callout(receipt, callout)?;
                if engine.callout(receipt, callout)? != id {
                    return Err(Error::Shape {
                        object: Object::Callout(callout),
                        problem: Problem::Identity,
                    });
                }
                callout_ids[slot] = id;
            }
            engine.provider(receipt)?;
            Ok(Installed {
                receipt,
                callout_ids,
            })
        })
    }

    /// Verify the complete persistent metadata under a native read transaction.
    ///
    /// # Errors
    /// Returns the first missing/foreign object or original native refusal.
    pub fn verify(&mut self, receipt: InstallationReceipt) -> Result<Installed, ChangeFailure> {
        self.transaction(receipt, Access::ReadOnly, |engine| {
            Ok(Installed {
                receipt,
                callout_ids: engine.verified_ids(receipt)?,
            })
        })
    }

    /// Remove only the supplied installation's complete persistent metadata.
    /// All seven objects are verified before any deletion in the same write
    /// transaction. Numeric callout IDs may change across BFE restarts; each
    /// deletion targets the ID just queried under its verified stable binding.
    ///
    /// # Errors
    /// Refuses foreign/mutated shapes and native in-use/access failures. No
    /// filters, dynamic guards or runtime registrations are removed here.
    pub fn remove(&mut self, receipt: &InstallationReceipt) -> Result<(), ChangeFailure> {
        self.transaction(*receipt, Access::Change, |engine| {
            let ids = engine.verified_ids(*receipt)?;
            for id in ids {
                super::check("FwpmCalloutDeleteById0", unsafe {
                    // SAFETY: ID was just queried and nonce/shape-verified in
                    // this original write transaction, excluding replacement.
                    api::FwpmCalloutDeleteById0(engine.raw(), id)
                })?;
            }
            super::check("FwpmProviderDeleteByKey0", unsafe {
                // SAFETY: the same transaction verified this provider binding
                // and successfully removed its six original callout records.
                api::FwpmProviderDeleteByKey0(engine.raw(), &contract::DRIVER_PROVIDER)
            })?;
            Ok(())
        })
    }

    /// Close this original engine exactly once, preserving its actual result.
    /// Persistent metadata survives successful close. A failed close retains
    /// the original handle and disables further operations without retrying it.
    pub fn close(&mut self) -> Cleanup {
        if let Some(result) = self.close_result {
            return result;
        }
        let result = self.engine.as_ref().map_or(Cleanup::NotNeeded, |engine| {
            Cleanup::from_result(super::check("FwpmEngineClose0", unsafe {
                // SAFETY: this is the original exclusively owned ordinary engine;
                // the cached result excludes all subsequent native close attempts.
                api::FwpmEngineClose0(engine.raw())
            }))
        });
        if result == Cleanup::Succeeded {
            self.engine = None;
        }
        self.close_result = Some(result);
        result
    }

    fn transaction<T>(
        &mut self,
        receipt: InstallationReceipt,
        access: Access,
        change: impl FnOnce(&Connection) -> Result<T, Error>,
    ) -> Result<T, ChangeFailure> {
        let fail = |original| ChangeFailure {
            original,
            abort: Cleanup::NotNeeded,
            outcome: Outcome::NotCommitted,
            receipt,
        };
        self.available().map_err(fail)?;
        let engine = self.engine.as_ref().ok_or_else(|| fail(Error::Closed))?;
        engine.begin(access).map_err(|error| fail(error.into()))?;
        let mut commit_attempted = false;
        let changed = change(engine).and_then(|value| {
            commit_attempted = true;
            engine.commit()?;
            Ok(value)
        });
        match changed {
            Ok(value) => Ok(value),
            Err(original) => {
                let abort = Cleanup::from_result(engine.abort());
                self.uncertain_transaction = abort.has_failure();
                let outcome = if matches!(access, Access::Change)
                    && (commit_attempted || self.uncertain_transaction)
                {
                    Outcome::Unknown
                } else {
                    Outcome::NotCommitted
                };
                Err(ChangeFailure {
                    original,
                    abort,
                    outcome,
                    receipt,
                })
            }
        }
    }

    fn available(&self) -> Result<(), Error> {
        if self.close_result.is_some() || self.engine.is_none() {
            return Err(Error::Closed);
        }
        if self.uncertain_transaction {
            return Err(Error::TransactionUncertain);
        }
        Ok(())
    }
}

struct Connection {
    handle: NonNull<c_void>,
    _thread: PhantomData<Rc<()>>,
}
impl Connection {
    fn open(wait_ms: u32) -> Result<Self, Error> {
        let session = api::FWPM_SESSION0 {
            displayData: api::FWPM_DISPLAY_DATA0 {
                name: windows_sys::w!("GNUnet DNS metadata installer").cast_mut(),
                ..Default::default()
            },
            txnWaitTimeoutInMSec: wait_ms,
            // No DYNAMIC flag: committed PERSISTENT objects outlive this session.
            ..Default::default()
        };
        let mut output = ptr::null_mut();
        // SAFETY: fixed local-server/current-token authentication; the ordinary
        // session and initialized output remain live until this SDK call returns.
        super::check("FwpmEngineOpen0", unsafe {
            api::FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT,
                ptr::null(),
                &session,
                &mut output,
            )
        })?;
        Ok(Self {
            handle: NonNull::new(output).ok_or(Error::MissingOutput("FwpmEngineOpen0"))?,
            _thread: PhantomData,
        })
    }
    fn raw(&self) -> HANDLE {
        self.handle.as_ptr()
    }
    fn begin(&self, access: Access) -> Result<(), NativeFailure> {
        let flags = match access {
            Access::ReadOnly => api::FWPM_TXN_READ_ONLY,
            Access::Change => 0,
        };
        // SAFETY: this thread-confined engine has no unsettled transaction.
        super::check("FwpmTransactionBegin0", unsafe {
            api::FwpmTransactionBegin0(self.raw(), flags)
        })
    }
    fn commit(&self) -> Result<(), NativeFailure> {
        // SAFETY: one original metadata transaction is active on this engine.
        super::check("FwpmTransactionCommit0", unsafe {
            api::FwpmTransactionCommit0(self.raw())
        })
    }
    fn abort(&self) -> Result<(), NativeFailure> {
        // SAFETY: only the original failed metadata transaction is targeted.
        super::check("FwpmTransactionAbort0", unsafe {
            api::FwpmTransactionAbort0(self.raw())
        })
    }
    fn add_provider(&self, receipt: InstallationReceipt) -> Result<(), Error> {
        let mut bytes = binding(receipt, 0);
        let provider = api::FWPM_PROVIDER0 {
            providerKey: contract::DRIVER_PROVIDER,
            displayData: api::FWPM_DISPLAY_DATA0 {
                name: windows_sys::w!("GNUnet DNS native driver").cast_mut(),
                ..Default::default()
            },
            flags: api::FWPM_PROVIDER_FLAG_PERSISTENT,
            providerData: blob(&mut bytes),
            ..Default::default()
        };
        // SAFETY: original fixed metadata and default current-token security
        // are copied synchronously; a collision is returned without adoption.
        super::check("FwpmProviderAdd0", unsafe {
            api::FwpmProviderAdd0(self.raw(), &provider, ptr::null_mut())
        })?;
        Ok(())
    }
    fn add_callout(&self, receipt: InstallationReceipt, callout: Callout) -> Result<u32, Error> {
        let mut bytes = binding(receipt, role(callout));
        let mut provider = contract::DRIVER_PROVIDER;
        let view = api::FWPM_CALLOUT0 {
            calloutKey: callout.key(),
            displayData: api::FWPM_DISPLAY_DATA0 {
                name: windows_sys::w!("GNUnet DNS native callout").cast_mut(),
                ..Default::default()
            },
            flags: api::FWPM_CALLOUT_FLAG_PERSISTENT,
            providerKey: &mut provider,
            providerData: blob(&mut bytes),
            applicableLayer: callout.layer(),
            ..Default::default()
        };
        let mut id = 0;
        // SAFETY: fixed role/provider/layer, nonce bytes and output stay live
        // through the SDK call; no kernel callout or filter is registered here.
        super::check("FwpmCalloutAdd0", unsafe {
            api::FwpmCalloutAdd0(self.raw(), &view, ptr::null_mut(), &mut id)
        })?;
        if id == 0 {
            return Err(Error::MissingOutput("FwpmCalloutAdd0"));
        }
        Ok(id)
    }
    fn verified_ids(&self, receipt: InstallationReceipt) -> Result<[u32; CALLOUTS.len()], Error> {
        self.provider(receipt)?;
        let mut ids = [0; CALLOUTS.len()];
        for (slot, callout) in CALLOUTS.into_iter().enumerate() {
            ids[slot] = self.callout(receipt, callout)?;
        }
        Ok(ids)
    }

    fn provider(&self, receipt: InstallationReceipt) -> Result<(), Error> {
        let mut output = ptr::null_mut();
        // SAFETY: the original write transaction holds the fixed key stable.
        super::check("FwpmProviderGetByKey0", unsafe {
            api::FwpmProviderGetByKey0(self.raw(), &contract::DRIVER_PROVIDER, &mut output)
        })?;
        let allocation =
            Allocation(NonNull::new(output).ok_or(Error::MissingOutput("FwpmProviderGetByKey0"))?);
        // SAFETY: the SDK allocation owns this provider and its nested data.
        let view = unsafe { allocation.0.as_ref() };
        let problem = if !same_guid(view.providerKey, contract::DRIVER_PROVIDER) {
            Some(Problem::Identity)
        } else if view.flags != api::FWPM_PROVIDER_FLAG_PERSISTENT {
            Some(Problem::Flags)
        } else if !view.serviceName.is_null() {
            Some(Problem::Service)
        } else if !matches_blob(&view.providerData, &binding(receipt, 0)) {
            Some(Problem::Binding)
        } else {
            None
        };
        problem.map_or(Ok(()), |problem| {
            Err(Error::Shape {
                object: Object::Provider,
                problem,
            })
        })
    }
    fn callout(&self, receipt: InstallationReceipt, callout: Callout) -> Result<u32, Error> {
        let mut output = ptr::null_mut();
        // SAFETY: fixed original key is stable under the write transaction.
        super::check("FwpmCalloutGetByKey0", unsafe {
            api::FwpmCalloutGetByKey0(self.raw(), &callout.key(), &mut output)
        })?;
        let allocation =
            Allocation(NonNull::new(output).ok_or(Error::MissingOutput("FwpmCalloutGetByKey0"))?);
        // SAFETY: the successful SDK allocation owns this record and nested data.
        let view = unsafe { allocation.0.as_ref() };
        let problem = if !same_guid(view.calloutKey, callout.key()) {
            Some(Problem::Identity)
        } else if view.providerKey.is_null()
            // SAFETY: null is excluded; this nested GUID belongs to the same
            // successful allocation and remains valid through the comparison.
            || !same_guid(unsafe { *view.providerKey }, contract::DRIVER_PROVIDER)
        {
            Some(Problem::Provider)
        } else if !same_guid(view.applicableLayer, callout.layer()) {
            Some(Problem::Layer)
        } else if view.flags & !api::FWPM_CALLOUT_FLAG_REGISTERED
            != api::FWPM_CALLOUT_FLAG_PERSISTENT
        {
            Some(Problem::Flags)
        } else if !matches_blob(&view.providerData, &binding(receipt, role(callout))) {
            Some(Problem::Binding)
        } else {
            None
        };
        if let Some(problem) = problem {
            return Err(Error::Shape {
                object: Object::Callout(callout),
                problem,
            });
        }
        if view.calloutId == 0 {
            return Err(Error::MissingOutput("FwpmCalloutGetByKey0"));
        }
        Ok(view.calloutId)
    }
}

const fn role(callout: Callout) -> u8 {
    match callout {
        Callout::FlowV4 => 1,
        Callout::FlowV6 => 2,
        Callout::DatagramV4 => 3,
        Callout::DatagramV6 => 4,
        Callout::ClosureV4 => 5,
        Callout::ClosureV6 => 6,
    }
}

fn binding(receipt: InstallationReceipt, role: u8) -> [u8; BINDING_BYTES] {
    let mut bytes = [0; BINDING_BYTES];
    bytes[..MARKER.len()].copy_from_slice(MARKER);
    bytes[MARKER.len()..MARKER.len() + 32].copy_from_slice(&receipt.nonce);
    bytes[BINDING_BYTES - 1] = role;
    bytes
}
fn blob(bytes: &mut [u8; BINDING_BYTES]) -> api::FWP_BYTE_BLOB {
    api::FWP_BYTE_BLOB {
        size: BINDING_BYTES as u32,
        data: bytes.as_mut_ptr(),
    }
}
fn matches_blob(blob: &api::FWP_BYTE_BLOB, expected: &[u8; BINDING_BYTES]) -> bool {
    if blob.size != BINDING_BYTES as u32 || blob.data.is_null() {
        return false;
    }
    // SAFETY: caller borrows a successful SDK allocation whose checked blob
    // extent retains these exact native bytes until its owning allocation drops.
    unsafe { std::slice::from_raw_parts(blob.data, BINDING_BYTES) == expected }
}
struct Allocation<T>(NonNull<T>);
impl<T> Drop for Allocation<T> {
    fn drop(&mut self) {
        let mut pointer = self.0.as_ptr().cast::<c_void>();
        // SAFETY: this one successful SDK allocation is freed exactly once;
        // nested pointers are no longer observed after its owner is dropped.
        unsafe { api::FwpmFreeMemory0(&mut pointer) };
    }
}
