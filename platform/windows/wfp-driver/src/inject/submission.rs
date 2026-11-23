use super::{
    Error, Pool, Target,
    completion::{self, Context},
    error,
    packet::Plan,
    resources::Resources,
};
use crate::sdk;
use core::{
    ffi::c_void,
    fmt,
    num::NonZeroU64,
    pin::Pin,
    ptr::{self, NonNull},
};
use gnunet_wfp_dns::{Family, Injection};

/// Native acceptance of one original packet; completion can precede this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Submitted {
    /// Original opaque key passed as WFP injectionContext, never an allocation.
    pub context: NonZeroU64,
    /// Exact native acceptance status; the completion supplies the final status.
    pub native_status: sdk::NTSTATUS,
}

/// Unique reservation owner before one native submission attempt.
/// Errors retain the original for `State::reject_injection`; acceptance transfers
/// it to the real WFP completion. Neither this owner nor its errors settle core
/// debt automatically or report successful application delivery.
#[must_use = "submit or return the original reservation to its core owner"]
pub struct Submission {
    original: Option<Injection>,
    attempted: bool,
}

impl Submission {
    /// Take custody after the original core has published its pending reservation.
    pub const fn new(original: Injection) -> Self {
        Self {
            original: Some(original),
            attempted: false,
        }
    }

    /// Recover an original that no native injection accepted.
    /// Feed it to the same original core's rejection path to settle native debt.
    /// Returns none when the real completion already owns the reservation.
    pub fn into_unsubmitted(self) -> Option<Injection> {
        self.original
    }

    /// Build and submit one complete native inbound UDP DNS response.
    ///
    /// The IP source/UDP source are the original remote resolver; destination
    /// is the original application. Packets carry the required IPv4 header and
    /// IPv4/IPv6 UDP checksums, without offload assumptions. Interface, subinterface
    /// and compartment select native delivery; no replacement socket is used.
    ///
    /// # Errors
    /// Refuses reuse, invalid reply/path facts, IRQL, stopped/full pool, allocation
    /// failures and native rejection. A refused first attempt retains the
    /// original reservation without accepting a completion. Reuse leaves the
    /// earlier reservation disposition unchanged.
    ///
    /// # Safety
    /// Call at IRQL <= DISPATCH_LEVEL with no arena/spin lock held. The real
    /// matching family transport handle, original registered guard and complete
    /// flow/driver state must remain alive through native completion/cutoff.
    /// Publish the unique pending reservation and completion recipient first:
    /// WFP can classify and complete synchronously before this call returns.
    /// Pool, target and input body are resident; body is valid/immutable through
    /// this call. Stop/join submitters and obtain the real native cutoff before
    /// retiring their original handle, pool, recipient or executing callback code.
    pub unsafe fn submit(
        &mut self,
        pool: Pin<&Pool>,
        handles: &[NonNull<c_void>; 2],
        payload: &[u8],
        target: Target,
    ) -> Result<Submitted, Error> {
        if self.attempted {
            return Err(Error::AlreadySubmitted);
        }
        self.attempted = true;
        error::at_most(sdk::DISPATCH_LEVEL)?;
        let original = self.original.as_ref().ok_or(Error::AlreadySubmitted)?;
        let path = original.path;
        if original.flow.family != path.family() || original.flow.compartment != path.compartment()
        {
            return Err(Error::Path);
        }
        let key = original.context();
        let interface = path.interface();
        let (family, handle) = match path.family() {
            Family::V4 => (sdk::GNUNET_WFP_AF_INET, handles[0]),
            Family::V6 => (sdk::GNUNET_WFP_AF_INET6, handles[1]),
        };
        let plan = Plan::new(path, payload)?;
        let resources = Resources::prepare(pool.claim()?, &plan, payload)?;
        let list = resources.list()?;
        let context = resources.context();
        let injection = self.original.take().ok_or(Error::AlreadySubmitted)?;
        // SAFETY: ExAllocatePool2 reserved this aligned Context prefix, disjoint
        // from packet bytes. Transfer all original owners before native entry.
        unsafe {
            context.as_ptr().write(Context {
                resources,
                injection,
                target,
            })
        };
        // SAFETY: the original transport handle and initialized single NBL are
        // live, all original callback owners were published above, reserved
        // arguments are zero, and the native packet begins with its IP header.
        let status = unsafe {
            sdk::FwpsInjectTransportReceiveAsync0(
                handle.as_ptr(),
                ptr::without_provenance_mut(key.get() as usize),
                ptr::null_mut(),
                0,
                family as sdk::ADDRESS_FAMILY,
                // WDK represents the 32-bit native compartment identifier as
                // an enum; preserve its original bits across that carrier.
                path.compartment() as sdk::COMPARTMENT_ID,
                interface.index(),
                interface.subinterface(),
                list.as_ptr(),
                Some(completion::complete),
                context.as_ptr().cast(),
            )
        };
        if status == sdk::GNUNET_WFP_STATUS_SUCCESS {
            // Completion may already have freed context/resources. Never read,
            // dereference or release that original allocation after acceptance.
            return Ok(Submitted {
                context: key,
                native_status: status,
            });
        }
        // Microsoft's receive-injection contract guarantees no completion when
        // return != STATUS_SUCCESS. Recover exactly this original publication.
        // SAFETY: WFP refused custody and cannot access this initialized context.
        let Context {
            resources,
            injection,
            target: _,
        } = unsafe { context.as_ptr().read() };
        self.original = Some(injection);
        drop(resources);
        Err(Error::Native {
            operation: "FwpsInjectTransportReceiveAsync0",
            status,
        })
    }
}

impl fmt::Debug for Submission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InjectionSubmission")
            .field("attempted", &self.attempted)
            .field("has_original", &self.original.is_some())
            .finish_non_exhaustive()
    }
}
