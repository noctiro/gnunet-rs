//! Replace a failed or obsolete generation after its original owners drain.
use super::{Driver, FAILED, Generation, bfe, retire};
use crate::sdk;
use core::{ptr::NonNull, sync::atomic::Ordering};

const FLOW_BUDGET: usize = 32;

impl Driver {
    /// Drive recovery from an authenticated passive packet CREATE without
    /// borrowing the generation-access gate. Every unsuccessful attempt keeps
    /// the old allocation published and a later CREATE can observe progress.
    pub(super) unsafe fn recover(&'static self) -> Result<(), sdk::NTSTATUS> {
        let _control = retire::control_owner(self)?;
        if self.stop_requested.load(Ordering::Acquire) {
            return Err(sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY);
        }
        // SAFETY: lifecycle control excludes administrative stop and replacement.
        let old = unsafe { self.generation() };
        let epoch = self.bfe.epoch();
        if !old.needs_recovery(epoch) {
            return Ok(());
        }
        if epoch == u64::MAX || !bfe::running() {
            return Err(sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY);
        }
        if old.phase.load(Ordering::Acquire) == FAILED {
            // A failed START is immutable for its original FILE_OBJECT. A new
            // CREATE must not retire that file's cached failure underneath it.
            // Only after actual CLEANUP can the ordinary native retirement
            // protocol establish whether a fresh generation is possible.
            // SAFETY: lifecycle control retains this initialized original
            // generation through its bounded locked snapshot.
            let original = unsafe { old.runtime().retirement_snapshot() }
                .ok_or(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)?;
            if original.file_owned {
                return Err(sdk::GNUNET_WFP_STATUS_DEVICE_BUSY);
            }
        }
        // SAFETY: this Create has no generation borrow or packet dispatch loan.
        let mut progress = unsafe { retire::poll_generation(old, FLOW_BUDGET) }?;
        if matches!(
            progress.phase,
            retire::Phase::PreparedForNativeWait | retire::Phase::Completion
        ) {
            // SAFETY: only passive lifecycle control can join the native owners.
            progress = unsafe { retire::finalize_generation(old) }?;
        }
        if progress.phase == retire::Phase::Failed {
            // SAFETY: still under the original exclusive lifecycle control.
            let receipts = unsafe { &*old.retirement.get() }.observations();
            return Err(retire::refusal_status(retire::failure_status(
                progress.failure,
                Some(receipts),
            )));
        }
        if let Some(status) = progress.counts.upstream_close_failure {
            return Err(retire::refusal_status(status));
        }
        if progress.phase != retire::Phase::NativeRetired || !progress.counts.can_replace() {
            return Err(sdk::GNUNET_WFP_STATUS_DEVICE_BUSY);
        }

        // At this point no original packet CLEANUP remains due. Block stable
        // generation borrowers, including the BFE notification, before reuse.
        self.access.stop();
        if self.access.outstanding() != 0 {
            return Err(sdk::GNUNET_WFP_STATUS_DEVICE_BUSY);
        }
        // SAFETY: the original CREATE is passive and does not borrow the old
        // owner. A failed allocation leaves the old retired pointer in place.
        let next = unsafe { Generation::allocate() }?;
        let original = self.generation.swap(next.as_ptr(), Ordering::AcqRel);
        // SAFETY: the old file, original native owners and access leases all
        // drained. The passive lifecycle control excludes any other mutation.
        unsafe { Generation::free(NonNull::new_unchecked(original)) };
        assert!(
            self.access.reopen().is_ok(),
            "joined generation gate could not reopen"
        );
        Ok(())
    }
}

impl Driver {
    /// Pin the current generation for a packet IRP. A new authenticated CREATE
    /// can advance recovery without holding a borrow of the generation it frees.
    pub(super) unsafe fn packet_access(
        &'static self,
        stack: &sdk::IO_STACK_LOCATION,
        major: u32,
    ) -> Result<retire::Dispatch<'static>, sdk::NTSTATUS> {
        if major != sdk::IRP_MJ_CLEANUP && !self.packet_admitted.load(Ordering::Acquire) {
            return Err(sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY);
        }
        let existing = self.access.enter();
        if major != sdk::IRP_MJ_CREATE {
            return existing.ok_or(sdk::GNUNET_WFP_STATUS_DEVICE_BUSY);
        }
        if self.stop_requested.load(Ordering::Acquire) {
            return Err(sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY);
        }
        if let Some(lease) = existing {
            // SAFETY: this exact lease protects the observed current generation.
            if !unsafe { self.generation() }.needs_recovery(self.bfe.epoch()) {
                return Ok(lease);
            }
        }
        let file = NonNull::new(stack.FileObject).ok_or(sdk::GNUNET_WFP_STATUS_FILE_CLOSED)?;
        // SAFETY: the I/O manager selected CREATE on this protected packet device.
        unsafe {
            crate::device::dispatch::validate_root_create(
                stack,
                file,
                crate::device::dispatch::CreateAccess::ReadWrite,
            )
        }?;
        // SAFETY: no packet/access lease remains. Only passive qualifying opens
        // can enter the original serialized recovery control.
        unsafe { self.recover() }?;
        self.access
            .enter()
            .ok_or(sdk::GNUNET_WFP_STATUS_DEVICE_BUSY)
    }
}
