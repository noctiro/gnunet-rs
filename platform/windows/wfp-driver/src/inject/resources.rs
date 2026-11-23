use super::{Error, completion::Context, packet::Plan, pool::Permit};
use crate::{POOL_ALIGNMENT, sdk};
use core::{
    ffi::c_void,
    ptr::{self, NonNull},
};

const PACKET_TAG: u32 = u32::from_le_bytes(*b"GDIP");

pub(super) struct Resources<'owner> {
    // This permit outlives every native object and the target's notification.
    permit: Permit<'owner>,
    allocation: NonNull<c_void>,
    mdl: Option<NonNull<sdk::MDL>>,
    list: Option<NonNull<sdk::NET_BUFFER_LIST>>,
}

impl<'owner> Resources<'owner> {
    pub(super) fn prepare(
        permit: Permit<'owner>,
        plan: &Plan,
        payload: &[u8],
    ) -> Result<Self, Error> {
        let prefix = core::mem::size_of::<Context<'owner>>();
        // The allocation's native alignment also covers its Rust prefix.
        const {
            assert!(core::mem::align_of::<Context<'_>>() <= POOL_ALIGNMENT);
        }
        // Plan's family-specific bound is at most 65,575 bytes. Prefix is a
        // fixed small record, so neither the size nor MDL length can overflow.
        let total = prefix + plan.bytes();
        // SAFETY: caller checked IRQL <= DISPATCH_LEVEL. These are the real
        // non-executable nonpaged pool flags and a nonzero original pool tag.
        let allocation = unsafe {
            sdk::ExAllocatePool2(
                sdk::GNUNET_WFP_POOL_FLAG_NON_PAGED as sdk::POOL_FLAGS,
                total as sdk::SIZE_T,
                PACKET_TAG,
            )
        };
        let allocation = NonNull::new(allocation).ok_or(Error::Allocation {
            operation: "ExAllocatePool2",
        })?;
        let mut resources = Self {
            permit,
            allocation,
            mdl: None,
            list: None,
        };
        // SAFETY: the original pool allocation covers prefix plus all packet
        // bytes. Context is still uninitialized; the trailing region is disjoint.
        let data = unsafe { allocation.as_ptr().cast::<u8>().add(prefix) };
        // SAFETY: this exclusive initialized resident slice is exactly Plan's
        // extent and remains owned through native packet retirement.
        plan.write(payload, unsafe {
            core::slice::from_raw_parts_mut(data, plan.bytes())
        })?;
        // SAFETY: bounded ULONG length, no IRP/quota ownership, and original
        // nonpaged data remains resident until after this MDL is freed.
        let mdl =
            unsafe { sdk::IoAllocateMdl(data.cast(), plan.bytes() as u32, 0, 0, ptr::null_mut()) };
        let mdl = NonNull::new(mdl).ok_or(Error::Allocation {
            operation: "IoAllocateMdl",
        })?;
        resources.mdl = Some(mdl);
        // SAFETY: this original MDL describes our live nonpaged allocation;
        // these pages are neither probed nor locked, and need no unlock later.
        unsafe { sdk::MmBuildMdlForNonPagedPool(mdl.as_ptr()) };
        let mut list = ptr::null_mut();
        // SAFETY: the original NDIS pool preallocates one NB with DataSize zero;
        // caller-owned MDL covers a complete IP packet at data offset zero.
        let status = unsafe {
            sdk::FwpsAllocateNetBufferAndNetBufferList0(
                resources.permit.handle()?.as_ptr(),
                0,
                0,
                mdl.as_ptr(),
                0,
                plan.bytes() as sdk::SIZE_T,
                &mut list,
            )
        };
        if status != sdk::GNUNET_WFP_STATUS_SUCCESS {
            return Err(Error::Native {
                operation: "FwpsAllocateNetBufferAndNetBufferList0",
                status,
            });
        }
        resources.list = Some(NonNull::new(list).ok_or(Error::MissingOutput)?);
        Ok(resources)
    }

    pub(super) fn context(&self) -> NonNull<Context<'owner>> {
        self.allocation.cast()
    }

    pub(super) fn list(&self) -> Result<NonNull<sdk::NET_BUFFER_LIST>, Error> {
        self.list.ok_or(Error::MissingOutput)
    }
}

impl Drop for Resources<'_> {
    fn drop(&mut self) {
        if let Some(list) = self.list.take() {
            // SAFETY: either no submission was accepted, or its original WFP
            // completion has arrived. Free its NBL/NB before the external MDL.
            unsafe { sdk::FwpsFreeNetBufferList0(list.as_ptr()) };
        }
        if let Some(mdl) = self.mdl.take() {
            // SAFETY: NBL retired first. Nonpaged MDLs are freed without unlock.
            unsafe { sdk::IoFreeMdl(mdl.as_ptr()) };
        }
        // SAFETY: Context was moved to the stack before destroying Resources,
        // or was never published. No remaining owner can access these bytes.
        unsafe { sdk::ExFreePoolWithTag(self.allocation.as_ptr(), PACKET_TAG) };
        // Rust then drops the separate inline permit from this stack value.
    }
}
