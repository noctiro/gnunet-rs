use super::{
    engine::{Allocation, Engine, check},
    error::{Datagram, Error, NativeFailure, Problem},
};
use crate::{ids, sdk};
use core::{
    num::{NonZeroU32, NonZeroU64},
    ptr::{self, NonNull},
};

pub(super) struct Guard {
    pub family: Datagram,
    key: sdk::GUID,
    pub(super) callout: sdk::GUID,
    pub(super) layer: sdk::GUID,
}

pub(super) fn guards() -> [Guard; 2] {
    [
        Guard {
            family: Datagram::V4,
            key: ids::GUARD_V4,
            callout: ids::DATAGRAM_V4,
            // SAFETY: the selected SDK supplies this immutable linked GUID.
            layer: unsafe { sdk::FWPM_LAYER_DATAGRAM_DATA_V4 },
        },
        Guard {
            family: Datagram::V6,
            key: ids::GUARD_V6,
            callout: ids::DATAGRAM_V6,
            // SAFETY: the selected SDK supplies this immutable linked GUID.
            layer: unsafe { sdk::FWPM_LAYER_DATAGRAM_DATA_V6 },
        },
    ]
}

pub(super) const fn wide<const N: usize>(bytes: &[u8; N]) -> [u16; N] {
    let mut output = [0; N];
    let mut index = 0;
    while index < N {
        output[index] = bytes[index] as u16;
        index += 1;
    }
    output
}
const PROVIDER_NAME: &[u16] = &wide(b"GNUnet DNS driver policy\0");
const SUBLAYER_NAME: &[u16] = &wide(b"GNUnet DNS interception\0");
const FILTER_NAME: &[u16] = &wide(b"GNUnet DNS inbound UDP guard\0");

fn same(a: sdk::GUID, b: sdk::GUID) -> bool {
    a.Data1 == b.Data1 && a.Data2 == b.Data2 && a.Data3 == b.Data3 && a.Data4 == b.Data4
}

impl Engine {
    pub(super) fn observe_callout(
        &self,
        family: Datagram,
        key: &sdk::GUID,
        layer: sdk::GUID,
    ) -> Result<NonZeroU32, Error> {
        let mut output = ptr::null_mut();
        // SAFETY: this original live engine and fixed key are borrowed synchronously.
        check("FwpmCalloutGetByKey0", unsafe {
            sdk::FwpmCalloutGetByKey0(self.raw(), key, &mut output)
        })?;
        let allocation = Allocation(NonNull::new(output).ok_or(Error::Catalog {
            datagram: family,
            problem: Problem::MissingOutput,
        })?);
        // SAFETY: successful native allocation retains this record and nested provider GUID.
        let callout = unsafe { allocation.0.as_ref() };
        let problem = if !same(callout.calloutKey, *key) {
            Some(Problem::Identity)
        } else if callout.providerKey.is_null()
            // SAFETY: null is excluded; the nested GUID belongs to the original allocation.
            || !same(unsafe { *callout.providerKey }, ids::DRIVER_PROVIDER)
        {
            Some(Problem::Provider)
        } else if !same(callout.applicableLayer, layer) {
            Some(Problem::Layer)
        } else if callout.flags & sdk::FWPM_CALLOUT_FLAG_REGISTERED == 0 {
            Some(Problem::Unregistered)
        } else if callout.flags & sdk::FWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT != 0 {
            Some(Problem::ProviderContext)
        } else {
            None
        };
        if let Some(problem) = problem {
            return Err(Error::Catalog {
                datagram: family,
                problem,
            });
        }
        NonZeroU32::new(callout.calloutId).ok_or(Error::Catalog {
            datagram: family,
            problem: Problem::MissingOutput,
        })
    }

    pub(super) fn add_provider(&self) -> Result<(), NativeFailure> {
        // SAFETY: this C SDK input record permits zero integer/pointer members.
        let mut provider = unsafe { core::mem::zeroed::<sdk::FWPM_PROVIDER0>() };
        provider.providerKey = ids::GUARD_PROVIDER;
        provider.displayData.name = PROVIDER_NAME.as_ptr().cast_mut();
        // SAFETY: all input pointers remain valid while BFE copies the metadata.
        check("FwpmProviderAdd0", unsafe {
            sdk::FwpmProviderAdd0(self.raw(), &provider, ptr::null_mut())
        })
    }

    pub(super) fn add_sublayer(&self) -> Result<(), NativeFailure> {
        // SAFETY: this C SDK input record permits zero integer/pointer members.
        let mut sublayer = unsafe { core::mem::zeroed::<sdk::FWPM_SUBLAYER0>() };
        let mut provider = ids::GUARD_PROVIDER;
        sublayer.subLayerKey = ids::GUARD_SUBLAYER;
        sublayer.displayData.name = SUBLAYER_NAME.as_ptr().cast_mut();
        sublayer.providerKey = &mut provider;
        sublayer.weight = 0x7000;
        // SAFETY: local record and immutable input string are borrowed synchronously.
        check("FwpmSubLayerAdd0", unsafe {
            sdk::FwpmSubLayerAdd0(self.raw(), &sublayer, ptr::null_mut())
        })
    }

    pub(super) fn add_guard(&self, guard: &Guard) -> Result<NonZeroU64, Error> {
        let mut conditions = conditions(sdk::FWP_DIRECTION__FWP_DIRECTION_INBOUND);
        let mut provider = ids::GUARD_PROVIDER;
        // SAFETY: zero selects EMPTY weight, no context and null optional C pointers.
        let mut filter = unsafe { core::mem::zeroed::<sdk::FWPM_FILTER0>() };
        filter.filterKey = guard.key;
        filter.displayData.name = FILTER_NAME.as_ptr().cast_mut();
        filter.providerKey = &mut provider;
        filter.layerKey = guard.layer;
        filter.subLayerKey = ids::GUARD_SUBLAYER;
        filter.numFilterConditions = 2;
        filter.filterCondition = conditions.as_mut_ptr();
        filter.action.type_ = sdk::FWP_ACTION_CALLOUT_UNKNOWN;
        filter.action.__bindgen_anon_1.calloutKey = guard.callout;
        let mut id = 0;
        // SAFETY: every nested input remains live throughout this same transaction call.
        check("FwpmFilterAdd0", unsafe {
            sdk::FwpmFilterAdd0(self.raw(), &filter, ptr::null_mut(), &mut id)
        })?;
        NonZeroU64::new(id).ok_or(Error::Catalog {
            datagram: guard.family,
            problem: Problem::MissingOutput,
        })
    }

    pub(super) fn confirm_guard(&self, guard: &Guard, original: NonZeroU64) -> Result<(), Error> {
        let mut output = ptr::null_mut();
        // SAFETY: fixed original key and initialized output are borrowed synchronously.
        check("FwpmFilterGetByKey0", unsafe {
            sdk::FwpmFilterGetByKey0(self.raw(), &guard.key, &mut output)
        })?;
        let allocation = Allocation(NonNull::new(output).ok_or(Error::Catalog {
            datagram: guard.family,
            problem: Problem::MissingOutput,
        })?);
        // SAFETY: the original successful SDK allocation owns every nested pointer.
        let filter = unsafe { allocation.0.as_ref() };
        let valid = filter.filterId == original.get()
            && same(filter.filterKey, guard.key)
            && !filter.providerKey.is_null()
            // SAFETY: short-circuiting excludes null; this is an owned nested native GUID.
            && same(unsafe { *filter.providerKey }, ids::GUARD_PROVIDER)
            && same(filter.layerKey, guard.layer)
            && same(filter.subLayerKey, ids::GUARD_SUBLAYER)
            && filter.flags & !sdk::FWPM_FILTER_FLAG_INDEXED == 0
            && filter.action.type_ == sdk::FWP_ACTION_CALLOUT_UNKNOWN
            // SAFETY: the checked callout action selects this union member.
            && same(unsafe { filter.action.__bindgen_anon_1.calloutKey }, guard.callout)
            // SAFETY: the checked flags exclude provider context, selecting rawContext.
            && unsafe { filter.__bindgen_anon_1.rawContext } == 0
            && valid_conditions(filter);
        if valid {
            Ok(())
        } else {
            Err(Error::Catalog {
                datagram: guard.family,
                problem: Problem::GuardShape,
            })
        }
    }

    pub(super) fn delete_filter(&self, id: NonZeroU64) -> Result<(), NativeFailure> {
        // SAFETY: only this dynamic session's original native ID is targeted.
        check("FwpmFilterDeleteById0", unsafe {
            sdk::FwpmFilterDeleteById0(self.raw(), id.get())
        })
    }
    pub(super) fn delete_sublayer(&self) -> Result<(), NativeFailure> {
        // SAFETY: only a successful add by this same original dynamic session permits this call.
        check("FwpmSubLayerDeleteByKey0", unsafe {
            sdk::FwpmSubLayerDeleteByKey0(self.raw(), &ids::GUARD_SUBLAYER)
        })
    }
    pub(super) fn delete_provider(&self) -> Result<(), NativeFailure> {
        // SAFETY: this original dynamic engine owns the fixed provider; static metadata is separate.
        check("FwpmProviderDeleteByKey0", unsafe {
            sdk::FwpmProviderDeleteByKey0(self.raw(), &ids::GUARD_PROVIDER)
        })
    }
}

pub(super) fn conditions(direction: sdk::FWP_DIRECTION) -> [sdk::FWPM_FILTER_CONDITION0; 2] {
    // SAFETY: these C SDK input records permit zero integer/pointer members.
    let mut conditions = unsafe { core::mem::zeroed::<[sdk::FWPM_FILTER_CONDITION0; 2]>() };
    // SAFETY: the SDK supplies these immutable, linked condition GUIDs.
    conditions[0].fieldKey = unsafe { sdk::FWPM_CONDITION_IP_PROTOCOL };
    conditions[0].matchType = sdk::FWP_MATCH_TYPE__FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type_ = sdk::FWP_DATA_TYPE__FWP_UINT8;
    conditions[0].conditionValue.__bindgen_anon_1.uint8 = 17;
    // SAFETY: the SDK supplies this immutable, linked condition GUID.
    conditions[1].fieldKey = unsafe { sdk::FWPM_CONDITION_DIRECTION };
    conditions[1].matchType = sdk::FWP_MATCH_TYPE__FWP_MATCH_EQUAL;
    conditions[1].conditionValue.type_ = sdk::FWP_DATA_TYPE__FWP_UINT32;
    conditions[1].conditionValue.__bindgen_anon_1.uint32 = direction as u32;
    conditions
}

fn valid_conditions(filter: &sdk::FWPM_FILTER0) -> bool {
    if filter.numFilterConditions != 2 || filter.filterCondition.is_null() {
        return false;
    }
    // SAFETY: the original SDK allocation owns exactly this checked two-element array.
    let conditions = unsafe { core::slice::from_raw_parts(filter.filterCondition, 2) };
    let first = condition(&conditions[0]);
    let second = condition(&conditions[1]);
    (first == 1 && second == 2) || (first == 2 && second == 1)
}

fn condition(condition: &sdk::FWPM_FILTER_CONDITION0) -> u8 {
    if condition.matchType != sdk::FWP_MATCH_TYPE__FWP_MATCH_EQUAL {
        return 0;
    }
    // SAFETY: immutable linked SDK GUIDs are valid for this synchronous comparison.
    let protocol = unsafe { sdk::FWPM_CONDITION_IP_PROTOCOL };
    // SAFETY: the same linked-SDK contract applies to the direction GUID.
    let direction = unsafe { sdk::FWPM_CONDITION_DIRECTION };
    if same(condition.fieldKey, protocol) && condition.conditionValue.type_ == sdk::FWP_DATA_TYPE__FWP_UINT8
        // SAFETY: the checked native tag selects this initialized UINT8.
        && unsafe { condition.conditionValue.__bindgen_anon_1.uint8 } == 17
    {
        1
    } else if same(condition.fieldKey, direction) && condition.conditionValue.type_ == sdk::FWP_DATA_TYPE__FWP_UINT32
        // SAFETY: the checked native tag selects this initialized UINT32.
        && unsafe { condition.conditionValue.__bindgen_anon_1.uint32 } == sdk::FWP_DIRECTION__FWP_DIRECTION_INBOUND as u32
    {
        2
    } else {
        0
    }
}
