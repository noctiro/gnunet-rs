//! Original outbound DNS flows and their native datagram-context association.
use crate::sdk;
use core::num::NonZeroU64;
use gnunet_wfp_dns::{ClassifiedFlow, Family, Flow, FlowId, PendingFlow};

struct Fields {
    family: Family,
    protocol: i32,
    direction: i32,
    local_port: i32,
    remote_port: i32,
    compartment: i32,
}

fn fields(layer: u16) -> Option<Fields> {
    match i32::from(layer) {
        sdk::FWPS_BUILTIN_LAYERS__FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4 => Some(Fields {
            family: Family::V4,
            protocol: sdk::FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL,
            direction: sdk::FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION,
            local_port: sdk::FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT,
            remote_port: sdk::FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT,
            compartment: sdk::FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_COMPARTMENT_ID,
        }),
        sdk::FWPS_BUILTIN_LAYERS__FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6 => Some(Fields {
            family: Family::V6,
            protocol: sdk::FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V6__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL,
            direction: sdk::FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V6__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_DIRECTION,
            local_port: sdk::FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V6__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT,
            remote_port: sdk::FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V6__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT,
            compartment: sdk::FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V6__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_COMPARTMENT_ID,
        }),
        _ => None,
    }
}

fn datagram_fields(layer: u16) -> Option<Fields> {
    match i32::from(layer) {
        sdk::FWPS_BUILTIN_LAYERS__FWPS_LAYER_DATAGRAM_DATA_V4 => Some(Fields {
            family: Family::V4,
            protocol: sdk::FWPS_FIELDS_DATAGRAM_DATA_V4__FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL,
            direction: sdk::FWPS_FIELDS_DATAGRAM_DATA_V4__FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION,
            local_port:
                sdk::FWPS_FIELDS_DATAGRAM_DATA_V4__FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT,
            remote_port:
                sdk::FWPS_FIELDS_DATAGRAM_DATA_V4__FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT,
            compartment:
                sdk::FWPS_FIELDS_DATAGRAM_DATA_V4__FWPS_FIELD_DATAGRAM_DATA_V4_COMPARTMENT_ID,
        }),
        sdk::FWPS_BUILTIN_LAYERS__FWPS_LAYER_DATAGRAM_DATA_V6 => Some(Fields {
            family: Family::V6,
            protocol: sdk::FWPS_FIELDS_DATAGRAM_DATA_V6__FWPS_FIELD_DATAGRAM_DATA_V6_IP_PROTOCOL,
            direction: sdk::FWPS_FIELDS_DATAGRAM_DATA_V6__FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION,
            local_port:
                sdk::FWPS_FIELDS_DATAGRAM_DATA_V6__FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_PORT,
            remote_port:
                sdk::FWPS_FIELDS_DATAGRAM_DATA_V6__FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT,
            compartment:
                sdk::FWPS_FIELDS_DATAGRAM_DATA_V6__FWPS_FIELD_DATAGRAM_DATA_V6_COMPARTMENT_ID,
        }),
        _ => None,
    }
}

fn value(values: &[sdk::FWPS_INCOMING_VALUE0], index: i32) -> Option<&sdk::FWP_VALUE0> {
    Some(&values.get(usize::try_from(index).ok()?)?.value)
}

fn uint8(values: &[sdk::FWPS_INCOMING_VALUE0], index: i32) -> Option<u8> {
    let value = value(values, index)?;
    if value.type_ != sdk::FWP_DATA_TYPE__FWP_UINT8 {
        return None;
    }
    // SAFETY: the original value's checked tag selects its initialized member.
    Some(unsafe { value.__bindgen_anon_1.uint8 })
}

fn uint16(values: &[sdk::FWPS_INCOMING_VALUE0], index: i32) -> Option<u16> {
    let value = value(values, index)?;
    if value.type_ != sdk::FWP_DATA_TYPE__FWP_UINT16 {
        return None;
    }
    // SAFETY: the original value's checked tag selects its initialized member.
    Some(unsafe { value.__bindgen_anon_1.uint16 })
}

fn uint32(values: &[sdk::FWPS_INCOMING_VALUE0], index: i32) -> Option<u32> {
    let value = value(values, index)?;
    if value.type_ != sdk::FWP_DATA_TYPE__FWP_UINT32 {
        return None;
    }
    // SAFETY: the original value's checked tag selects its initialized member.
    Some(unsafe { value.__bindgen_anon_1.uint32 })
}

pub(crate) fn endpoint(metadata: &sdk::FWPS_INCOMING_METADATA_VALUES0) -> Option<NonZeroU64> {
    if !reports_endpoint(metadata) {
        return None;
    }
    NonZeroU64::new(metadata.transportEndpointHandle)
}

fn reports_endpoint(metadata: &sdk::FWPS_INCOMING_METADATA_VALUES0) -> bool {
    metadata.currentMetadataValues & sdk::FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE != 0
}

fn reports_flow(metadata: &sdk::FWPS_INCOMING_METADATA_VALUES0) -> bool {
    metadata.currentMetadataValues & sdk::FWPS_METADATA_FIELD_FLOW_HANDLE != 0
}

/// Decode the required context and conditional native handle metadata of this
/// datagram classification. A flagged zero is a contradictory observation.
pub(crate) fn classified(
    context: u64,
    metadata: Option<&sdk::FWPS_INCOMING_METADATA_VALUES0>,
) -> Option<ClassifiedFlow> {
    let id = FlowId::from_context(NonZeroU64::new(context)?);
    let flow_handle = match metadata.filter(|metadata| reports_flow(metadata)) {
        Some(metadata) => Some(NonZeroU64::new(metadata.flowHandle)?),
        None => None,
    };
    let endpoint_handle = match metadata.filter(|metadata| reports_endpoint(metadata)) {
        Some(metadata) => Some(NonZeroU64::new(metadata.transportEndpointHandle)?),
        None => None,
    };
    Some(ClassifiedFlow::new(id, flow_handle, endpoint_handle))
}

/// Decode an original outbound UDP DNS association from either ALE flow layer.
/// Missing metadata and inconsistent typed fields refuse admission. The returned
/// facts alone neither pin the native flow nor associate a context with it.
///
/// # Safety
/// Call only from the original ALE_FLOW_ESTABLISHED callback at IRQL no higher
/// than DISPATCH_LEVEL. `fixed` and `metadata` must describe that same live
/// callback. Its `valueCount` incoming values and every selected tagged member
/// must remain initialized, valid and immutable throughout this call.
pub unsafe fn outbound(
    fixed: &sdk::FWPS_INCOMING_VALUES0,
    metadata: &sdk::FWPS_INCOMING_METADATA_VALUES0,
) -> Option<Flow> {
    let fields = fields(fixed.layerId)?;
    // SAFETY: the original ALE observations and all selected values remain live.
    unsafe { decode(fixed, metadata, fields) }
}

/// Decode native outbound datagram metadata for an unassociated existing flow.
/// No tuple lookup substitutes for the native flow and endpoint handles.
///
/// # Safety
/// Supply one live DATAGRAM_DATA_V4/V6 classification at IRQL no higher than
/// DISPATCH_LEVEL. Its typed incoming array and metadata must remain initialized
/// and immutable throughout this call, as required by [`outbound`].
pub unsafe fn datagram_outbound(
    fixed: &sdk::FWPS_INCOMING_VALUES0,
    metadata: &sdk::FWPS_INCOMING_METADATA_VALUES0,
) -> Option<Flow> {
    let fields = datagram_fields(fixed.layerId)?;
    if metadata.currentMetadataValues & sdk::FWPS_METADATA_FIELD_COMPARTMENT_ID == 0 {
        return None;
    }
    // DATAGRAM_DATA supports all three metadata fields, conditionally. Checking
    // their presence and the typed fixed compartment binds one actual callback:
    // https://learn.microsoft.com/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer
    // SAFETY: the original datagram observations meet the same array contract.
    unsafe { decode(fixed, metadata, fields) }
}

unsafe fn decode(
    fixed: &sdk::FWPS_INCOMING_VALUES0,
    metadata: &sdk::FWPS_INCOMING_METADATA_VALUES0,
    fields: Fields,
) -> Option<Flow> {
    let endpoint = endpoint(metadata)?;
    if !reports_flow(metadata) || fixed.incomingValue.is_null() || !fixed.incomingValue.is_aligned()
    {
        return None;
    }
    let handle = NonZeroU64::new(metadata.flowHandle)?;
    let count = usize::try_from(fixed.valueCount).ok()?;
    if count > isize::MAX as usize / core::mem::size_of::<sdk::FWPS_INCOMING_VALUE0>() {
        return None;
    }
    // SAFETY: caller retains the original initialized array; the extent and
    // alignment checks rule out invalid slice arithmetic before observation.
    let values = unsafe { core::slice::from_raw_parts(fixed.incomingValue, count) };
    if uint8(values, fields.protocol)? != 17
        || uint32(values, fields.direction)? != sdk::FWP_DIRECTION__FWP_DIRECTION_OUTBOUND as u32
        || uint16(values, fields.local_port)? == 0
        || uint16(values, fields.remote_port)? != 53
    {
        return None;
    }
    let compartment = uint32(values, fields.compartment)?;
    if metadata.currentMetadataValues & sdk::FWPS_METADATA_FIELD_COMPARTMENT_ID != 0
        && metadata.compartmentId != compartment
    {
        return None;
    }
    Some(Flow {
        handle,
        endpoint,
        family: fields.family,
        compartment,
    })
}

pub(crate) fn datagram_layer(family: Family) -> u16 {
    // These WDK built-in layer constants are UINT16 run-time identifiers.
    match family {
        Family::V4 => sdk::FWPS_BUILTIN_LAYERS__FWPS_LAYER_DATAGRAM_DATA_V4 as u16,
        Family::V6 => sdk::FWPS_BUILTIN_LAYERS__FWPS_LAYER_DATAGRAM_DATA_V6 as u16,
    }
}

/// Associate the original native flow with its same-family datagram callout.
/// Return the original SDK status without replacing an existing association.
///
/// # Safety
/// The native flow and this driver's registered datagram `callout_id` must
/// remain live at IRQL no higher than DISPATCH_LEVEL. That callout must have a
/// flow-delete callback. `context` belongs to the same original driver instance
/// and must already have reserved callback custody before entering WFP. Retain
/// that custody until a failed association is settled or the actual flow-delete
/// callback arrives. Numeric flow handles alone do not establish this contract.
pub unsafe fn associate(context: &PendingFlow, callout_id: u32) -> sdk::NTSTATUS {
    let flow = context.flow();
    // Microsoft's DDProxy associates the ALE flowHandle with DATAGRAM_DATA's
    // layer and callout, rather than the ALE callback's identifiers:
    // https://github.com/microsoft/Windows-driver-samples/blob/main/network/trans/ddproxy/sys/DD_proxy.c
    // SAFETY: caller pins the original native flow, callout and reserved context.
    unsafe {
        sdk::FwpsFlowAssociateContext0(
            flow.handle.get(),
            datagram_layer(flow.family),
            callout_id,
            context.context().get(),
        )
    }
}

/// Request removal from the original datagram callout, preserving its SDK status.
/// SUCCESS invokes flow-delete synchronously; PENDING invokes it asynchronously.
/// Neither status permits inventing a second retirement of the original context.
///
/// # Safety
/// Call at IRQL no higher than DISPATCH_LEVEL for the still-owned association
/// under this driver's live same-family datagram `callout_id`. Exclude a new
/// association under a reused native flow handle. Do not hold a lock that the
/// flow-delete callback acquires. Keep callback custody until that actual
/// callback; this function does not retire the arena slot. Do not call it from
/// flow-delete, where WFP has already removed the association.
pub unsafe fn remove(flow: Flow, callout_id: u32) -> sdk::NTSTATUS {
    // https://learn.microsoft.com/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsflowremovecontext0
    // SAFETY: caller retains the exact original association through native return
    // and permits the SDK's synchronous callback without holding its state lock.
    unsafe {
        sdk::FwpsFlowRemoveContext0(flow.handle.get(), datagram_layer(flow.family), callout_id)
    }
}
