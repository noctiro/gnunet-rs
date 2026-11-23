//! Typed DATAGRAM_DATA observations in the application's local/remote roles.
use crate::sdk;
use gnunet_wfp_dns::{Addresses, Family, LocalInterface, Path, ReceivePath};

struct Fields {
    protocol: i32,
    direction: i32,
    local_address: i32,
    remote_address: i32,
    local_port: i32,
    remote_port: i32,
    local_interface: i32,
    interface: i32,
    subinterface: i32,
    compartment: i32,
}

fn fields(layer: u16) -> Option<(Family, Fields)> {
    match i32::from(layer) {
        sdk::FWPS_BUILTIN_LAYERS__FWPS_LAYER_DATAGRAM_DATA_V4 => Some((
            Family::V4,
            Fields {
                protocol: sdk::FWPS_FIELDS_DATAGRAM_DATA_V4__FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL,
                direction: sdk::FWPS_FIELDS_DATAGRAM_DATA_V4__FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION,
                local_address: sdk::FWPS_FIELDS_DATAGRAM_DATA_V4__FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS,
                remote_address: sdk::FWPS_FIELDS_DATAGRAM_DATA_V4__FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS,
                local_port: sdk::FWPS_FIELDS_DATAGRAM_DATA_V4__FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT,
                remote_port: sdk::FWPS_FIELDS_DATAGRAM_DATA_V4__FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT,
                local_interface: sdk::FWPS_FIELDS_DATAGRAM_DATA_V4__FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_INTERFACE,
                interface: sdk::FWPS_FIELDS_DATAGRAM_DATA_V4__FWPS_FIELD_DATAGRAM_DATA_V4_INTERFACE_INDEX,
                subinterface: sdk::FWPS_FIELDS_DATAGRAM_DATA_V4__FWPS_FIELD_DATAGRAM_DATA_V4_SUB_INTERFACE_INDEX,
                compartment: sdk::FWPS_FIELDS_DATAGRAM_DATA_V4__FWPS_FIELD_DATAGRAM_DATA_V4_COMPARTMENT_ID,
            },
        )),
        sdk::FWPS_BUILTIN_LAYERS__FWPS_LAYER_DATAGRAM_DATA_V6 => Some((
            Family::V6,
            Fields {
                protocol: sdk::FWPS_FIELDS_DATAGRAM_DATA_V6__FWPS_FIELD_DATAGRAM_DATA_V6_IP_PROTOCOL,
                direction: sdk::FWPS_FIELDS_DATAGRAM_DATA_V6__FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION,
                local_address: sdk::FWPS_FIELDS_DATAGRAM_DATA_V6__FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_ADDRESS,
                remote_address: sdk::FWPS_FIELDS_DATAGRAM_DATA_V6__FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_ADDRESS,
                local_port: sdk::FWPS_FIELDS_DATAGRAM_DATA_V6__FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_PORT,
                remote_port: sdk::FWPS_FIELDS_DATAGRAM_DATA_V6__FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT,
                local_interface: sdk::FWPS_FIELDS_DATAGRAM_DATA_V6__FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_INTERFACE,
                interface: sdk::FWPS_FIELDS_DATAGRAM_DATA_V6__FWPS_FIELD_DATAGRAM_DATA_V6_INTERFACE_INDEX,
                subinterface: sdk::FWPS_FIELDS_DATAGRAM_DATA_V6__FWPS_FIELD_DATAGRAM_DATA_V6_SUB_INTERFACE_INDEX,
                compartment: sdk::FWPS_FIELDS_DATAGRAM_DATA_V6__FWPS_FIELD_DATAGRAM_DATA_V6_COMPARTMENT_ID,
            },
        )),
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
    // SAFETY: the native value's checked tag selects the initialized UINT8 member.
    Some(unsafe { value.__bindgen_anon_1.uint8 })
}

fn uint16(values: &[sdk::FWPS_INCOMING_VALUE0], index: i32) -> Option<u16> {
    let value = value(values, index)?;
    if value.type_ != sdk::FWP_DATA_TYPE__FWP_UINT16 {
        return None;
    }
    // SAFETY: the native value's checked tag selects the initialized UINT16 member.
    Some(unsafe { value.__bindgen_anon_1.uint16 })
}

fn uint32(values: &[sdk::FWPS_INCOMING_VALUE0], index: i32) -> Option<u32> {
    let value = value(values, index)?;
    if value.type_ != sdk::FWP_DATA_TYPE__FWP_UINT32 {
        return None;
    }
    // SAFETY: the native value's checked tag selects the initialized UINT32 member.
    Some(unsafe { value.__bindgen_anon_1.uint32 })
}

unsafe fn uint64(values: &[sdk::FWPS_INCOMING_VALUE0], index: i32) -> Option<u64> {
    let value = value(values, index)?;
    if value.type_ != sdk::FWP_DATA_TYPE__FWP_UINT64 {
        return None;
    }
    // SAFETY: FWP_UINT64 selects the pointer to the original UINT64 value.
    let pointer = unsafe { value.__bindgen_anon_1.uint64 };
    if pointer.is_null() || !pointer.is_aligned() {
        return None;
    }
    // SAFETY: the original classification keeps its immutable value live.
    Some(unsafe { *pointer })
}

unsafe fn bytes16(values: &[sdk::FWPS_INCOMING_VALUE0], index: i32) -> Option<[u8; 16]> {
    let value = value(values, index)?;
    if value.type_ != sdk::FWP_DATA_TYPE__FWP_BYTE_ARRAY16_TYPE {
        return None;
    }
    // SAFETY: the checked tag selects the native pointer member.
    let pointer = unsafe { value.__bindgen_anon_1.byteArray16 };
    if pointer.is_null() || !pointer.is_aligned() {
        return None;
    }
    // SAFETY: inbound's native-buffer contract keeps the pointed-to array live.
    Some(unsafe { (*pointer).byteArray16 })
}

/// Decode only inbound UDP at the two native datagram-data layers.
///
/// These facts describe a classification; they grant no socket or interface loan.
///
/// # Safety
/// `fixed` must be an original SDK classification with `valueCount` live,
/// initialized incoming values. Their tagged pointer members must remain valid
/// and immutable for this call. Any supplied metadata must be that same original
/// classification. No user-supplied pointer or copied numeric observation can
/// establish these requirements.
pub(super) unsafe fn inbound(
    fixed: &sdk::FWPS_INCOMING_VALUES0,
    meta: Option<&sdk::FWPS_INCOMING_METADATA_VALUES0>,
) -> Option<ReceivePath> {
    // SAFETY: the incoming view retains the original native callback buffers.
    let observed = unsafe { decode(fixed, meta, sdk::FWP_DIRECTION__FWP_DIRECTION_INBOUND) }?;
    let arrival = meta
        .filter(|meta| {
            meta.currentMetadataValues & sdk::FWPS_METADATA_FIELD_SOURCE_INTERFACE_INDEX != 0
        })
        .map(|meta| meta.sourceInterfaceIndex);
    ReceivePath::new(
        observed.addresses,
        observed.ports,
        observed.compartment,
        observed.interface,
        arrival,
    )
    .ok()
}

/// Decode an original outbound UDP/DNS datagram. See `inbound` for native
/// pointer ownership; the same WFP fields and address conventions apply.
pub(super) unsafe fn outbound(
    fixed: &sdk::FWPS_INCOMING_VALUES0,
    meta: Option<&sdk::FWPS_INCOMING_METADATA_VALUES0>,
) -> Option<Path> {
    // SAFETY: the outgoing view retains the original native callback buffers.
    let observed = unsafe { decode(fixed, meta, sdk::FWP_DIRECTION__FWP_DIRECTION_OUTBOUND) }?;
    if observed.ports[1] != 53 {
        return None;
    }
    let remote_scope = match meta {
        Some(meta)
            if meta.currentMetadataValues & sdk::FWPS_METADATA_FIELD_REMOTE_SCOPE_ID != 0 =>
        {
            // SAFETY: the flag makes the original complete outbound SCOPE_ID valid.
            unsafe { meta.remoteScopeId.__bindgen_anon_1.Value }
        }
        _ => 0,
    };
    Path::new(
        observed.addresses,
        observed.ports,
        observed.compartment,
        observed.interface,
        remote_scope,
    )
    .ok()
}

struct Observed {
    addresses: Addresses,
    ports: [u16; 2],
    compartment: u32,
    interface: LocalInterface,
}

unsafe fn decode(
    fixed: &sdk::FWPS_INCOMING_VALUES0,
    meta: Option<&sdk::FWPS_INCOMING_METADATA_VALUES0>,
    direction: sdk::FWP_DIRECTION,
) -> Option<Observed> {
    let (family, fields) = fields(fixed.layerId)?;
    if fixed.incomingValue.is_null() || !fixed.incomingValue.is_aligned() {
        return None;
    }
    let count = usize::try_from(fixed.valueCount).ok()?;
    if count > isize::MAX as usize / core::mem::size_of::<sdk::FWPS_INCOMING_VALUE0>() {
        return None;
    }
    // SAFETY: the caller retains the original array; count and alignment are checked.
    let values = unsafe { core::slice::from_raw_parts(fixed.incomingValue, count) };
    if uint8(values, fields.protocol)? != 17
        || uint32(values, fields.direction)? != direction as u32
    {
        return None;
    }
    let compartment = uint32(values, fields.compartment)?;
    if let Some(meta) = meta
        && meta.currentMetadataValues & sdk::FWPS_METADATA_FIELD_COMPARTMENT_ID != 0
        && meta.compartmentId != compartment
    {
        return None;
    }
    let addresses = match family {
        Family::V4 => Addresses::V4 {
            // FWP_VALUE0 documents IPv4 UINT32 and UINT16 ports as host order:
            // https://learn.microsoft.com/windows/win32/api/fwptypes/ns-fwptypes-fwp_value0
            local: uint32(values, fields.local_address)?.to_be_bytes(),
            remote: uint32(values, fields.remote_address)?.to_be_bytes(),
        },
        Family::V6 => Addresses::V6 {
            // The SDK's FWP_BYTE_ARRAY16 representation is copied without word swaps.
            // SAFETY: both nested arrays share the caller's original classification loan.
            local: unsafe { bytes16(values, fields.local_address)? },
            // SAFETY: the same original native-buffer contract applies to the remote value.
            remote: unsafe { bytes16(values, fields.remote_address)? },
        },
    };
    let interface = LocalInterface::new(
        // SAFETY: the typed LUID belongs to the same live classification.
        unsafe { uint64(values, fields.local_interface)? },
        uint32(values, fields.interface)?,
        uint32(values, fields.subinterface)?,
    )
    .ok()?;
    Some(Observed {
        addresses,
        ports: [
            uint16(values, fields.local_port)?,
            uint16(values, fields.remote_port)?,
        ],
        compartment,
        interface,
    })
}
