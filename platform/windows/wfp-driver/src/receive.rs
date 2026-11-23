//! Classify a native injection without borrowing its original allocation.
use crate::{flow, path, sdk};
use core::{ffi::c_void, num::NonZeroU64, ptr::NonNull};
use gnunet_wfp_dns::{ClassifiedFlow, Gate, ReceivePath, RequestId, State};

/// Checked observation of a single inbound WFP callback.
#[must_use]
pub struct Classify<'callback> {
    output: &'callback mut sdk::FWPS_CLASSIFY_OUT0,
    packet: Packet,
}

enum Packet {
    Foreign,
    Unattributed,
    Original {
        request: RequestId,
        flow: ClassifiedFlow,
        path: ReceivePath,
    },
}

pub(crate) enum Decision<'callback> {
    Complete(Verdict),
    NeedsAuthority(Candidate<'callback>),
}

pub(crate) struct Candidate<'callback> {
    output: &'callback mut sdk::FWPS_CLASSIFY_OUT0,
    request: RequestId,
    flow: ClassifiedFlow,
    path: ReceivePath,
}

/// Result recorded at the receiving layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// No GNUnet injection to authorize at this layer.
    Foreign,
    /// A matching original retains authority through this receiving layer.
    Authorized,
    /// An original injection was refused, or the preexisting verdict denied it.
    Refused,
}

/// Read WFP injection provenance and the callback's native receive metadata.
/// No state lock is needed while querying the SDK or taking these observations.
///
/// # Safety
/// Call only from the matching inbound DATAGRAM_DATA callbacks, at their SDK
/// IRQL. `fixed`, `metadata`, `packet` and `output` are the original parameters
/// of one live callback; any non-null packet and all SDK buffers behind the
/// references must remain valid through this call. The two injection handles
/// are the live original family owners and must both remain pinned during the
/// query. No effects may race a destroyed/foreign owner into these parameters.
pub unsafe fn inspect<'callback>(
    handles: &[NonNull<c_void>; 2],
    packet: *const sdk::NET_BUFFER_LIST,
    fixed: &sdk::FWPS_INCOMING_VALUES0,
    metadata: Option<&sdk::FWPS_INCOMING_METADATA_VALUES0>,
    flow_context: u64,
    output: &'callback mut sdk::FWPS_CLASSIFY_OUT0,
) -> Classify<'callback> {
    let observation = if packet.is_null() {
        // There is no data indication whose injection can be authenticated.
        Packet::Foreign
    } else {
        // SAFETY: inspect's callback contract pins both original handles and
        // the network buffer list during the synchronous SDK observation.
        unsafe { packet_owner(handles, packet, fixed, metadata, flow_context) }
    };
    Classify {
        output,
        packet: observation,
    }
}

unsafe fn packet_owner(
    handles: &[NonNull<c_void>; 2],
    packet: *const sdk::NET_BUFFER_LIST,
    fixed: &sdk::FWPS_INCOMING_VALUES0,
    metadata: Option<&sdk::FWPS_INCOMING_METADATA_VALUES0>,
    flow_context: u64,
) -> Packet {
    for handle in handles {
        let mut context = core::ptr::null_mut();
        // SAFETY: the original handle and NBL remain live until native return;
        // the output is an initialized stack location for one opaque context.
        let kind =
            unsafe { sdk::FwpsQueryPacketInjectionState0(handle.as_ptr(), packet, &mut context) };
        match kind {
            sdk::FWPS_PACKET_INJECTION_STATE__FWPS_PACKET_NOT_INJECTED
            | sdk::FWPS_PACKET_INJECTION_STATE__FWPS_PACKET_INJECTED_BY_OTHER => continue,
            sdk::FWPS_PACKET_INJECTION_STATE__FWPS_PACKET_INJECTED_BY_SELF => {
                // SAFETY: WFP supplies a live NBL for DATAGRAM_DATA. These SDK
                // accessors only inspect links owned by the same indication.
                if !unsafe { single_datagram(packet) } {
                    return Packet::Unattributed;
                }
                // The WFP injection context is an integer token. Reclassified
                // clones may outlive the original completion and allocation.
                let Some(token) = NonZeroU64::new(context.addr() as u64) else {
                    return Packet::Unattributed;
                };
                let Some(flow) = flow::classified(flow_context, metadata) else {
                    return Packet::Unattributed;
                };
                // SAFETY: these are the original fixed incoming values and
                // metadata describing this same authenticated callback.
                let Some(path) = (unsafe { path::inbound(fixed, metadata) }) else {
                    return Packet::Unattributed;
                };
                return Packet::Original {
                    request: RequestId::from_context(token),
                    flow,
                    path,
                };
            }
            // Previously self-injected also includes clones another callout
            // modified or injected. They carry history, not the original NBL.
            _ => return Packet::Unattributed,
        }
    }
    Packet::Foreign
}

unsafe fn single_datagram(packet: *const sdk::NET_BUFFER_LIST) -> bool {
    // SAFETY: caller pins the original valid NBL, including its NB links.
    unsafe {
        let first = sdk::gnunet_wfp_nbl_first_nb(packet);
        !first.is_null()
            && sdk::gnunet_wfp_nbl_next(packet).is_null()
            && sdk::gnunet_wfp_nb_next(first).is_null()
    }
}

impl<'callback> Classify<'callback> {
    /// Check live authority and apply the verdict to this same callback. Hold
    /// the original arena's lock across the check and immediate verdict write.
    /// `now` is the native monotonic time in the captured request's clock.
    pub fn enforce<const F: usize, const R: usize>(
        self,
        owner: &mut State<F, R>,
        now: u64,
    ) -> Verdict {
        match self.decide() {
            Decision::Complete(verdict) => verdict,
            Decision::NeedsAuthority(candidate) => candidate.enforce(owner, now),
        }
    }

    pub(crate) fn decide(self) -> Decision<'callback> {
        let output = self.output;
        match self.packet {
            Packet::Foreign => {
                if can_write(output) {
                    output.actionType = sdk::FWP_ACTION_CONTINUE;
                }
                Decision::Complete(Verdict::Foreign)
            }
            Packet::Unattributed => Decision::Complete(refuse(output)),
            Packet::Original {
                request,
                flow,
                path,
            } => {
                // A prior hard block remains authoritative. Do not consume an
                // original authorization for a packet already denied.
                if !can_write(output) && output.actionType != sdk::FWP_ACTION_PERMIT {
                    return Decision::Complete(Verdict::Refused);
                }
                Decision::NeedsAuthority(Candidate {
                    output,
                    request,
                    flow,
                    path,
                })
            }
        }
    }
}

impl Candidate<'_> {
    pub(crate) fn enforce<const F: usize, const R: usize>(
        self,
        owner: &mut State<F, R>,
        now: u64,
    ) -> Verdict {
        if owner.authorize_receive(self.request, self.flow, self.path, now) == Gate::Deny {
            return refuse(self.output);
        }
        if can_write(self.output) {
            self.output.actionType = sdk::FWP_ACTION_CONTINUE;
        }
        Verdict::Authorized
    }

    pub(crate) fn refuse(self) {
        refuse(self.output);
    }
}

fn can_write(output: &sdk::FWPS_CLASSIFY_OUT0) -> bool {
    output.rights & sdk::FWPS_RIGHT_ACTION_WRITE != 0
}

fn refuse(output: &mut sdk::FWPS_CLASSIFY_OUT0) -> Verdict {
    // WFP allows a block veto of a prior hard permit even without the
    // action-write right. Preserve all other non-writable decisions.
    if can_write(output) || output.actionType == sdk::FWP_ACTION_PERMIT {
        output.actionType = sdk::FWP_ACTION_BLOCK;
        output.rights &= !sdk::FWPS_RIGHT_ACTION_WRITE;
    }
    Verdict::Refused
}
