//! Reserve capture bytes before reading WFP, then publish before absorbing.
use super::Capture;
use crate::{
    capture, device, flow,
    runtime::{Runtime, now},
    sdk,
};
use core::pin::Pin;
use gnunet_wfp_dns::{Error, RequestId};

/// Why no original capture ownership was committed to the device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureError {
    /// WFP did not grant this filter the right to act on the original packet.
    NoActionRight,
    /// No original active file, live flow, or bounded queue slot.
    Unavailable,
    /// Outbound rundown refused the original callback.
    Admission(device::Error),
    /// Exact native UDP observation or owned copy refused.
    Packet(capture::Refusal),
    /// The original request arena refused admission.
    State(Error),
}

impl<const F: usize, const R: usize> Runtime<F, R> {
    /// Capture one admitted UDP DNS body and absorb its exact original packet.
    /// The queue and request token are live before the verdict is written.
    ///
    /// # Safety
    /// Call from the actual outbound capture filter with its original native
    /// arguments. The flow context must come from WFP or a successful native
    /// association of this same callback's flow. Exclude the service's
    /// upstream sockets and self-injected packets before calling. Preserve
    /// the initialized nonpaged state and all original arguments until return.
    ///
    /// # Errors
    /// Any refused capture leaves the native action unchanged. The caller
    /// handles normal WFP continuation for that filter.
    pub unsafe fn capture(
        self: Pin<&Self>,
        packet: *const sdk::NET_BUFFER_LIST,
        fixed: &sdk::FWPS_INCOMING_VALUES0,
        metadata: Option<&sdk::FWPS_INCOMING_METADATA_VALUES0>,
        context: u64,
        output: &mut sdk::FWPS_CLASSIFY_OUT0,
        expires: u64,
    ) -> Result<RequestId, CaptureError> {
        if output.rights & sdk::FWPS_RIGHT_ACTION_WRITE == 0 {
            return Err(CaptureError::NoActionRight);
        }
        let flow = flow::classified(context, metadata).ok_or(CaptureError::Unavailable)?;
        let endpoint = flow.endpoint().ok_or(CaptureError::Unavailable)?;
        // SAFETY: the actual WFP callback keeps the original allocation live.
        let _admission = unsafe { self.admission().acquire() }.map_err(CaptureError::Admission)?;
        let session = {
            // SAFETY: short metadata acquisition in the original callback.
            let mut state = unsafe { self.lock() }.ok_or(CaptureError::Unavailable)?;
            let active = state.channel.active.ok_or(CaptureError::Unavailable)?;
            if state.channel.captures.len() + state.channel.copying >= R
                || !state.channel.intercepts(endpoint)
                || state.core.classified_flow(flow).is_none()
            {
                return Err(CaptureError::Unavailable);
            }
            state.channel.copying += 1;
            active.session
        };

        // SAFETY: one reserved slot owns the byte budget while NDIS copies.
        let copied = unsafe { capture::copy(packet, fixed, metadata) };
        // Keep the allocation's Drop outside the state lock on all refusals.
        let mut copied = copied.map_err(CaptureError::Packet);
        // SAFETY: the earlier spin acquisition proves this owner is initialized.
        let mut state = unsafe { self.lock() }.ok_or(CaptureError::Unavailable)?;
        state.channel.copying -= 1;
        let path = match &copied {
            Ok(packet) => packet.path(),
            Err(error) => return Err(*error),
        };
        if state
            .channel
            .active
            .is_none_or(|active| active.session != session)
            || !state.channel.intercepts(endpoint)
            || state.core.classified_flow(flow).is_none()
        {
            return Err(CaptureError::Unavailable);
        }
        let stamp = now();
        state.core.sweep(stamp, 8);
        let request = state
            .core
            .capture(session, flow, path, stamp, expires)
            .map_err(CaptureError::State)?;
        // The request and exact payload move together under the original lock.
        let packet = core::mem::replace(&mut copied, Err(CaptureError::Unavailable))?;
        if let Err(rejected) = state.channel.captures.push(Capture { request, packet }) {
            state.core.cancel_queued_capture(session, request);
            drop(state);
            drop(rejected);
            return Err(CaptureError::Unavailable);
        }
        output.actionType = sdk::FWP_ACTION_BLOCK;
        output.flags |= sdk::FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        output.rights &= !sdk::FWPS_RIGHT_ACTION_WRITE;
        state.channel.signal();
        Ok(request)
    }
}
