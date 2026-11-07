//! Bounded observations of original native retirement, without payload copies.
use super::*;
use gnunet_transport::dv_bridge::{
    SendId, SendState, TransferDiagnostic, TransferId, TransferOutcome, TransferState,
};

/// An actual native guard action; local cancellation is distinct from source loss.
#[derive(Clone, Debug)]
pub enum NativeGuardEvent {
    /// The original physical client was dropped.
    SourceRetired(ClientId),
    /// Every original parent chunk was reclaimed before native admission.
    TransferUnsent(TransferId),
    /// The original logical Job ended and every original local chunk has a
    /// known disposition. The MQ remains live; Written is only local coverage,
    /// not a remote acknowledgement of the retired Job.
    TransferSettled {
        /// Exact original common-transmit parent.
        id: TransferId,
        /// Its actual terminal local packet outcome.
        outcome: TransferOutcome,
    },
}

/// Exact pending native DV work at an original deadline.
#[derive(Clone, Debug)]
pub enum DvRetirementWork {
    /// An original single packet, including its actual local exposure.
    Packet {
        /// Exact original packet token.
        id: SendId,
        /// Actual original packet exposure and callback facts.
        state: SendState,
    },
    /// One original common-transmit parent and its actual local facts.
    Transfer {
        /// Exact original common-transmit parent.
        id: TransferId,
        /// Actual original parent exposure and pending work.
        state: TransferState,
    },
}
/// The actual local branch requesting original native retirement.
#[derive(Clone, Debug)]
pub enum RetirementCause {
    /// Original source, partial-input or output-head target.
    NativeDeadline,
    /// Original pending DV work reached its fixed native target.
    DvDeadline {
        /// Actual pending packet or parent.
        work: DvRetirementWork,
        /// Fixed native target which was reached.
        hard: Instant,
    },
    /// An explicit original DV parent cancellation requested physical closure.
    DvTransferCancellation {
        /// Exact parent whose Job cancellation requested original MQ closure.
        id: TransferId,
        /// Actual facts before cancellation or physical retirement.
        state: TransferState,
    },
    /// The existing source output-pressure policy requested closure.
    OutputPressure,
    /// The original observer refused native admission or its queued callback.
    ObserverRefusal(Error),
    /// A retained DV input belongs to a retired or different actor source.
    DvSourceRetired,
}
/// Facts captured before dropping one original native source. No field implies
/// remote delivery, successful cancellation or a replacement-source authority.
#[derive(Clone, Debug)]
pub struct NativeRetirement {
    /// Exact original Engine/native client, not a raw OS process identifier.
    pub client: ClientId,
    /// Local branch which actually requested this retirement.
    pub cause: RetirementCause,
    /// Exact selected common parent's metadata before physical source closure,
    /// when that original transfer still belongs to this client. Cancellation
    /// may already have run; this is not a pre-cancel snapshot or new authority.
    /// Missing diagnostics never prevent the original retirement.
    pub transfer: Option<TransferDiagnostic>,
    /// Actual native sample before dropping the source.
    pub observed: Instant,
    /// Original accepted-source target.
    pub lease: Instant,
    /// Original first-byte target for the current input, if any.
    pub input: Option<Instant>,
    /// Original output-head target, if any.
    pub output: Option<Instant>,
    /// Type of a complete retained input head, if one is present.
    pub input_type: Option<u16>,
    /// Complete retained input extent. None also covers partial input.
    pub input_frame_bytes: Option<usize>,
    /// Frames actually admitted to this source's native output queue.
    pub queued_frames: usize,
    /// Actual admitted byte cursor minus the positive-write cursor.
    pub queued_bytes: u64,
    /// Type of a same-client frame still held before native queue admission.
    pub staged_type: Option<u16>,
    /// Independent Engine-close failure after the native owner was dropped.
    pub engine_close_error: Option<Error>,
    /// Further observed retirements coalesced while this first row was unread.
    pub coalesced: u64,
}
impl Server {
    /// Take the first unread selected retirement and its bounded coalesced
    /// count. Observation capacity never changes the source-retirement policy.
    pub fn take_native_retirement(&mut self) -> Option<NativeRetirement> {
        self.native_retirement.take()
    }
    pub(super) fn close_observed(
        &mut self,
        index: usize,
        cause: RetirementCause,
    ) -> Result<(), Error> {
        let original = self.native_retirement.is_none().then(|| {
            let client = &self.clients[index];
            let transfer = match &cause {
                RetirementCause::DvDeadline {
                    work: DvRetirementWork::Transfer { id, .. },
                    ..
                }
                | RetirementCause::DvTransferCancellation { id, .. }
                    if self
                        .engine
                        .dv_transfer_owner(id)
                        .is_ok_and(|owner| *owner == client.id) =>
                {
                    self.engine.dv_transfer_diagnostic(id)
                }
                _ => None,
            };
            NativeRetirement {
                client: client.id.clone(),
                cause,
                transfer,
                observed: Instant::now(),
                lease: client.lease,
                input: client.input,
                output: client.output,
                input_type: client.io.frame().and_then(|frame| {
                    gnunet_wire::official::Frame::decode(frame)
                        .ok()
                        .map(|f| f.header().message_type().value())
                }),
                input_frame_bytes: client.io.frame().map(<[u8]>::len),
                queued_frames: client.io.queued_frames(),
                queued_bytes: client
                    .io
                    .queued_cursor()
                    .saturating_sub(client.io.written_cursor()),
                staged_type: self.pending_frame.as_ref().and_then(|(id, frame)| {
                    (*id == client.id)
                        .then(|| {
                            gnunet_wire::official::Frame::decode(frame.bytes())
                                .ok()
                                .map(|f| f.header().message_type().value())
                        })
                        .flatten()
                }),
                engine_close_error: None,
                coalesced: 0,
            }
        });
        let result = self.close(index);
        if let Some(mut original) = original {
            original.engine_close_error = result.as_ref().err().copied();
            self.native_retirement = Some(original);
        } else if let Some(first) = &mut self.native_retirement {
            first.coalesced = first.coalesced.saturating_add(1);
        }
        result
    }
}
