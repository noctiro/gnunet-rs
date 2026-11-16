//! Actual source/message observations and frozen display admission.
use super::*;
fn render<'id>(
    api: &Api<'id, OsEntropy>,
    state: &mut State<'id>,
    settings: &Settings,
    room: Room<'id>,
    hash: Hash,
) -> Result<Option<[Hash; 2]>, Failure> {
    let message = api.message(room, &hash)?;
    let parents = *message.parents();
    let attributed = message.original_signer().is_some();
    if message.phase() == MessagePhase::Applied && !state.seen.contains(&hash) {
        if state.seen.len() == state.seen.capacity() {
            return Err("bounded Messenger displayed-message inventory exhausted".into());
        }
        let _queued = output::message(
            api,
            room,
            message,
            settings.talk,
            settings.silence,
            &mut state.output,
        )?;
        state.seen.push(hash);
    }
    Ok(attributed.then_some(parents))
}
// This is the same sole Input and fixed payload allocation. Offline input is
// explicitly unsent rather than acquiring an old member/recipient capability.
pub(super) fn unavailable_input(
    result: io::Result<usize>,
    state: &mut State<'_>,
    reporter: &Reporter,
    report: &mut Report,
    errors: &mut Failures,
) {
    match result {
        Ok(0) => state.eof = true,
        Ok(_) => {
            report.input_chunks = report.input_chunks.saturating_add(1);
            if !state.recovery_input_warned {
                reporter.warning("messenger.input.unsent", format_args!(
                    "input received while disconnected was not sent; resend it after the room has joined"
                ));
                state.recovery_input_warned = true;
            }
        }
        Err(error) => errors.input = Some(error),
    }
    state.payload.as_mut_slice().zeroize();
}
pub(super) async fn before_source_loss(
    input: &mut Input,
    state: &mut State<'_>,
    reporter: &Reporter,
    report: &mut Report,
    errors: &mut Failures,
    supplied: Option<io::Result<usize>>,
) {
    // Preserve initial pre-JOIN backpressure. After a joined source ends,
    // continue observing stdin during recovery so EOF can actually terminate it.
    if state.eof || !state.ever_joined {
        return;
    }
    if state.pending.take().is_some() {
        reporter.warning(
            "messenger.input.interrupted",
            format_args!(
                "pending input was interrupted by connection loss and was not resubmitted"
            ),
        );
        state.payload.as_mut_slice().zeroize();
    }
    let observed = match supplied {
        Some(result) => Poll::Ready(result),
        None => poll_fn(|cx| Poll::Ready(input.poll(cx, &mut state.payload))).await,
    };
    if let Poll::Ready(result) = observed {
        unavailable_input(result, state, reporter, report, errors);
    }
}
pub(super) fn progress<'id>(
    event: Progress<'id>,
    api: &mut Api<'id, OsEntropy>,
    state: &mut State<'id>,
    settings: &Settings,
    reporter: &Reporter,
    report: &mut Report,
    errors: &mut Failures,
) -> Result<bool, Failure> {
    match event {
        Progress::Lost(loss) => {
            if !state.stop_requested
                && !state.eof
                && state.close.is_none()
                && !errors.failed()
                && !state.budgets().any(|deadline| deadline.expired(None))
                && api.can_reconnect(&loss)
            {
                reporter.warning(
                    "messenger.source.recovering",
                    format_args!("Messenger connection lost; restoring room membership. Outstanding messages will not be resent automatically."),
                );
                state.recovering = true;
                report.capture_recovery(loss, errors);
                // Those actual old jobs are failed/retired. A pending input
                // might contain recipients bound to the old member session;
                // abandon it explicitly rather than resubmitting its bytes.
                if state.pending.is_some() {
                    reporter.warning(
                        "messenger.input.interrupted",
                        format_args!(
                            "pending input was interrupted by MQ loss and was not resubmitted"
                        ),
                    );
                }
                state.pending = None;
                state.payload.as_mut_slice().zeroize();
                state.originals.clear();
                state.requested.clear();
                state.monitor_started = false;
                state.joined = false;
                state.walked = false;
                // The new authenticated membership establishes its current
                // name/subscription with fresh control messages. No old frame,
                // user payload, hash, operation or success is transplanted.
                state.setup_step = 0;
                // Keep a not-yet-admitted initial setup's original deadline.
                // An admitted TALK subscription is recovered by Api alone.
                api.reconnect()?;
                return Ok(false);
            }
            let expected = state.destroy
                && loss.control().is_some_and(|control| {
                    control.kind() == messenger::native::Kind::Destroy
                        && matches!(control.exposure(), messenger::Exposure::Written { .. })
                });
            report.capture(loss, errors);
            if !expected && errors.original.is_none() {
                errors.record_original(
                    "original Messenger source ended before graceful DESTROY".into(),
                );
            }
            return Ok(true);
        }
        Progress::LayoutNeeded(_) => {
            return Err(
                "original Messenger input needs an explicit original-producer layout".into(),
            );
        }
        Progress::Written {
            binding,
            kind,
            bytes,
            ..
        } => {
            report.local_written = report.local_written.saturating_add(1);
            reporter.debug(
                "messenger.operation.write",
                format_args!(
                    "local whole-write kind={kind:?} bytes={bytes} operation={:?}",
                    binding.map(|binding| binding.operation().observation())
                ),
            );
        }
        Progress::RoomClosed { closing, .. } => {
            if state.room == Some(closing.room()) {
                state.room_closed = true;
            }
        }
        Progress::Records(record) => {
            if let Some(error) = record.refusal() {
                reporter.warning(
                    "messenger.record.refused",
                    format_args!("original record: {error}"),
                );
            }
            if let Some(loss) = record.loss() {
                if let Some(source) = loss.general() {
                    report.record_source(source);
                }
                if let Some(source) = loss.monitor() {
                    report.record_source(source);
                }
            }
            match record.into_native() {
                gnunet_namestore_client_host::Progress::Lost {
                    cause,
                    report: original,
                } => {
                    report.record_source(&original);
                    if errors.records.is_none() {
                        errors.records = Some(cause);
                    }
                }
                gnunet_namestore_client_host::Progress::Unavailable(error) => {
                    if errors.original.is_none() {
                        errors.record_original(Box::new(error));
                    }
                }
                original => reporter.debug(
                    "messenger.records.activity",
                    format_args!("NAMESTORE: {original:?}"),
                ),
            }
        }
        Progress::State(event) => match event {
            Event::MessageChanged(room, hash, _) => {
                if let Some(parents) = render(api, state, settings, room, hash)?
                    && settings.history
                    && !settings.talk
                    && state.close.is_none()
                {
                    for parent in parents {
                        state.fetch(api, parent, settings.timeout)?;
                    }
                }
                if settings.history
                    && !state.walked
                    && api.message(room, &hash)?.phase() == MessagePhase::Applied
                    && api.message(room, &hash)?.history_complete()
                    && let Some(member) = api.state().local_member(room)?
                {
                    state.walked = true;
                    let mut original = match api.history(member, &hash, &mut state.history) {
                        Ok(original) => original,
                        Err(messenger::Error::Domain(domain::Error::Protocol(
                            Fault::PermissionDenied | Fault::NotReady | Fault::NotFound,
                        ))) => {
                            reporter.warning("messenger.history.unavailable",format_args!("cached history is outside the current member's available rights"));
                            return Ok(false);
                        }
                        Err(error) => return Err(Box::new(error)),
                    };
                    for _ in 0..settings.limits.core.messages_per_room {
                        let Some(message) = original.try_next()? else {
                            break;
                        };
                        let hash = *message.hash();
                        if message.phase() == MessagePhase::Applied && !state.seen.contains(&hash) {
                            if state.seen.len() == state.seen.capacity() {
                                return Err("bounded history output inventory exhausted".into());
                            }
                            let _queued = output::message(
                                api,
                                room,
                                message,
                                settings.talk,
                                settings.silence,
                                &mut state.output,
                            )?;
                            state.seen.push(hash);
                        }
                    }
                }
            }
            Event::Missing(room, hash)
                if settings.history && state.close.is_none() && state.room == Some(room) =>
            {
                state.fetch(api, hash, settings.timeout)?
            }
            Event::OperationChanged(operation, phase) => {
                reporter.debug(
                    "messenger.operation.state",
                    format_args!("operation={:?} phase={phase:?}", operation.observation()),
                );
                if let Some(index) = state
                    .originals
                    .iter()
                    .position(|o| o.operation == operation)
                    && matches!(
                        phase,
                        OperationPhase::Complete
                            | OperationPhase::Failed
                            | OperationPhase::Cancelled
                    )
                {
                    let original = state.originals.swap_remove(index);
                    // The caller consumed this terminal receipt. Release the
                    // corresponding API/Core slot as well as our local row;
                    // long conversations must not exhaust completed leases.
                    if let Err(error) = api.retire(operation) {
                        errors.record_original(Box::new(error));
                    }
                    if phase == OperationPhase::Complete {
                        report.completed = report.completed.saturating_add(1);
                    } else if matches!(original.purpose, Purpose::Input | Purpose::Setup) {
                        return Err(
                            "original Messenger input/setup operation failed or was canceled"
                                .into(),
                        );
                    }
                }
            }
            Event::ProviderFailed(binding, error) => {
                if state.originals.iter().any(|o| {
                    o.operation == binding.operation()
                        && matches!(o.purpose, Purpose::Input | Purpose::Setup)
                }) {
                    return Err(Box::new(error) as Failure);
                }
                reporter.warning(
                    "messenger.provider.refused",
                    format_args!("original provider: {error}"),
                );
            }
            original => reporter.debug(
                "messenger.state.activity",
                format_args!("state: {original:?}"),
            ),
        },
        original => reporter.debug(
            "messenger.native.activity",
            format_args!("Messenger: {original:?}"),
        ),
    }
    Ok(false)
}
