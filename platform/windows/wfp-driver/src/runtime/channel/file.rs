//! Buffered reads and native reply reservations from the original FILE_OBJECT.
use super::{Completion, DeviceError, FileSession, upstream};
use crate::{
    runtime::{Runtime, now},
    sdk,
};
use core::{pin::Pin, ptr::NonNull};
use gnunet_wfp_dns::{Injection, RequestId, device as record};

impl<const F: usize, const R: usize> Runtime<F, R> {
    /// Establish one device file's capture and submit authority.
    ///
    /// # Safety
    /// Invoke only for a successful access check at the original device's
    /// CREATE dispatch. The I/O manager must retain this FILE_OBJECT through
    /// its original CLEANUP. Keep runtime state live at IRQL <= DISPATCH_LEVEL.
    ///
    /// # Errors
    /// Returns original admission or exclusive file refusal.
    pub unsafe fn open_file(
        self: Pin<&Self>,
        file: NonNull<sdk::FILE_OBJECT>,
    ) -> Result<(), DeviceError> {
        // SAFETY: original dispatch retains this state before using the gate.
        let _loan = unsafe { self.admission().acquire() }.map_err(DeviceError::Admission)?;
        // SAFETY: this dispatch can take the state lock at original IRQL.
        let mut state = unsafe { self.lock() }.ok_or(DeviceError::Uninitialized)?;
        if state.channel.active.is_some()
            || state.channel.closing.is_some()
            || state.channel.socket_operation_pending
            || state.channel.failed_sockets.is_some()
        {
            return Err(DeviceError::Busy);
        }
        let session = state.core.open_session().map_err(DeviceError::State)?;
        state.channel.active = Some(FileSession {
            file: file.addr().get(),
            session,
        });
        Ok(())
    }

    /// Revoke the original file's authority and release its unconsumed buffers.
    /// Accepted native replies keep completion custody after this returns.
    ///
    /// # Safety
    /// Only the original device's CLEANUP dispatch may supply the active file.
    /// Keep it and the driver state live at PASSIVE_LEVEL.
    ///
    /// # Errors
    /// Refuses a stale or unknown original file.
    pub unsafe fn cleanup_file(
        self: Pin<&Self>,
        file: NonNull<sdk::FILE_OBJECT>,
    ) -> Result<(), DeviceError> {
        upstream::passive()?;
        let file = file.addr().get();
        let (session, wake, sockets) = {
            // SAFETY: CLEANUP holds the original driver state after admission stopped.
            let mut state = unsafe { self.lock() }.ok_or(DeviceError::Uninitialized)?;
            let session = state.channel.session(file)?;
            let _ = state.core.close_session(session);
            state.channel.active = None;
            state.channel.closing = Some(file);
            while state.channel.completions.pop().is_some() {}
            state.channel.replies = 0;
            state.channel.started = false;
            state.channel.stopped = false;
            (
                session,
                state.channel.wake.take(),
                state.channel.sockets.take(),
            )
        };
        drop(wake);
        // SAFETY: exact detached file and its revoked original generation.
        unsafe { self.discard_captures(session)? };
        // SAFETY: this owner initiated the one passive native close attempt.
        let close = unsafe { self.close_sockets(sockets) };
        // SAFETY: the closing marker still excludes a new file.
        let mut state = unsafe { self.lock() }.ok_or(DeviceError::Uninitialized)?;
        state.channel.closing = None;
        close
    }

    /// Revoke this file's capture and reply admission, drain unconsumed
    /// captures and release kernel socket handles. Original submitted
    /// operations keep their completion path open on the same device file.
    ///
    /// # Safety
    /// Call on the original file's passive STOP dispatch with live state.
    ///
    /// # Errors
    /// Refuses stale ownership or returns an original native handle error.
    pub unsafe fn stop_file(
        self: Pin<&Self>,
        file: NonNull<sdk::FILE_OBJECT>,
    ) -> Result<(), DeviceError> {
        upstream::passive()?;
        let (session, sockets) = {
            // SAFETY: original passive dispatch retains the initialized state.
            let mut state = unsafe { self.lock() }.ok_or(DeviceError::Uninitialized)?;
            let session = state.channel.session(file.addr().get())?;
            if !state.channel.started || state.channel.sockets.is_none() {
                return Err(DeviceError::Stale);
            }
            state.channel.stopped = true;
            let _ = state.core.close_session(session);
            state.channel.socket_operation_pending = true;
            (session, state.channel.sockets.take())
        };
        // SAFETY: original revoked session cannot add a capture.
        unsafe { self.discard_captures(session)? };
        // SAFETY: this owner initiated the one passive native close attempt.
        unsafe { self.close_sockets(sockets) }
    }

    pub(super) unsafe fn close_sockets(
        self: Pin<&Self>,
        sockets: Option<upstream::Sockets>,
    ) -> Result<(), DeviceError> {
        let Some(mut sockets) = sockets else {
            return Ok(());
        };
        let result = sockets.close();
        // SAFETY: original passive STOP/CLEANUP retains the pinned state.
        let mut state = unsafe { self.lock() }.ok_or(DeviceError::Uninitialized)?;
        if result.is_err() {
            state.channel.failed_sockets = Some(sockets);
        }
        state.channel.socket_operation_pending = false;
        result
    }

    unsafe fn discard_captures(
        self: Pin<&Self>,
        session: gnunet_wfp_dns::SessionId,
    ) -> Result<(), DeviceError> {
        for _ in 0..R {
            // SAFETY: caller retains native state for the revoked original file.
            let mut state = unsafe { self.lock() }.ok_or(DeviceError::Uninitialized)?;
            // Racing CLEANUP may already permit a newer file.
            if state
                .channel
                .active
                .is_some_and(|active| active.session != session)
            {
                break;
            }
            let Some(capture) = state.channel.captures.pop() else {
                break;
            };
            state.core.cancel_queued_capture(session, capture.request);
            drop(state);
            drop(capture);
        }
        Ok(())
    }

    /// Dequeue one complete capture through the original device system buffer.
    /// An insufficient buffer leaves the live front capture in place.
    ///
    /// # Safety
    /// Use the original READ FILE_OBJECT and writable resident I/O manager
    /// buffer at IRQL <= DISPATCH_LEVEL. Keep both valid throughout the call.
    ///
    /// # Errors
    /// Refuses stale admission or a buffer shorter than the original record.
    pub unsafe fn dequeue(
        self: Pin<&Self>,
        file: NonNull<sdk::FILE_OBJECT>,
        output: &mut [u8],
    ) -> Result<Option<usize>, DeviceError> {
        // SAFETY: dispatch retains original runtime and device references.
        let _loan = unsafe { self.admission().acquire() }.map_err(DeviceError::Admission)?;
        let file = file.addr().get();
        for _ in 0..R {
            // SAFETY: same original dispatch acquires metadata for one queue entry.
            let mut state = unsafe { self.lock() }.ok_or(DeviceError::Uninitialized)?;
            let session = state.channel.session(file)?;
            state.channel.check_policy()?;
            let Some(front) = state.channel.captures.front() else {
                return Ok(None);
            };
            let request = front.request;
            let stamp = now();
            let live = state.core.has_capture(session, request, stamp);
            if live {
                let needed = record::TOKEN_BYTES + front.packet.payload().len();
                if output.len() < needed {
                    return Err(DeviceError::Buffer { needed });
                }
                state
                    .core
                    .dequeue_capture(session, request, stamp)
                    .map_err(DeviceError::State)?;
            } else {
                state.core.cancel_queued_capture(session, request);
            }
            let capture = state.channel.captures.pop().ok_or(DeviceError::Stale)?;
            state.channel.copying += 1;
            drop(state);
            let record = live.then(|| record::encode(request, capture.packet.payload(), output));
            drop(capture);
            // SAFETY: original rundown and dispatch retain the initialized lock.
            let mut state = unsafe { self.lock() }.ok_or(DeviceError::Uninitialized)?;
            state.channel.copying -= 1;
            if let Some(record) = record {
                return record.map(Some).map_err(DeviceError::Record);
            }
        }
        Ok(None)
    }

    /// Reserve a native injection for the original buffered user reply.
    /// A token-only write retires an issued capture without injection.
    ///
    /// # Safety
    /// Call from the original buffered WRITE dispatch. The caller must settle
    /// every returned reservation via original native rejection or completion.
    /// Keep the input and file valid at IRQL <= DISPATCH_LEVEL.
    ///
    /// # Errors
    /// Returns invalid record, stale file, or original capacity refusal.
    pub unsafe fn begin_reply(
        self: Pin<&Self>,
        file: NonNull<sdk::FILE_OBJECT>,
        input: &[u8],
    ) -> Result<Option<Injection>, DeviceError> {
        let reply = record::reply(input).map_err(DeviceError::Record)?;
        // SAFETY: dispatch and the device keep this runtime live.
        let _loan = unsafe { self.admission().acquire() }.map_err(DeviceError::Admission)?;
        // SAFETY: use only original device-owned file metadata under the lock.
        let mut state = unsafe { self.lock() }.ok_or(DeviceError::Uninitialized)?;
        let session = state.channel.session(file.addr().get())?;
        match reply {
            record::Reply::Discard(request) => {
                state
                    .core
                    .revoke_reply(session, request)
                    .map_err(DeviceError::State)?;
                Ok(None)
            }
            record::Reply::Datagram(request, _) => {
                state.channel.check_policy()?;
                if state.channel.policy_epoch.is_none()
                    || !state.channel.started
                    || state.channel.stopped
                {
                    return Err(DeviceError::Stale);
                }
                if state.channel.replies == R {
                    return Err(DeviceError::Capacity);
                }
                let injection = state
                    .core
                    .begin_injection(session, request, now())
                    .map_err(DeviceError::State)?;
                state.channel.replies += 1;
                Ok(Some(injection))
            }
        }
    }

    /// Settle the exact original native submission refusal.
    ///
    /// # Safety
    /// Call only after actual native rejection before SDK custody or a
    /// completion was possible. Keep the original runtime valid <= DISPATCH_LEVEL.
    ///
    /// # Errors
    /// Refuses an unknown or already observed original reservation.
    pub unsafe fn reject_reply(self: Pin<&Self>, injection: Injection) -> Result<(), DeviceError> {
        let session = injection.session();
        // SAFETY: the native submitter retains this initialized runtime.
        let mut state = unsafe { self.lock() }.ok_or(DeviceError::Uninitialized)?;
        state
            .core
            .reject_injection(injection)
            .map_err(DeviceError::State)?;
        if state
            .channel
            .active
            .is_some_and(|file| file.session == session)
        {
            state.channel.replies -= 1;
        }
        Ok(())
    }

    /// Retire the original WFP completion, delivering it only to the file
    /// session that submitted it. A closed session still settles native debt.
    ///
    /// # Safety
    /// The real WFP completion callback must provide exact original reservation
    /// and NBL status. Keep the runtime nonpaged until native callback cutoff.
    ///
    /// # Errors
    /// Refuses an unknown or duplicate completion.
    pub unsafe fn complete_reply(
        self: Pin<&Self>,
        injection: Injection,
        status: sdk::NTSTATUS,
    ) -> Result<(), DeviceError> {
        let request = RequestId::from_context(injection.context());
        // SAFETY: the original WFP callback retains this initialized owner.
        let mut state = unsafe { self.lock() }.ok_or(DeviceError::Uninitialized)?;
        let observation = state
            .core
            .complete_injection(request)
            .map_err(DeviceError::State)?;
        if state
            .channel
            .active
            .is_some_and(|file| file.session == injection.session())
        {
            state
                .channel
                .completions
                .push(Completion {
                    request,
                    status,
                    observation,
                })
                .map_err(|_| DeviceError::Capacity)?;
            state.channel.signal();
        }
        Ok(())
    }

    /// Observe one completed native WFP write for the original file.
    ///
    /// # Safety
    /// Original file and nonpaged driver state must remain valid through this
    /// dispatch at IRQL <= DISPATCH_LEVEL.
    ///
    /// # Errors
    /// Refuses stale file or closed admission.
    pub unsafe fn completion(
        self: Pin<&Self>,
        file: NonNull<sdk::FILE_OBJECT>,
    ) -> Result<Option<Completion>, DeviceError> {
        // SAFETY: actual original dispatch retains the parent runtime.
        let _loan = unsafe { self.admission().acquire() }.map_err(DeviceError::Admission)?;
        // SAFETY: original file dispatch takes the short state lock.
        let mut state = unsafe { self.lock() }.ok_or(DeviceError::Uninitialized)?;
        state.channel.session(file.addr().get())?;
        let result = state.channel.completions.pop();
        if result.is_some() {
            state.channel.replies -= 1;
        } else {
            state.channel.check_policy()?;
        }
        Ok(result)
    }
}
