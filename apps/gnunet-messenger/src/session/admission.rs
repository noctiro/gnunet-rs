//! Bounded Messenger room and message effect admission.
use super::*;
pub(super) fn advance<'id>(
    api: &mut Api<'id, OsEntropy>,
    state: &mut State<'id>,
    settings: &Settings,
    key: Hash,
    report: &mut Report,
) -> Result<(), Failure> {
    if !api.ready() {
        return Ok(());
    }
    if state.room.is_none() {
        let deadline = match state.opening {
            Some(d) => d,
            None => {
                let d = api.deadline(settings.timeout)?;
                state.opening = Some(d);
                d
            }
        };
        let result = match settings.door {
            Some(door) => api.enter_room_bounded(key, door, deadline),
            None => api.open_room_bounded(key, deadline),
        };
        match result {
            Ok((room, operation)) => {
                state.room = Some(room);
                state.retain(operation, Purpose::Setup)?;
                output::welcome(
                    &mut state.output,
                    &key,
                    settings.talk,
                    settings.silence,
                    settings.door.is_some(),
                )?;
            }
            Err(error) if retry(&error) => return Ok(()),
            Err(error) => return Err(Box::new(error)),
        }
    }
    let room = state.room.ok_or(Fault::Conflict)?;
    if !state.monitor_started {
        // A recovered room must first have its actual new source/member. An
        // early whole-zone watch would otherwise retain an empty/old watch set.
        if !api.state().joined(room)? || api.state().local_member(room)?.is_none() {
            return Ok(());
        }
        // This is a declared bounded observation window, not a reconnect or a
        // renewal of an old query. All key operations keep their own deadlines.
        match api.watch_records(settings.record_window) {
            Ok(_) => state.monitor_started = true,
            Err(error) if retry(&error) => return Ok(()),
            Err(error) => return Err(Box::new(error)),
        }
    }
    if !state.joined {
        if !api.state().joined(room)? || api.state().local_member(room)?.is_none() {
            return Ok(());
        }
        state.joined = true;
        state.ever_joined = true;
        state.recovering = false;
        state.recovery_input_warned = false;
        state.opening = None;
        output::joined(&mut state.output, settings.talk, settings.silence)?;
    }
    if state.setup_step < 2 {
        let setup = match state.setup {
            Some(d) => d,
            None => {
                let d = api.deadline(settings.timeout)?;
                state.setup = Some(d);
                d
            }
        };
        if state.setup_step == 0 {
            if let Some(name) = &settings.ego {
                match api.send_bounded(
                    room,
                    Body::Name {
                        name: Text::new(name)?,
                    },
                    setup,
                ) {
                    Ok(op) => state.retain(op, Purpose::Setup)?,
                    Err(error) if retry(&error) => return Ok(()),
                    Err(error) => return Err(Box::new(error)),
                }
            }
            state.setup_step = 1;
        }
        if state.setup_step == 1 {
            if settings.talk && !state.talk_admitted {
                let discourse = [0; 32];
                match api.subscribe_bounded(room, discourse, Duration::from_secs(1), true, setup) {
                    Ok(op) => {
                        state.retain(op, Purpose::Setup)?;
                        state.talk_admitted = true;
                    }
                    Err(error) if retry(&error) => return Ok(()),
                    Err(error) => return Err(Box::new(error)),
                }
            }
            state.setup_step = 2;
            state.setup = None;
        }
    }
    if let Some(pending) = &mut state.pending {
        let bytes = &state.payload[..pending.length];
        let discourse = [0; 32];
        let body = if settings.talk {
            Body::Talk {
                discourse: &discourse,
                data: messenger::wire::SensitiveBytes::new(bytes),
            }
        } else {
            Body::Text {
                text: Text::new(bytes)?,
            }
        };
        let result = if settings.private {
            if let Some(recipient) = pending.recipients.get(pending.next) {
                api.send_private_bounded(room, *recipient, body, pending.deadline)
            } else {
                state.pending = None;
                state.payload.as_mut_slice().zeroize();
                return Ok(());
            }
        } else {
            api.send_bounded(room, body, pending.deadline)
        };
        match result {
            Ok(op) => {
                pending.next += 1;
                let done = !settings.private || pending.next == pending.recipients.len();
                state.retain(op, Purpose::Input)?;
                report.submitted = report.submitted.saturating_add(1);
                if done {
                    state.pending = None;
                    state.payload.as_mut_slice().zeroize();
                }
            }
            Err(error) if retry(&error) => {}
            Err(error) => return Err(Box::new(error)),
        }
    }
    if let Some(fetch) = state.fetch.front() {
        match api.request_message_bounded(room, fetch.hash, fetch.deadline) {
            Ok(op) => {
                let original = state.fetch.pop_front().ok_or(Fault::Conflict)?;
                state.requested.push(original.hash);
                state.retain(op, Purpose::History)?;
            }
            Err(error) if retry(&error) => {}
            Err(error) => return Err(Box::new(error)),
        }
    }
    Ok(())
}
