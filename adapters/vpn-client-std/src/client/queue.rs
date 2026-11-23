//! Admission order is independent of the bounded table's reusable slot indices.
use super::State;

pub(super) fn next(
    slots: &[Option<State<'_>>],
    capacity: impl FnOnce(usize) -> bool,
) -> Option<usize> {
    let (index, _, bytes) = slots
        .iter()
        .enumerate()
        .filter_map(|(index, state)| {
            let state = state.as_ref()?;
            let source = state.source.as_ref()?;
            state
                .reason
                .is_none()
                .then_some((index, state.operation, source.len()))
        })
        .min_by_key(|(_, operation, _)| operation.diagnostic())?;
    // Existing output must drain rather than letting smaller new requests
    // indefinitely consume the space needed by this original head.
    capacity(bytes).then_some(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Address, AfProfile, Cancel, Client, EndpointSource, Instance, Limits, Protocol, Service,
    };
    use gnunet_service_runtime::clock::{RuntimeClock, SystemClock};
    use std::{cell::Cell, sync::Arc};

    #[test]
    fn reused_slot_cannot_bypass_the_original_head_or_its_capacity()
    -> Result<(), Box<dyn std::error::Error>> {
        let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
        let response = clock
            .sample()?
            .now
            .as_micros()
            .checked_add(60_000_000)
            .ok_or("response time overflow")?;
        // Endpoint selection and local admissions create no socket or connector.
        let source = EndpointSource::unix_with_clock(
            std::path::PathBuf::from("unused-vpn-allocation-queue"),
            clock,
        );
        let mut instance = Instance::new();
        let mut client = Client::new(
            &mut instance,
            source,
            AfProfile::DARWIN,
            Limits {
                operations: 2,
                ..Limits::default()
            },
        )?;
        let first = client.internet(Address::V4([192, 0, 2, 1]), None, u64::MAX, response)?;
        let older = client.service(
            Service {
                peer: [3; 32],
                descriptor: [4; 64],
                protocol: Protocol::Udp,
            },
            None,
            u64::MAX,
            response,
        )?;
        if client.cancel(first)? != Cancel::Unsent || client.next_event().is_none() {
            return Err("original unissued cancellation did not settle locally".into());
        }
        let newer = client.internet(Address::V4([192, 0, 2, 2]), None, u64::MAX, response)?;
        let old_index = client.index(older)?;
        let new_index = client.index(newer)?;
        if new_index >= old_index || next(&client.slots, |_| true) != Some(old_index) {
            return Err("a reused slot bypassed the older original operation".into());
        }
        let old_bytes = client.slots[old_index]
            .as_ref()
            .and_then(|state| state.source.as_ref())
            .ok_or("missing original head")?
            .len();
        let new_bytes = client.slots[new_index]
            .as_ref()
            .and_then(|state| state.source.as_ref())
            .ok_or("missing newer request")?
            .len();
        if old_bytes <= new_bytes {
            return Err("capacity fixture requires a larger original head".into());
        }
        let observed = Cell::new(None);
        if next(&client.slots, |bytes| {
            observed.set(Some(bytes));
            bytes <= new_bytes
        })
        .is_some()
            || observed.get() != Some(old_bytes)
        {
            return Err("a smaller newer request starved the original head".into());
        }
        if next(&client.slots, |bytes| bytes <= old_bytes) != Some(old_index) {
            return Err("drained capacity did not expose the original head".into());
        }
        if client.cancel(older)? != Cancel::Unsent
            || next(&client.slots, |_| true) != Some(new_index)
        {
            return Err("cancelling the original head failed to expose its successor".into());
        }
        if client.cancel(newer)? != Cancel::Unsent || next(&client.slots, |_| true).is_some() {
            return Err("cancelled requests retained queue admission".into());
        }
        Ok(())
    }
}
