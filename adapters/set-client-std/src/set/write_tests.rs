//! Scripted local write receipts preserve source retirement without socket IO.
use super::*;
use gnunet_service_runtime::clock::SystemClock;
use std::{error::Error as StdError, task::Waker, time::Duration};

#[test]
fn post_write_loss_is_retained_after_actual_mutation_receipt() -> Result<(), Box<dyn StdError>> {
    for take in 0..4 {
        let factory = crate::Factory::new(EndpointSource::unix_with_clock(
            "unused-set-post-write-retirement".into(),
            Arc::new(SystemClock),
        ))?;
        let original = Bounds::new(factory.clock().as_ref(), Duration::from_secs(30))?;
        let mut set = factory.set(OperationType::Union, Limits::default(), original)?;
        let id = MutationId {
            owner: set.owner.clone(),
            serial: 7,
        };
        for serial in [7, 8] {
            set.mutations.push(MutationReceipt {
                id: MutationId {
                    owner: set.owner.clone(),
                    serial,
                },
                kind: MutationKind::Add,
                written: 0,
                whole: false,
                original,
            });
        }
        let context = DeadlineContext::at(
            DeadlineScope::Write(DeadlineWrite::Mutation { serial: 7 }),
            original,
            Instant::now(),
            Some(original.expires),
        );
        let progress = set.written(
            crate::Epoch::new(),
            Some(Tag::Mutation(7)),
            8,
            true,
            Some(Error::deadline(context)),
        )?;
        let SetProgress::MutationWritten(receipt) = progress else {
            return Err("actual whole mutation write was replaced by loss".into());
        };
        if receipt.id != id || receipt.written != 8 || !receipt.whole || !set.closed {
            return Err("late write lost its whole receipt or physical fence".into());
        }
        if !matches!(
            set.add(crate::Element {
                element_type: 0,
                data: &[]
            }),
            Err(Error::Protocol(Fault::Closed))
        ) {
            return Err("retired original source admitted another mutation".into());
        }
        let mut cx = Context::from_waker(Waker::noop());
        let loss = match take {
            0 => match set.poll_progress(&mut cx) {
                Poll::Ready(Ok(SetProgress::Lost(loss))) => loss,
                _ => return Err("next poll did not return original post-write loss".into()),
            },
            1 => set
                .poll_native_guard(&mut cx)
                .ok_or("native guard lost pending receipt")?,
            2 => set.close(),
            _ => set.retire_after(Fault::Cancelled.into()),
        };
        let deadline = loss.deadline.ok_or("original refusing target was lost")?;
        if !matches!(loss.cause, Cause::Deadline)
            || deadline.scope != context.scope
            || deadline.hard != context.hard
            || deadline.expires != context.expires
            || deadline.observed_canonical != context.observed_canonical
            || loss.mutations.len() != 1
            || loss.mutations[0].id.serial != 8
            || loss.mutations[0].written != 0
            || loss.mutations[0].whole
        {
            return Err("retirement changed the cause or unrelated original mutation".into());
        }
        if set.poll_native_guard(&mut cx).is_some() {
            return Err("original loss receipt was delivered twice".into());
        }
    }
    Ok(())
}
