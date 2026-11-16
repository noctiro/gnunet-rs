//! Native IPC result delivery, including genuine typed empty application values.
use super::*;
use crate::{Cause, ResultValue, Status};
use gnunet_wire::official::set::ClientResponse;

async fn response(
    owner: &mut Set,
    peer: &mut Stream,
    request_id: u32,
    status: u16,
    element_type: u16,
    data: &[u8],
) -> Result<SetProgress, Failure> {
    let response = ClientResponse::Result {
        current_size: 7,
        request_id,
        status,
        element: crate::Element { element_type, data },
    };
    let mut bytes = vec![0; response.encoded_len(owner.limits.abi)?];
    response.encode(&mut bytes, owner.limits.abi)?;
    peer.write_all(&bytes).await?;
    timeout(WAIT, async {
        loop {
            match owner.progress().await? {
                SetProgress::Activity => {}
                event => return Ok(event),
            }
        }
    })
    .await?
}

#[test]
fn modes_preserve_typed_empty_elements_and_separate_control_markers() -> Result<(), Failure> {
    runtime()?.block_on(async {
        for (kind, mode) in [
            (OperationType::Intersection, ResultMode::Full),
            (OperationType::Intersection, ResultMode::Removed),
            (OperationType::Union, ResultMode::Added),
            (OperationType::Union, ResultMode::Symmetric),
        ] {
            let clock = Arc::new(FrozenClock);
            let (_socket, mut owner, mut peer) =
                initialized_for(clock.clone(), Limits::default(), kind).await?;
            let bounds = Bounds::new(clock.as_ref(), Duration::from_secs(5))?;
            let id = operation_mode(&mut owner, &mut peer, bounds, mode).await?;
            let rid = owner.operations[0].request_id;
            // Even an unknown status on an old RID cannot affect this operation.
            check(
                matches!(response(&mut owner, &mut peer, rid + 1, u16::MAX, 0, &[]).await?,
                SetProgress::StaleResult { request_id } if request_id == rid + 1),
            )?;
            let statuses: &[Status] = if mode == ResultMode::Symmetric {
                &[Status::AddLocal, Status::AddRemote]
            } else {
                &[Status::Ok]
            };
            for status in statuses {
                for element_type in [0, 0x1234] {
                    let SetProgress::Result {
                        operation,
                        value,
                        terminal,
                        ..
                    } = response(
                        &mut owner,
                        &mut peer,
                        rid,
                        *status as u16,
                        element_type,
                        &[],
                    )
                    .await?
                    else {
                        return Err("empty element did not produce a result".into());
                    };
                    let element = value.element().ok_or("empty element became a marker")?;
                    check(operation == id && value.status() == *status && terminal.is_none())?;
                    check(element.element_type == element_type && element.data.is_empty())?;
                    check(owner.operations.len() == 1 && owner.operations[0].mode == mode)?;
                }
            }
            // Official C ignores marker element fields. They are not values,
            // even when a counterpart leaves nonempty data in the frame.
            for status in [Status::HalfDone, Status::Done] {
                let SetProgress::Result {
                    operation,
                    value,
                    terminal,
                    ..
                } = response(&mut owner, &mut peer, rid, status as u16, 25, b"ignored").await?
                else {
                    return Err("control marker did not produce a result".into());
                };
                check(operation == id && value.status() == status && value.element().is_none())?;
                if status == Status::Done {
                    let receipt =
                        terminal.ok_or("DONE did not terminate the original operation")?;
                    check(receipt.id == id && receipt.mode == mode && receipt.half_done)?;
                    check(receipt.current_size == Some(7) && owner.operations.is_empty())?;
                } else {
                    check(matches!(value, ResultValue::HalfDone) && terminal.is_none())?;
                    check(owner.operations.len() == 1)?;
                }
            }
        }
        Ok(())
    })
}

#[test]
fn wrong_mode_result_retires_original_source_with_all_outstanding_receipts() -> Result<(), Failure>
{
    runtime()?.block_on(async {
        let clock = Arc::new(FrozenClock);
        let (_socket, mut owner, mut peer) = initialized_with_clock(clock.clone()).await?;
        let bounds = Bounds::new(clock.as_ref(), Duration::from_secs(5))?;
        let added = operation_mode(&mut owner, &mut peer, bounds, ResultMode::Added).await?;
        let symmetric =
            operation_mode(&mut owner, &mut peer, bounds, ResultMode::Symmetric).await?;
        let epoch = owner.epoch().cloned().ok_or("missing source")?;
        let rid = owner.operations[0].request_id;
        let SetProgress::Lost(loss) =
            response(&mut owner, &mut peer, rid, Status::AddLocal as u16, 25, &[]).await?
        else {
            return Err("wrong-mode element was delivered".into());
        };
        check(matches!(
            loss.cause,
            Cause::Failure(Error::UnexpectedResult {
                mode: ResultMode::Added,
                status: Status::AddLocal,
            })
        ))?;
        check(!epoch.live() && loss.operations.len() == 2)?;
        check(loss.operations[0].id == added && loss.operations[0].mode == ResultMode::Added)?;
        check(
            loss.operations[1].id == symmetric && loss.operations[1].mode == ResultMode::Symmetric,
        )?;
        check(
            loss.operations
                .iter()
                .all(|r| r.current_size.is_none() && !r.half_done),
        )?;
        eof(&mut peer).await
    })
}
