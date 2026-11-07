//! One actual INDEX_START owner, shared by immediate and durable publication.
use super::{Error, IndexRegistration, RegistrationFailure, TimeLimit, registration_failure};
use crate::ipc;
use gnunet_client_host::{ConnectError, EndpointSource};
use gnunet_fs::client::Event;
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use std::{future::Future, os::unix::ffi::OsStrExt, path::Path, time::Duration};

/// Original actual INDEX_STARTED receipt and independent retirement trouble.
pub(crate) struct IndexAnswer {
    pub(crate) response: ipc::Received,
    pub(crate) retirement_error: Option<ConnectError>,
}
fn before_submit(cause: Error) -> Box<RegistrationFailure> {
    Box::new(RegistrationFailure {
        registration: IndexRegistration::NotSubmitted,
        cause: Some(cause),
        preceding: None,
        failure: None,
        response: None,
        retirement_error: None,
    })
}
enum Observation<T> {
    Step(T),
    Cancel,
}
async fn observe<F: Future>(
    future: F,
    control: &mut impl FnMut() -> bool,
    enabled: bool,
) -> Observation<F::Output> {
    let mut future = std::pin::pin!(future);
    if !enabled {
        return Observation::Step(future.await);
    }
    loop {
        let mut tick = std::pin::pin!(tokio::time::sleep(Duration::from_millis(50)));
        let result = std::future::poll_fn(|cx| {
            if let std::task::Poll::Ready(step) = future.as_mut().poll(cx) {
                return std::task::Poll::Ready(Some(step));
            }
            if tick.as_mut().poll(cx).is_ready() {
                return std::task::Poll::Ready(None);
            }
            std::task::Poll::Pending
        })
        .await;
        if let Some(step) = result {
            return Observation::Step(step);
        }
        if !control() {
            return Observation::Cancel;
        }
    }
}
/// Plain immediate operation has no periodic control-observation wakeups.
pub(super) async fn immediate(
    source: EndpointSource,
    file_id: [u8; 64],
    filename: &Path,
    time: &mut TimeLimit,
    deadline: AbsoluteTime,
) -> Result<IndexAnswer, Box<RegistrationFailure>> {
    execute(source, file_id, filename, time, deadline, || true, false).await
}
/// Drive one original operation; false cancels and physically retires that owner.
/// Partial writes retain native OutcomeUnknown, never a safe replay permission.
pub(crate) async fn controlled(
    source: EndpointSource,
    file_id: [u8; 64],
    filename: &Path,
    time: &mut TimeLimit,
    deadline: AbsoluteTime,
    control: impl FnMut() -> bool,
) -> Result<IndexAnswer, Box<RegistrationFailure>> {
    execute(source, file_id, filename, time, deadline, control, true).await
}
async fn execute(
    source: EndpointSource,
    file_id: [u8; 64],
    filename: &Path,
    time: &mut TimeLimit,
    deadline: AbsoluteTime,
    mut control: impl FnMut() -> bool,
    controlled: bool,
) -> Result<IndexAnswer, Box<RegistrationFailure>> {
    time.during(std::future::ready(()))
        .await
        .map_err(before_submit)?;
    if controlled && !control() {
        return Err(before_submit(ProtocolError::Cancelled.into()));
    }
    let mut identity = ipc::Instance::new();
    let request = gnunet_wire::official::fs::Request::IndexStart {
        device: 0,
        inode: 0,
        file_id,
        filename: filename.as_os_str().as_bytes(),
    };
    let mut client = ipc::Client::<0>::new(
        &mut identity,
        request,
        source,
        Default::default(),
        Default::default(),
        deadline,
    )
    .map_err(|error| before_submit(error.into()))?;
    let mut preceding = None;
    loop {
        // An observation tick retains this exact pending future. It never
        // restarts deadline, submits another request or discards partial I/O.
        let observation = observe(time.during(client.drive(None)), &mut control, controlled).await;
        let cause = match observation {
            Observation::Cancel => ProtocolError::Cancelled.into(),
            Observation::Step(step) => match step {
                Ok(Ok(ipc::Step::Event(response))) => match response.event() {
                    Event::IndexStarted => {
                        let retirement_error =
                            client.abort_with_cause(ProtocolError::Cancelled).err();
                        return Ok(IndexAnswer {
                            response,
                            retirement_error,
                        });
                    }
                    Event::IndexFailed(_) => {
                        return Err(Box::new(RegistrationFailure {
                            registration: IndexRegistration::Refused,
                            cause: None,
                            preceding,
                            failure: client.failure(),
                            response: Some(response),
                            retirement_error: client
                                .abort_with_cause(ProtocolError::Cancelled)
                                .err(),
                        }));
                    }
                    _ => ProtocolError::Malformed.into(),
                },
                Ok(Ok(ipc::Step::Connected)) => {
                    preceding = None;
                    continue;
                }
                Ok(Ok(ipc::Step::Retry { cause, .. })) => {
                    if client.failure().is_some() {
                        Error::Client(cause)
                    } else {
                        if preceding.is_none() {
                            preceding = Some(cause.into());
                        }
                        continue;
                    }
                }
                Ok(Ok(ipc::Step::Unavailable(cause))) => cause.into(),
                Ok(Ok(ipc::Step::Finished)) => ProtocolError::NotReady.into(),
                Ok(Ok(_)) => continue,
                Ok(Err(cause)) => cause.into(),
                Err(cause) => cause,
            },
        };
        return Err(Box::new(registration_failure(
            &mut client,
            cause,
            preceding,
        )));
    }
}
