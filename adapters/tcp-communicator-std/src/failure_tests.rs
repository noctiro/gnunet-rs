//! Pure original-cause arbitration and recovery-policy regressions.
use super::{HostError, OwnedFailure, ServiceCause};
use gnunet_types::Error;
use std::{error::Error as StdError, io};

fn check(condition: bool) -> Result<(), Error> {
    condition.then_some(()).ok_or(Error::InvalidInput)
}

#[test]
fn service_arbitration_keeps_original_cause_and_runs_retirement_once() -> Result<(), Error> {
    for peerstore in [false, true] {
        for native in [false, true] {
            let cause = if native {
                ServiceCause::Io(io::Error::from_raw_os_error(54))
            } else {
                ServiceCause::Protocol(Error::Capacity)
            };
            let mut retirement_calls = 0;
            let cause = HostError::service_failure(peerstore, cause, || {
                retirement_calls += 1;
                Err(Error::Capacity)
            });
            check(retirement_calls == 1)?;
            let owned = OwnedFailure {
                session: None,
                cause,
            };
            let primary = owned
                .source()
                .and_then(|error| error.source())
                .and_then(|error| error.downcast_ref::<ServiceCause>())
                .ok_or(Error::NotReady)?;
            if native {
                let original = primary
                    .source()
                    .and_then(|error| error.downcast_ref::<io::Error>())
                    .ok_or(Error::NotReady)?;
                check(original.raw_os_error() == Some(54))?;
            } else {
                let original = primary
                    .source()
                    .and_then(|error| error.downcast_ref::<Error>())
                    .ok_or(Error::NotReady)?;
                check(*original == Error::Capacity)?;
            }
            check(!owned.cause.transport_io_retired())?;
            let message = owned.to_string();
            check(message.contains("independent MQ retirement: Capacity"))?;
            check(message.contains(if peerstore { "PEERSTORE" } else { "TRANSPORT" }))?;
            let original = match owned.cause {
                HostError::Peerstore(original) if peerstore => original,
                HostError::Transport(original) if !peerstore => original,
                _ => return Err(Error::Stale),
            };
            check(original.retirement == Some(Error::Capacity))?;
        }
    }
    Ok(())
}

#[test]
fn recovery_requires_native_transport_cause_and_no_retirement_rejection() {
    for peerstore in [false, true] {
        for native in [false, true] {
            for refused in [false, true] {
                let cause = if native {
                    ServiceCause::Io(io::Error::from_raw_os_error(54))
                } else {
                    ServiceCause::Protocol(Error::Capacity)
                };
                let mut retirement_calls = 0;
                let failure = HostError::service_failure(peerstore, cause, || {
                    retirement_calls += 1;
                    if refused {
                        Err(Error::Capacity)
                    } else {
                        Ok(())
                    }
                });
                assert_eq!(retirement_calls, 1);
                assert_eq!(
                    failure.transport_io_retired(),
                    !peerstore && native && !refused
                );
            }
        }
    }
    assert!(!HostError::Core(Error::Capacity).transport_io_retired());
    assert!(!HostError::Peer(io::Error::from_raw_os_error(54)).transport_io_retired());
}
