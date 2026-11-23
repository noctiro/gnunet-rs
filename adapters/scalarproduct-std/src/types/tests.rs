use super::{ConnectError, Error, Fault, seti};
use std::{error::Error as _, io};

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "the fixture checks original source retirement and the resulting ordinary failure response; setup errors propagate"
)]
fn seti_deadline_survives_original_computation_retirement() -> Result<(), Fault> {
    use gnunet_scalarproduct::{
        Action, Completion, Computation, HashOrder, Instance, Limits, PeerSource, Stage, Value,
        Vector,
    };
    use gnunet_wire::official::scalarproduct::ResponseStatus;

    let instance = Instance::new();
    let vector = Vector::new(vec![Value::new([1; 64], 2)], HashOrder::native(), 1, 4096)?;
    let mut core = Computation::bob(&instance, [2; 64], vector, Limits::default())?;
    let port = core.effect().ok_or(Fault::NotReady)?.id;
    core.admit_effect(port)?;
    core.complete_effect(port, Completion::Written)?;
    let source = PeerSource {
        epoch: 1,
        channel: 1,
        peer: [3; 32],
    };
    core.attach_peer(source)?;

    // Model only the shared host's original source-retirement handoff, without
    // making a socket, SETI operation, remote ACK or cryptographic result.
    let original = Error::Seti(seti::Cause::Deadline);
    core.peer_lost(source, original.classified())?;
    let failure = core.outcome().failure.ok_or(Fault::NotReady)?;
    assert_eq!(failure.cause, Fault::Deadline);
    assert_eq!(failure.stage, Stage::Source);
    assert!(core.outcome().known_value().is_none());
    assert!(matches!(
        core.effect().map(|effect| &effect.action),
        Some(Action::ClientResult { status, value: None }) if *status == ResponseStatus::FAILURE
    ));
    core.cancel()?;
    assert_eq!(
        core.outcome().failure.map(|failure| failure.cause),
        Some(Fault::Deadline)
    );
    Ok(())
}

#[test]
fn seti_retirement_keeps_the_original_classification() {
    assert_eq!(
        Error::Seti(seti::Cause::Deadline).classified(),
        Fault::Deadline
    );
    for cause in [seti::Cause::Eof, seti::Cause::Closed] {
        assert_eq!(Error::Seti(cause).classified(), Fault::Closed);
    }
    for cause in [Fault::Malformed, Fault::Capacity, Fault::Cancelled] {
        let protocol = Error::Seti(seti::Cause::Protocol(cause));
        assert_eq!(protocol.classified(), cause);
        assert_eq!(
            protocol
                .source()
                .and_then(|error| error.downcast_ref::<Fault>()),
            Some(&cause)
        );
        let port = Error::Seti(seti::Cause::Ports(ConnectError::Protocol(cause)));
        assert_eq!(port.classified(), cause);
        assert!(
            port.source()
                .is_some_and(|error| error.is::<ConnectError>())
        );
    }
}

#[test]
fn original_seti_socket_errors_remain_io_failures() {
    let socket = Error::Seti(seti::Cause::Io(io::Error::from_raw_os_error(123)));
    assert_eq!(socket.classified(), Fault::Io);
    assert_eq!(
        socket
            .source()
            .and_then(|error| error.downcast_ref::<io::Error>())
            .and_then(io::Error::raw_os_error),
        Some(123)
    );
    let port = Error::Seti(seti::Cause::Ports(ConnectError::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        "original source timeout",
    ))));
    assert_eq!(port.classified(), Fault::Io);
    assert!(
        port.source()
            .is_some_and(|error| error.is::<ConnectError>())
    );
}
