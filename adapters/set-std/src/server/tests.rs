//! Source cases use real original Service inputs and the native CPU-pass helper.
//! Pure effect completions below are not native IO or peer interoperability.
use super::progress_activity;
use gnunet_set::{
    Action, Completion, Compression, Error, Instance, Limits, Random, ResultMode, Service,
    wire::{Abi, ClientRequest, Options, PeerMessage},
};

struct Scripted;
impl Random for Scripted {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        output.fill(7);
        Ok(())
    }
}
impl Compression for Scripted {
    fn compress(&mut self, _: &[u8], _: usize) -> Result<Vec<u8>, Error> {
        Err(Error::Unsupported)
    }
    fn decompress_exact(&mut self, _: &[u8], _: usize, _: usize) -> Result<Vec<u8>, Error> {
        Err(Error::Unsupported)
    }
}
fn check(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(Error::Conflict) }
}
fn whole_open(service: &mut Service<'_>) -> Result<(), Error> {
    let effect = service.effect().ok_or(Error::NotReady)?;
    check(matches!(effect.action, Action::OpenPeer { .. }))?;
    let id = effect.id;
    service.admit_effect(id)?;
    let _original = service.complete_effect(id, Completion::Written)?;
    Ok(())
}
fn whole_request(service: &mut Service<'_>) -> Result<(), Error> {
    let effect = service.effect().ok_or(Error::NotReady)?;
    let Action::PeerSend { bytes, .. } = &effect.action else {
        return Err(Error::Conflict);
    };
    check(matches!(
        PeerMessage::decode(bytes, Abi::native())?,
        PeerMessage::OperationRequest { .. }
    ))?;
    let id = effect.id;
    service.admit_effect(id)?;
    let _original = service.complete_effect(id, Completion::Written)?;
    Ok(())
}

#[test]
fn finite_native_cpu_pass_reaches_second_ready_original_after_first_waits() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut service = Service::new(&mut instance, Limits::default(), Abi::native(), 1)?;
    let client = service.attach_client()?;
    service.client_request(
        client,
        ClientRequest::Create { operation: 2 },
        1,
        &mut Scripted,
    )?;
    let evaluate = |request_id| ClientRequest::Evaluate {
        result_mode: ResultMode::Symmetric as u32,
        target: [5; 32],
        app_id: [4; 64],
        request_id,
        options: Options::default(),
        context: &[],
    };

    // This actual first owner has whole original Open/OperationRequest, built
    // its empty strata and now genuinely waits on peer input, with no effects.
    service.client_request(client, evaluate(1), 1, &mut Scripted)?;
    whole_open(&mut service)?;
    check(service.progress(1, &mut Scripted)?)?;
    whole_request(&mut service)?;
    check(service.progress(1, &mut Scripted)?)?;
    check(!service.progress(1, &mut Scripted)? && service.effect().is_none())?;

    // A distinct admitted original becomes active. Its own strata still needs
    // CPU work; no fabricated incoming frame, timer or private state is used.
    service.client_request(client, evaluate(2), 1, &mut Scripted)?;
    whole_open(&mut service)?;
    check(service.progress(1, &mut Scripted)?)?;
    whole_request(&mut service)?;
    check(service.progress_span() == 2 && service.effect().is_none())?;
    let mut remaining = service.progress_span();

    let first = service.progress(1, &mut Scripted)?;
    check(!first)?;
    check(progress_activity(
        &mut remaining,
        service.progress_span(),
        first,
    ))?;
    check(remaining == 1)?;
    let second = service.progress(1, &mut Scripted)?;
    check(second)?;
    check(progress_activity(
        &mut remaining,
        service.progress_span(),
        second,
    ))?;
    check(remaining == 2 && service.effect().is_none())?;

    // Once both real owners wait, exactly one complete unchanged pass reaches
    // Pending. Bookkeeping cannot renew itself or manufacture a SET result.
    let first = service.progress(1, &mut Scripted)?;
    check(!first && progress_activity(&mut remaining, service.progress_span(), first))?;
    let second = service.progress(1, &mut Scripted)?;
    check(!second && !progress_activity(&mut remaining, service.progress_span(), second))?;
    check(remaining == 0 && service.pending_effects() == 0 && service.client_live(client))
}

#[test]
fn final_failure_observation_keeps_original_cause_and_actual_unsent()
-> Result<(), Box<dyn std::error::Error>> {
    // Construction and explicit rejection open no socket. These are original
    // production never-admitted terminal paths, not scripted native writes or
    // C/peer delivery evidence.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut instance = Instance::new();
            let mut core = Service::new(&mut instance, Limits::default(), Abi::native(), 1)?;
            let application = core.attach_client()?;
            core.client_request(
                application,
                ClientRequest::Create { operation: 2 },
                1,
                &mut Scripted,
            )?;
            core.client_request(
                application,
                ClientRequest::Evaluate {
                    result_mode: ResultMode::Symmetric as u32,
                    target: [5; 32],
                    app_id: [4; 64],
                    request_id: 17,
                    options: Options::default(),
                    context: &[],
                },
                1,
                &mut Scripted,
            )?;
            let open = core.effect().ok_or(Error::NotReady)?.id;
            let mut cadet_instance = super::cadet::Instance::new();
            let mut ports = [super::cadet::PortSlot::new()];
            let mut channels = [super::cadet::ChannelSlot::new()];
            let client = super::cadet::Client::new(
                &mut cadet_instance,
                super::cadet::EndpointSource::unix(std::path::PathBuf::from(
                    "/unused-set-operation-diagnostic",
                )),
                &mut ports,
                &mut channels,
                super::cadet::Limits::default(),
            )?;
            let mut server = super::Server::new(
                core,
                client,
                super::Limits::default(),
                super::ServiceOptions::default(),
                super::UnixAccess::default(),
            )?;
            let mut early_failure = false;
            server.reject(open, Error::Capacity, &mut |event| {
                if let super::Event::OperationFailed(_) = event {
                    early_failure = true;
                }
            })?;
            check(!early_failure)?;
            for _ in 0..128 {
                server.core.progress(1, &mut Scripted)?;
                if server.core.effect().is_some() {
                    break;
                }
            }
            let final_id = server.core.effect().ok_or(Error::NotReady)?.id;
            let original = server
                .core
                .failure_for_effect(final_id)
                .ok_or(Error::NotReady)?;
            check(original.reason == Error::Capacity && original.request_id == 17)?;
            let mut actual_terminal = None;
            let mut operation_failure = None;
            let mut observations = 0;
            {
                let mut observe = |event| match event {
                    super::Event::EffectTerminal(terminal) => {
                        actual_terminal = Some((terminal.effect.id.value(), terminal.completion));
                    }
                    super::Event::OperationFailed(failure) => {
                        observations += 1;
                        operation_failure = Some(failure);
                    }
                    _ => {}
                };
                server.reject(final_id, Error::Closed, &mut observe)?;
                check(matches!(
                    server.reject(final_id, Error::Closed, &mut observe),
                    Err(super::Error::Protocol(Error::Stale))
                ))?;
            }
            check(actual_terminal == Some((final_id.value(), Completion::Unsent(Error::Closed))))?;
            check(observations == 1)?;
            check(
                operation_failure
                    == Some(super::FailedOperation {
                        failure: original,
                        completion: Completion::Unsent(Error::Closed),
                    }),
            )?;
            check(server.core.failure_for_effect(final_id).is_none())?;
            check(server.cadet.epoch().is_none() && server.report().written_frames == 0)?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })
}
