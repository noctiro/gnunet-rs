//! Original command orchestration and consuming teardown.
mod drive;
mod failure;
mod scheduling;
use crate::{
    Cause,
    budget::Budget,
    options::Settings,
    state::{Report, SourceMeta, State},
    stdio::Stdio,
};
use drive::{Driving, drive};
use failure::{Errors, Failed};
use gnunet_cadet_host::{self as cadet, Client};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_program_host::{foreground::Stop as Control, reporting::Reporter};
use gnunet_resolver_broker::{Context as Broker, Driver};
use gnunet_service_runtime::clock::RuntimeClock;
pub(super) use scheduling::scheduled;
use std::{io, sync::Arc};
use tokio::time::Instant;

struct Inputs {
    settings: Settings,
    live: LiveConfiguration,
    context: Broker<128, 256>,
    resolver: Driver<128, 256>,
    source: Arc<dyn RuntimeClock>,
    reporter: Reporter,
    control: Control,
    initial: Budget,
}
async fn run(inputs: Inputs) -> Result<Report, Cause> {
    let Inputs {
        settings,
        live,
        context,
        mut resolver,
        source,
        reporter,
        mut control,
        initial,
    } = inputs;
    let mut report = Report::default();
    let mut errors = Errors::default();
    let mut instance = cadet::Instance::new();
    let mut ports = [cadet::PortSlot::new(); 1];
    let mut channels = [cadet::ChannelSlot::new(); 2];
    let outcome = async {
        if Instant::now() >= initial.hard {
            return Err(gnunet_types::Error::Deadline.into());
        }
        let mut stdio = Stdio::new(settings.chunk);
        let mut state = State::new(&settings, initial)?;
        let endpoint = EndpointSource::live(live, b"cadet", context.resolution_context());
        let mut client = Client::new(
            &mut instance,
            endpoint,
            &mut ports,
            &mut channels,
            cadet::Limits {
                io_slice_bytes: settings.io_bytes,
                ..cadet::Limits::default()
            },
        )?;
        // No `?` after constructing the real client: every terminal branch
        // returns through the same close below before Resolver disconnect.
        drive(
            &mut client,
            &mut state,
            Driving {
                stdio: &mut stdio,
                control: &mut control,
                settings: &settings,
                source,
                resolver: &mut resolver,
                reporter: &reporter,
                report: &mut report,
                errors: &mut errors,
            },
        )
        .await;
        // The first close/fatal observation fixes one native target for both
        // protocol retirement and the original stdio jobs. No phase renews it.
        let hard = match state
            .close_hard
            .or_else(|| Instant::now().checked_add(settings.cleanup))
        {
            Some(hard) => hard,
            None => {
                errors.record(Box::new(gnunet_types::Error::Overflow));
                Instant::now()
            }
        };
        match client.close() {
            Ok(loss) => report.close_loss = loss.map(SourceMeta::from_loss),
            Err(error) => errors.close = Some(error),
        }
        drop(client);
        let retired = stdio.retire(hard).await;
        if let Some(count) = retired.input_bytes() {
            report.input_bytes = report.input_bytes.saturating_add(count as u64);
            report.input_unsubmitted = report.input_unsubmitted.saturating_add(count);
        }
        if let Some(count) = retired.output_bytes() {
            if count == 0 {
                errors.output = Some(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "stdout accepted zero bytes of an original payload",
                ));
            } else if let Err(error) = state.wrote_output(count, &mut report) {
                errors.record(Box::new(error));
            }
        }
        report.input_closed = retired.input_closed();
        report.input_cancelled = retired.input_cancelled();
        report.output_closed = retired.output_closed();
        report.output_flushed = retired.output_flushed();
        if !retired.successful() {
            errors.stdio = Some(retired);
        }
        state.final_metadata(&mut report);
        drop(state);
        Ok::<(), Cause>(())
    }
    .await;
    if let Err(error) = outcome {
        errors.record(error);
    }
    if let Err(error) = resolver.disconnect() {
        errors.resolver_close = Some(error);
    }
    drop(resolver);
    reporter.debug(
        "cadet.stream.stopped",
        format_args!("actual local transfer/close facts: {report:?}"),
    );
    errors.logging = reporter.take_error();
    if errors.failed() {
        Err(Box::new(Failed { report, errors }))
    } else {
        Ok(report)
    }
}
