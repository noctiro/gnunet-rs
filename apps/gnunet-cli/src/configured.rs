//! Shared PROGRAM startup and bounded resolver ownership for installed commands.
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_config::{Configuration, ProjectData};
use gnunet_program_host::{
    getopt::Options,
    logging::Logger,
    program::{self, Defaults, Invocation, Preparation},
    shared_clock::SharedClock,
};
use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    sync::Arc,
    task::Poll,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub(crate) fn prepare(
    binary: &'static [u8],
    help: &'static [u8],
    options: Options<'_>,
) -> Result<Option<(Box<program::Prepared>, SharedClock)>> {
    let clock = SharedClock::native(128)?;
    let configuration =
        Configuration::create(Arc::new(ProjectData::default()), Default::default())?;
    let mut logger = Logger::new(binary, std::process::id(), false)?;
    let preparation = program::prepare_installed(
        configuration,
        Invocation {
            binary_name: binary,
            help: Some(help),
            select_default_filename: true,
            defaults: Defaults::Native,
        },
        options,
        std::env::args_os(),
        &program::Environment::capture(),
        &mut logger,
        &clock,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )?;
    match preparation {
        Preparation::Ready(prepared) => Ok(Some((prepared, clock))),
        Preparation::Stopped(stopped)
            if stopped.code == 0 && matches!(stopped.reason, program::StoppedReason::Options) =>
        {
            Ok(None)
        }
        Preparation::Stopped(stopped) => Err(format!(
            "PROGRAM stopped: {:?}, code {}",
            stopped.reason, stopped.code
        )
        .into()),
    }
}

pub(crate) fn run<T, F, const N: usize>(
    config: &Configuration,
    clock: SharedClock,
    sections: [&'static [u8]; N],
    operation: impl FnOnce([EndpointSource; N]) -> F,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let live = LiveConfiguration::new(config.duplicate()?);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(drive(live, clock, sections, operation))
}

async fn drive<T, F, const N: usize>(
    live: LiveConfiguration,
    clock: SharedClock,
    sections: [&'static [u8]; N],
    operation: impl FnOnce([EndpointSource; N]) -> F,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let (context, resolver) = gnunet_resolver_broker::broker::<4, 256>(
        live.clone(),
        gnunet_resolver_broker::Limits {
            max_frame_bytes: 4096,
            io_chunk_bytes: 4096,
            max_queued_frames: 4,
        },
        gnunet_resolver_broker::native_profile()?,
        Arc::new(clock),
    )?;
    let resolution = context.resolution_context();
    let mut operation =
        std::pin::pin!(operation(sections.map(|name| {
            EndpointSource::live(live.clone(), name, resolution.clone())
        })));
    let mut resolver = Some(resolver);
    let mut resolver_failure = None;
    let result = poll_fn(|cx| {
        if let Poll::Ready(result) = operation.as_mut().poll(cx) {
            return Poll::Ready(result);
        }
        let step = resolver.as_mut().map(|driver| {
            std::pin::pin!(driver.drive_waiting(None, |_| {}))
                .as_mut()
                .poll(cx)
        });
        match step {
            Some(Poll::Ready(Err(error))) => {
                resolver_failure = Some(error);
                drop(resolver.take());
                cx.waker().wake_by_ref();
            }
            Some(Poll::Ready(Ok(_))) => cx.waker().wake_by_ref(),
            None | Some(Poll::Pending) => {}
        }
        Poll::Pending
    })
    .await;
    let cleanup = match (resolver, resolver_failure) {
        (Some(mut resolver), _) => resolver.disconnect(),
        (None, Some(error)) => Err(error),
        (None, None) => Ok(()),
    };
    match (result, cleanup) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(Box::new(error)),
        (Err(operation), Err(resolver)) => Err(Box::new(ResolverCleanup {
            operation,
            resolver: Box::new(resolver),
        })),
    }
}

#[derive(Debug)]
struct ResolverCleanup {
    operation: Box<dyn Error>,
    resolver: Box<dyn Error>,
}

impl fmt::Display for ResolverCleanup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (resolver cleanup: {})",
            self.operation, self.resolver
        )
    }
}

impl Error for ResolverCleanup {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.operation.as_ref())
    }
}
