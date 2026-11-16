//! One retained PROGRAM task owns DNS IPC, Resolver and shutdown observations.
use crate::{program::Settings, session};
use gnunet_dns_client_host::EndpointSource;
use gnunet_program_host::{
    foreground, program::Prepared, reporting::Reporter, shared_clock::SharedClock,
};
use gnunet_resolver_broker::LiveConfiguration;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::ParentControl;
use std::{cell::Cell, error::Error, fmt, io, rc::Rc, sync::Arc};
pub(super) type Failure = Box<dyn Error>;
#[derive(Debug, Default)]
pub(super) struct Failures {
    pub program: Option<Failure>,
    pub task: Option<Failure>,
    pub resolver: Option<Failure>,
    pub logging: Option<io::Error>,
}
impl fmt::Display for Failures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DNS utility failures: {self:?}")
    }
}
impl Error for Failures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.program
            .as_deref()
            .or(self.task.as_deref())
            .or(self.resolver.as_deref())
            .or_else(|| self.logging.as_ref().map(|error| error as _))
    }
}
impl Failures {
    pub fn finish(self) -> Result<(), Failure> {
        if self.program.is_none()
            && self.task.is_none()
            && self.resolver.is_none()
            && self.logging.is_none()
        {
            Ok(())
        } else {
            Err(Box::new(self))
        }
    }
}
pub(super) async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    mut settings: Settings,
    reporter: Reporter,
    parent: Option<ParentControl>,
) -> Result<(), Failure> {
    let result = async {
        let config = prepared.main().config.duplicate()?;
        let native_clock: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
        let live = LiveConfiguration::new(config);
        let (mut context, resolver) = gnunet_resolver_broker::broker::<8, 256>(
            live.clone(),
            Default::default(),
            gnunet_resolver_broker::native_profile()?,
            native_clock.clone(),
        )?;
        let source = match settings.socket.take() {
            Some(path) => EndpointSource::unix_with_clock(path, native_clock),
            None => EndpointSource::live(live, b"dns", context.resolution_context()),
        };
        let stop = Rc::new(Cell::new(false));
        let product = session::run(
            source,
            resolver,
            settings,
            reporter.clone(),
            stop.clone(),
            parent,
        );
        foreground::run(prepared, &mut context, clock, stop, product)
            .await
            .map(|_report| ())
    }
    .await;
    if let Err(error) = &result {
        reporter.warning("dns.utility.failed", format_args!("{error}"));
    }
    Failures {
        program: result.err(),
        logging: reporter.take_error(),
        ..Default::default()
    }
    .finish()
}
