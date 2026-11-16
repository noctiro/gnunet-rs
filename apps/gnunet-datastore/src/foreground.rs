//! PROGRAM composition and independent client, Resolver and stream retirement.
mod driver;
mod outcome;
mod records;
use crate::{Failure, control::Signals, stream};
pub(super) use driver::{Budget, Driver};
use gnunet_client_host::{EndpointSource, LiveConfiguration, resolution::SharedResolution};
use gnunet_datastore_host::{self as host, Client};
use gnunet_program_host::reporting::Reporter;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::ParentControl;
use gnunet_types::Duration as Timeout;
pub(super) use outcome::Report;
use outcome::{Close, Failed};
use std::{
    cell::{Cell, RefCell},
    path::PathBuf,
    rc::Rc,
    sync::Arc,
};
use zeroize::Zeroizing;
pub(super) struct Inputs {
    pub dump: bool,
    pub streams: stream::Retained,
    pub insert: bool,
    pub path: Option<PathBuf>,
    pub parent: Option<ParentControl>,
    pub live: LiveConfiguration,
    pub resolution: SharedResolution,
    pub source: Arc<dyn RuntimeClock>,
    pub reports: Reporter,
    pub stop: Rc<Cell<bool>>,
    pub resolver: gnunet_resolver_broker::Driver<4, 256>,
}
#[derive(Debug)]
struct ResolverCleanup(Option<Failure>);
struct ResolverOwner {
    driver: gnunet_resolver_broker::Driver<4, 256>,
    cleanup: Rc<RefCell<ResolverCleanup>>,
    closed: bool,
}
impl ResolverOwner {
    fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            let result = self.driver.disconnect();
            if let Err(error) = result {
                self.cleanup.borrow_mut().0 = Some(Box::new(error));
            }
        }
    }
}
impl Drop for ResolverOwner {
    fn drop(&mut self) {
        self.close();
    }
}
fn buffer(length: usize) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    bytes.resize(length, 0);
    Ok(Zeroizing::new(bytes))
}
pub(super) async fn command(inputs: Inputs) -> Result<Report, Failure> {
    let Inputs {
        dump,
        insert,
        path,
        parent,
        live,
        resolution,
        source,
        reports,
        stop,
        resolver,
        streams,
    } = inputs;
    let cleanup = Rc::new(RefCell::new(ResolverCleanup(None)));
    let mut resolver = ResolverOwner {
        driver: resolver,
        cleanup: cleanup.clone(),
        closed: false,
    };
    let mut report = Report::default();
    let mut client_close = Close::default();
    let result: Result<(), Failure> = async {
        if stop.get() || reports.failed() {
            return Err("DATASTORE stopped before native admission".into());
        }
        let signals = Signals::new(parent)?;
        let mut instance = host::Instance::new();
        let mut storage = buffer(65535)?;
        let mut slots = [host::Slot::new(&mut storage)];
        let mut reservations = [host::ReservationSlot::default()];
        let protocol = host::ProtocolClient::new(
            &mut instance,
            &mut slots,
            &mut reservations,
            host::ProtocolLimits {
                max_pending: 1,
                max_frame_bytes: 65535,
                max_lifetime: Timeout(30_000_000),
                drain_timeout: Timeout(5_000_000),
            },
        )?;
        let endpoint = EndpointSource::live(live, b"datastore", resolution).snapshot()?;
        let client = Client::new(
            protocol,
            endpoint,
            host::Limits {
                frame_bytes: 65535,
                reply_frames: 1,
                reply_bytes: 65535,
                io_slice_bytes: 65535,
            },
        )?;
        let mut driver = Driver {
            client,
            resolver: &mut resolver.driver,
            signals,
            source: source.clone(),
            reports: reports.clone(),
            stop: stop.clone(),
            pending: None,
            report: Report::default(),
            cursor: false,
            closed: false,
        };
        let actual =
            records::work(&mut driver, dump, insert, path.as_deref(), streams.clone()).await;
        client_close = driver.close();
        report = driver.report;
        actual
    }
    .await;
    resolver.close();
    let resolver_error = cleanup.borrow_mut().0.take();
    let logging = reports.take_error();
    let source_failed = client_close.native.is_some() || client_close.take.is_some();
    if result.is_err() || source_failed || resolver_error.is_some() || logging.is_some() {
        Err(Box::new(Failed {
            original: result.err(),
            client: client_close,
            resolver: resolver_error,
            streams: stream::Cleanup::default(),
            logging,
            report,
        }))
    } else {
        Ok(report)
    }
}
pub(super) fn finish(
    result: Result<Report, Failure>,
    reports: Reporter,
    retained: stream::Retained,
) -> Result<(), Failure> {
    if let Ok(report) = &result {
        reports.debug(
            "datastore.completed",
            format_args!("actual DATASTORE counters={report:?}"),
        );
    }
    let logging = reports.take_error();
    let completed = result.as_ref().ok().copied().unwrap_or_default();
    let streams = std::mem::take(&mut *retained.borrow_mut());
    if logging.is_some() || streams.failed() {
        Err(Box::new(Failed {
            original: result.err(),
            client: Close::default(),
            resolver: None,
            streams,
            logging,
            report: completed,
        }))
    } else {
        result.map(|_| ())
    }
}
