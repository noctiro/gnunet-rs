//! Ordinary SCALARPRODUCT PROGRAM with one original computation/Resolver.
use crate::input::{Selection, Settings};
use gnunet_program_host::{program::Prepared, reporting::Reporter, shared_clock::SharedClock};
use gnunet_scalarproduct_client_host::{
    Bounds, Client, EndpointSource, Epoch, Loss, Progress, Receipt, Response, ResponseStatus, Role,
};
use gnunet_service_runtime::clock::RuntimeClock;
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    io,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::signal::unix::{Signal, SignalKind};
pub(super) type Failure = Box<dyn std::error::Error>;
#[derive(Debug)]
struct Failures {
    original: Option<Failure>,
    cleanup: Vec<Failure>,
    retirement: Option<Loss>,
    receipt: Option<Receipt>,
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(e) = &self.original {
            write!(f, "SCALARPRODUCT: {e}")?;
        }
        if let Some(loss) = &self.retirement {
            write!(f, "; original source cleanup: {loss}")?;
        }
        if let Some(receipt) = &self.receipt {
            write!(f, "; original input: {receipt:?}")?;
        }
        for e in &self.cleanup {
            write!(f, "; cleanup: {e}")?;
        }
        Ok(())
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.cleanup.first().map(|e| e.as_ref()))
            .or_else(|| {
                self.retirement
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
    }
}
struct Signals {
    interrupt: Signal,
    terminate: Signal,
}
impl Signals {
    fn new() -> io::Result<Self> {
        Ok(Self {
            interrupt: tokio::signal::unix::signal(SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(SignalKind::terminate())?,
        })
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        for signal in [&mut self.interrupt, &mut self.terminate] {
            match signal.poll_recv(cx) {
                Poll::Ready(Some(())) => return Poll::Ready(Ok(())),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::other("SCALARPRODUCT signal stream ended")));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}
struct Resolver {
    driver: gnunet_resolver_broker::Driver<16, 1024>,
    closed: bool,
    reporter: Reporter,
    dropped: Rc<RefCell<Option<Failure>>>,
}
impl Drop for Resolver {
    fn drop(&mut self) {
        if !self.closed
            && let Err(error) = self.driver.disconnect()
        {
            self.reporter.warning(
                "scalarproduct.resolver.drop",
                format_args!("SCALARPRODUCT canceled PROGRAM Resolver cleanup: {error}"),
            );
            *self.dropped.borrow_mut() = Some(Box::new(error));
        }
    }
}
struct Native {
    client: Client,
    closed: bool,
    reporter: Reporter,
    dropped: Rc<RefCell<Option<Failure>>>,
}
impl Native {
    fn close(&mut self) -> Loss {
        self.closed = true;
        self.client.close()
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        if !self.closed {
            let loss = self.client.close();
            self.reporter.debug(
                "scalarproduct.source.drop",
                format_args!("SCALARPRODUCT PROGRAM canceled original owner: {loss}"),
            );
            *self.dropped.borrow_mut() = Some(Box::new(loss));
        }
    }
}
/// Run through the actual prepared PROGRAM and its shared Resolver scheduler.
pub(super) async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    selection: Selection,
    reporter: Reporter,
) -> Result<(), Failure> {
    if reporter.failed() {
        return Err("selected SCALARPRODUCT Logger failed".into());
    }
    let config = prepared.main().config.duplicate()?;
    let canonical: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let live = gnunet_resolver_broker::LiveConfiguration::new(config);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<16, 1024>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        canonical.clone(),
    )?;
    let dropped = Rc::new(RefCell::new(None));
    let native_dropped = Rc::new(RefCell::new(None));
    let resolver = Resolver {
        driver: resolver,
        closed: false,
        reporter: reporter.clone(),
        dropped: dropped.clone(),
    };
    let result = Rc::new(RefCell::new(None::<Result<(), Failure>>));
    let receiving = result.clone();
    let receipt = native_dropped.clone();
    let program = prepared
        .run_scheduled(&mut context, clock, 1, move |_main, scope| {
            let destination = receiving.clone();
            let stop = scope.clone();
            if let Err(error) = scope.spawn(async move {
                *destination.borrow_mut() = Some(
                    run(
                        resolver, live, canonical, settings, selection, reporter, receipt,
                    )
                    .await,
                );
                if let Err(error) = stop.shutdown() {
                    let original = destination.borrow_mut().take().and_then(Result::err);
                    *destination.borrow_mut() = Some(Err(Box::new(Failures {
                        original,
                        cleanup: vec![Box::new(error)],
                        retirement: None,
                        receipt: None,
                    })));
                }
            }) {
                *receiving.borrow_mut() = Some(Err(Box::new(error)));
                if let Err(error) = scope.shutdown() {
                    let original = receiving.borrow_mut().take().and_then(Result::err);
                    *receiving.borrow_mut() = Some(Err(Box::new(Failures {
                        original,
                        cleanup: vec![Box::new(error)],
                        retirement: None,
                        receipt: None,
                    })));
                }
            }
        })
        .await;
    let task = result
        .borrow_mut()
        .take()
        .unwrap_or_else(|| Err("PROGRAM ended without SCALARPRODUCT command completion".into()));
    let program: Option<Failure> = match program {
        Ok(1) => None,
        Ok(code) => Some(format!("SCALARPRODUCT PROGRAM returned {code}").into()),
        Err(e) => Some(Box::new(e)),
    };
    let mut cleanup: Vec<Failure> = program.into_iter().collect();
    if let Some(error) = dropped.borrow_mut().take() {
        cleanup.push(error);
    }
    if let Some(loss) = native_dropped.borrow_mut().take() {
        cleanup.push(loss);
    }
    match task {
        Ok(()) if cleanup.is_empty() => Ok(()),
        task => Err(Box::new(Failures {
            original: task.err(),
            cleanup,
            retirement: None,
            receipt: None,
        })),
    }
}
struct ComputationFailure {
    status: u32,
    range: i32,
    product: Vec<u8>,
    receipt: Receipt,
}
impl std::fmt::Debug for ComputationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComputationFailure")
            .field("status", &self.status)
            .field("range", &self.range)
            .field("product_bytes", &self.product.len())
            .field("receipt", &self.receipt)
            .finish()
    }
}
impl std::fmt::Display for ComputationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SCALARPRODUCT service status={} range={} original_MPI_bytes={} receipt={:?}",
            self.status,
            self.range,
            self.product.len(),
            self.receipt
        )
    }
}
impl std::error::Error for ComputationFailure {}
fn same(actual: &Epoch, expected: &Option<Epoch>) -> Result<(), Failure> {
    if expected.as_ref() != Some(actual) {
        return Err(
            "SCALARPRODUCT observation belongs to a different original physical source".into(),
        );
    }
    Ok(())
}
/// C scans signed MPI STD, then adds for range>0 and subtracts otherwise.
/// A leading sign-padding byte and a negative MPI are not unsigned magnitudes.
pub(super) fn result_value(response: &Response) -> num_bigint::BigInt {
    if response.product.is_empty() {
        return num_bigint::BigInt::from(0u8);
    }
    let value = num_bigint::BigInt::from_signed_bytes_be(&response.product);
    if response.range > 0 { value } else { -value }
}
async fn run(
    mut resolver: Resolver,
    live: gnunet_client_host::LiveConfiguration,
    clock: Arc<dyn RuntimeClock>,
    settings: Settings,
    selection: Selection,
    reporter: Reporter,
    dropped: Rc<RefCell<Option<Failure>>>,
) -> Result<(), Failure> {
    let mut signals = Signals::new()?;
    let bounds = Bounds::new(clock.as_ref(), settings.total)?;
    let role = selection.role;
    let source = EndpointSource::live(
        live,
        role.service(),
        resolver.driver.context().resolution_context(),
    );
    let mut native = Native {
        client: Client::new(source, role, selection.elements, settings.native, bounds)?,
        closed: false,
        reporter: reporter.clone(),
        dropped,
    };
    let mut output =
        crate::output::Output::new(settings.output, settings.max_output, bounds, clock)?;
    let mut epoch = None;
    let mut cursor = false;
    let mut finished = false;
    let outcome: Result<(), Failure> = async {
        loop {
            enum Turn {
                Native(Progress),
                Output(bool),
                Activity,
            }
            let turn = poll_fn(|cx| -> Poll<Result<Turn, Failure>> {
                reporter.register(cx);
                if let Poll::Ready(result) = signals.poll(cx) {
                    result?;
                    return Poll::Ready(Err(Box::new(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "SCALARPRODUCT canceled by original signal",
                    )) as Failure));
                }
                if !native.closed
                    && let Some(loss) = native.client.poll_native_guard(cx)
                {
                    return Poll::Ready(Ok(Turn::Native(Progress::Lost(loss))));
                }
                if reporter.failed() {
                    return Poll::Ready(Err("selected SCALARPRODUCT Logger failed".into()));
                }
                for offset in 0..2 {
                    if reporter.failed() {
                        return Poll::Ready(Err(
                            "selected SCALARPRODUCT Logger failed after source callback".into(),
                        ));
                    }
                    if (usize::from(cursor) + offset) % 2 == 0 {
                        let mut driving = std::pin::pin!(resolver.driver.drive_waiting(None, |event| {
                            reporter.debug(
                                "scalarproduct.resolver",
                                format_args!("SCALARPRODUCT Resolver: {event:?}"),
                            )
                        }));
                        match driving.as_mut().poll(cx) {
                            Poll::Ready(Err(error)) => {
                                return Poll::Ready(Err(Box::new(error) as Failure));
                            }
                            Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
                            Poll::Pending => {}
                        }
                    } else if output.pending() {
                        if let Poll::Ready(progress) = output.poll(cx) {
                            return Poll::Ready(progress.map(Turn::Output));
                        }
                    } else if !native.closed {
                        match native.client.poll_progress(cx) {
                            Poll::Ready(Ok(progress)) => {
                                return Poll::Ready(Ok(Turn::Native(progress)));
                            }
                            Poll::Ready(Err(error)) => {
                                return Poll::Ready(Err(Box::new(error) as Failure));
                            }
                            Poll::Pending => {}
                        }
                    }
                }
                if finished && !output.pending() {
                    return Poll::Ready(Ok(Turn::Activity));
                }
                Poll::Pending
            })
            .await?;
            cursor = !cursor;
            match turn {
                Turn::Activity if finished => return Ok(()),
                Turn::Activity | Turn::Output(false) => {}
                Turn::Output(true) => return Ok(()),
                Turn::Native(Progress::Attached(attached)) => {
                    if epoch.is_some() {
                        return Err("SCALARPRODUCT source epoch was replaced".into());
                    }
                    epoch = Some(attached);
                }
                Turn::Native(Progress::Written { epoch: source, receipt, .. }) => {
                    same(&source, &epoch)?;
                    reporter.debug(
                        "scalarproduct.input.write",
                        format_args!("SCALARPRODUCT actual local input: {receipt:?}"),
                    );
                }
                Turn::Native(Progress::Activity) => {}
                Turn::Native(Progress::Retry(error)) => reporter.warning(
                    "scalarproduct.connect.retry",
                    format_args!("SCALARPRODUCT original unattached attempt: {error}"),
                ),
                Turn::Native(Progress::Lost(loss)) => {
                    native.closed = true;
                    return Err(Box::new(loss) as Failure);
                }
                Turn::Native(Progress::Result { response, receipt }) => {
                    native.closed = true;
                    same(
                        receipt.epoch.as_ref().ok_or("SCALARPRODUCT result has no original attached source")?,
                        &epoch,
                    )?;
                    if response.status != ResponseStatus::SUCCESS {
                        return Err(Box::new(ComputationFailure {
                            status: response.status.0,
                            range: response.range,
                            product: response.product,
                            receipt,
                        }) as Failure);
                    }
                    if !receipt.all_input_written {
                        return Err("SCALARPRODUCT success arrived without all original inputs wholly written".into());
                    }
                    reporter.debug(
                        "scalarproduct.result",
                        format_args!("SCALARPRODUCT actual result status={} range={} input={receipt:?}", response.status.0, response.range),
                    );
                    match role {
                        Role::Alice { .. } => {
                            let maximum = response.product.len().checked_mul(2)
                                .and_then(|n| n.checked_add(2))
                                .ok_or("SCALARPRODUCT result display size overflow")?;
                            if maximum > settings.max_output {
                                return Err("SCALARPRODUCT signed result display exceeds stdout budget".into());
                            }
                            let mut text = result_value(&response).to_str_radix(16);
                            text.make_ascii_uppercase();
                            text.push('\n');
                            output.admit(text.into_bytes())?;
                        }
                        Role::Bob { .. } => {
                            reporter.message(
                                gnunet_program_host::policy::Level::INFO,
                                "scalarproduct.complete",
                                format_args!("SCALARPRODUCT responder session completed by actual service result"),
                            );
                            finished = true;
                        }
                    }
                }
            }
        }
    }.await;
    let retirement = if native.closed {
        None
    } else {
        Some(native.close())
    };
    let mut cleanup = Vec::<Failure>::new();
    if let Some(error) = output.abandoned() {
        cleanup.push(error);
    }
    if let Err(error) = resolver.driver.disconnect() {
        cleanup.push(Box::new(error));
    }
    resolver.closed = true;
    match outcome {
        Ok(()) if cleanup.is_empty() && retirement.is_none() => Ok(()),
        outcome => Err(Box::new(Failures {
            original: outcome.err(),
            cleanup,
            retirement,
            receipt: Some(native.client.receipt()),
        })),
    }
}

#[cfg(test)]
mod mpi_cases {
    use super::result_value;
    use gnunet_scalarproduct_client_host::{Response, ResponseStatus};
    #[test]
    fn signed_std_bytes_and_independent_range_follow_c_result_operation() {
        let cases: &[(&[u8], i32, &str)] = &[
            (&[0xff], 1, "-1"),
            (&[0x80], -1, "128"),
            (&[0x00, 0x80], 0, "-128"),
            (&[], -1, "0"),
        ];
        for &(bytes, range, expected) in cases {
            let response = Response {
                status: ResponseStatus::SUCCESS,
                range,
                product: bytes.to_vec(),
            };
            assert_eq!(result_value(&response).to_str_radix(10), expected);
        }
    }
}
