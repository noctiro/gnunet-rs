use crate::{
    Failure,
    settings::{Input, Settings},
};
use gnunet_program_host::reporting::Reporter;
use gnunet_qr_host as qr;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_uri_host::{Bounds, CloseReport, Dispatcher};
use std::{
    fmt,
    future::{Future, poll_fn},
    io::{self, Read},
    os::unix::fs::OpenOptionsExt,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
#[derive(Debug, Default)]
struct Facts {
    input_bytes: usize,
    camera_steps: u64,
    symbology: Option<i32>,
    symbol_bytes: usize,
}
#[derive(Debug)]
struct Failed {
    original: Option<Failure>,
    camera: Option<qr::Cleanup>,
    handler: CloseReport,
    facts: Facts,
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "QR original={:?}; camera-close={:?}; actual handler={:?}; observations={:?}",
            self.original, self.camera, self.handler, self.facts
        )
    }
}
impl std::error::Error for Failed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_deref()
    }
}
fn gate(d: &mut Dispatcher, cx: &mut Context<'_>) -> Result<(), qr::Error> {
    d.guard(cx).map_err(|e| match e {
        gnunet_uri_host::Cause::Io(e) => qr::Error::Io(e),
        gnunet_uri_host::Cause::Clock(e) => qr::Error::Protocol(e),
    })
}
async fn check(d: &mut Dispatcher) -> Result<(), Failure> {
    poll_fn(|cx| Poll::Ready(d.guard(cx)))
        .await
        .map_err(|e| Box::new(e) as Failure)
}
async fn file(
    d: &mut Dispatcher,
    path: &std::path::Path,
    limits: qr::Limits,
    facts: &mut Facts,
) -> Result<Vec<u8>, Failure> {
    check(d).await?;
    // Nonblocking open avoids waiting for a FIFO writer before the actual fstat
    // can reject it. This does not claim remote filesystems are preemptible.
    let mut input = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    check(d).await?;
    let metadata = input.metadata()?;
    check(d).await?;
    if !metadata.is_file() {
        return Err(
            "bounded PNG input must be a regular file; use explicit camera input for a device"
                .into(),
        );
    }
    let initial = usize::try_from(metadata.len())?;
    if initial > limits.encoded_bytes {
        return Err("PNG input metadata exceeds INPUT_BYTES".into());
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(initial)?;
    if bytes.capacity() > limits.encoded_bytes {
        return Err("PNG encoded allocation exceeds INPUT_BYTES".into());
    }
    let mut scratch = [0u8; 16384];
    loop {
        check(d).await?;
        let remaining = limits
            .encoded_bytes
            .checked_sub(bytes.len())
            .ok_or("PNG input count overflow")?;
        let offer = remaining.saturating_add(1).min(scratch.len());
        let n = match input.read(&mut scratch[..offer]) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            value => value?,
        };
        facts.input_bytes = facts
            .input_bytes
            .checked_add(n)
            .ok_or("PNG input count overflow")?;
        check(d).await?;
        if n == 0 {
            break;
        }
        if n > remaining {
            return Err("actual PNG input grew beyond INPUT_BYTES".into());
        }
        if bytes.len() + n > bytes.capacity() {
            bytes.try_reserve_exact(n)?;
            if bytes.capacity() > limits.encoded_bytes {
                return Err("PNG retained input capacity exceeds INPUT_BYTES".into());
            }
        }
        bytes.extend_from_slice(&scratch[..n]);
        tokio::task::yield_now().await;
    }
    Ok(bytes)
}
/// The same real guard is polled while waiting between finite camera scans.
async fn pause(d: &mut Dispatcher, duration: Duration) -> Result<(), Failure> {
    let mut timer = Box::pin(tokio::time::sleep(duration));
    poll_fn(|cx| {
        d.guard(cx)?;
        match timer.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Ok::<(), gnunet_uri_host::Cause>(())),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
    .map_err(|e| Box::new(e) as Failure)
}
pub(super) async fn run(
    config: &gnunet_config::Configuration,
    clock: Arc<dyn RuntimeClock>,
    settings: Settings,
    reporter: Reporter,
    parent: Option<gnunet_service_startup::ParentControl>,
) -> Result<(), Failure> {
    let bounds = Bounds::new(clock.as_ref(), settings.life)?;
    let mut dispatcher = Dispatcher::new(parent, reporter.clone(), clock, Some(bounds))?;
    let mut camera = None;
    let mut facts = Facts::default();
    let result = async {
        let symbol = match &settings.input {
            Input::Png(path) => {
                let encoded = file(&mut dispatcher, path, settings.limits, &mut facts).await?;
                poll_fn(|cx| {
                    Poll::Ready(qr::scan_png(&encoded, settings.limits, &mut || {
                        gate(&mut dispatcher, cx)
                    }))
                })
                .await?
            }
            Input::Camera(device) => {
                let device = qr::Camera::device(device)?;
                camera = Some(
                    poll_fn(|cx| {
                        Poll::Ready(qr::Camera::open(
                            &device,
                            settings.display,
                            settings.limits,
                            &mut || gate(&mut dispatcher, cx),
                        ))
                    })
                    .await?,
                );
                loop {
                    let result = poll_fn(|cx| {
                        Poll::Ready(
                            camera
                                .as_mut()
                                .ok_or_else(|| {
                                    qr::Error::Io(io::Error::new(
                                        io::ErrorKind::NotConnected,
                                        "original camera owner is unavailable",
                                    ))
                                })?
                                .step(&mut || gate(&mut dispatcher, cx)),
                        )
                    })
                    .await?;
                    facts.camera_steps = facts
                        .camera_steps
                        .checked_add(1)
                        .ok_or("camera step counter overflow")?;
                    if let Some(symbol) = result {
                        break symbol;
                    }
                    pause(
                        &mut dispatcher,
                        Duration::from_millis(u64::from(settings.limits.camera_poll_ms).max(1)),
                    )
                    .await?;
                }
            }
        };
        facts.symbology = Some(symbol.kind());
        facts.symbol_bytes = symbol.bytes().len();
        // Retire the actual camera before a configured handler can start. A
        // decoder result never makes independent source cleanup successful.
        if let Some(mut owner) = camera.take() {
            let cleanup = owner.close();
            if !cleanup.is_clean() {
                return Err(Box::new(CameraClose(cleanup)) as Failure);
            }
        }
        check(&mut dispatcher).await?;
        let selected = gnunet_uri_host::Settings::from_qr_uri(config, symbol.bytes())?;
        dispatcher.start(selected)?;
        let _actual = dispatcher.drive().await?;
        reporter.debug(
            "qr.handler.finished",
            format_args!(
                "actual configured URI handler completed; decoded kind={:?}, bytes={}",
                facts.symbology, facts.symbol_bytes
            ),
        );
        Ok::<(), Failure>(())
    }
    .await;
    let camera = camera.map(|mut c| c.close());
    let handler = dispatcher.close();
    let bad_camera = camera.as_ref().is_some_and(|c| !c.is_clean());
    if result.is_ok()
        && !bad_camera
        && handler.kill.is_none()
        && handler.wait.is_none()
        && !handler.report.undrained
    {
        Ok(())
    } else {
        Err(Box::new(Failed {
            original: result.err(),
            camera,
            handler,
            facts,
        }))
    }
}
#[derive(Debug)]
struct CameraClose(qr::Cleanup);
impl fmt::Display for CameraClose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original camera close failed: {:?}", self.0)
    }
}
impl std::error::Error for CameraClose {}
