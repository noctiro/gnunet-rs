//! Finite ARM preparation of the selected native account and profile.
use gnunet_native::{
    identity::Sid,
    local_path::EndpointAccess,
    process::{AccountProfile, PrimaryToken},
};
use gnunet_service_runtime::local_listener::AccountBind;
use std::{
    ffi::OsStr,
    future::Future,
    io,
    path::PathBuf,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
    thread,
    time::Duration,
};
use tokio::{
    sync::oneshot,
    time::{self, Sleep},
};

const PREPARATION_LIMIT: Duration = Duration::from_secs(30);
static PREPARING: AtomicBool = AtomicBool::new(false);

struct WorkerCredit;
impl WorkerCredit {
    fn acquire() -> io::Result<Self> {
        PREPARING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::ErrorKind::ResourceBusy)?;
        Ok(Self)
    }
}
impl Drop for WorkerCredit {
    fn drop(&mut self) {
        PREPARING.store(false, Ordering::Release);
    }
}

pub(crate) struct AccountPreparation<T = AccountProfile> {
    result: oneshot::Receiver<io::Result<T>>,
    deadline: Pin<Box<Sleep>>,
}
impl AccountPreparation<AccountProfile> {
    pub(crate) fn begin(sid: &Sid, credential: &OsStr) -> io::Result<Self> {
        Self::start(sid, credential, AccountProfile::load)
    }
}
impl AccountPreparation<AccountBind> {
    pub(crate) async fn for_listener(
        sid: &Sid,
        credential: &OsStr,
        path: PathBuf,
        access: EndpointAccess,
    ) -> io::Result<AccountBind> {
        let mut worker = Self::start(sid, credential, move |token| {
            AccountBind::select(path, access, &token)
        })?;
        std::future::poll_fn(|cx| worker.poll(cx)).await
    }
}
impl<T: Send + 'static> AccountPreparation<T> {
    fn start(
        sid: &Sid,
        credential: &OsStr,
        prepare: impl FnOnce(PrimaryToken) -> io::Result<T> + Send + 'static,
    ) -> io::Result<Self> {
        let credit = WorkerCredit::acquire()?;
        let deadline = Box::pin(time::sleep(PREPARATION_LIMIT));
        let (send, result) = oneshot::channel();
        let sid = sid.clone();
        let credential = credential.to_owned();
        let worker = thread::Builder::new()
            .name("gnunet-arm-account".into())
            .spawn(move || {
                let prepared = PrimaryToken::log_on(&credential, &sid).and_then(prepare);
                // The blocking call has finished. A timed-out or canceled receiver
                // causes a successful profile to schedule its before-launch unload.
                drop(credit);
                drop(send.send(prepared));
            })?;
        drop(worker);
        Ok(Self { result, deadline })
    }

    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        if self.deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Windows service account preparation exceeded its deadline",
            )));
        }
        Pin::new(&mut self.result).poll(cx).map(|result| {
            result.map_err(|_| io::Error::other("Windows service account worker stopped"))?
        })
    }
}
