use super::{Prepared, Session, prepare};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tokio::{sync::oneshot, time::Sleep};

const JOIN_RECHECK: Duration = Duration::from_millis(1);

pub(in crate::packet_source::transparent) struct Restart {
    pub(super) until: Instant,
    cancelled: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<Prepared>>>,
    exit: Option<oneshot::Receiver<()>>,
    join_recheck: Option<Pin<Box<Sleep>>>,
}

impl Restart {
    pub(super) fn launch(session: &Session, until: Instant) -> io::Result<Self> {
        let interfaces = Arc::clone(&session.interfaces);
        Self::start(interfaces, Some(session.namespace), until)
    }

    pub(in crate::packet_source::transparent) fn startup(
        interfaces: Arc<gnunet_native::transparent_dns::exclusion::ConfiguredIngresses>,
        until: Instant,
    ) -> io::Result<Self> {
        Self::start(interfaces, None, until)
    }

    fn start(
        interfaces: Arc<gnunet_native::transparent_dns::exclusion::ConfiguredIngresses>,
        namespace: Option<gnunet_native::transparent_dns::NetworkNamespace>,
        until: Instant,
    ) -> io::Result<Self> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&cancelled);
        let (exited, exit) = oneshot::channel();
        let thread = thread::Builder::new()
            .name("dns-ingress-restart".into())
            .spawn(move || {
                let prepared = prepare(&interfaces, namespace, until, &stopping);
                let _notified = exited.send(());
                prepared
            })?;
        Ok(Self {
            until,
            cancelled,
            thread: Some(thread),
            exit: Some(exit),
            join_recheck: None,
        })
    }

    pub(in crate::packet_source::transparent) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(thread) = &self.thread {
            thread.thread().unpark();
        }
    }

    pub(in crate::packet_source::transparent) const fn is_joined(&self) -> bool {
        self.thread.is_none()
    }

    pub(in crate::packet_source::transparent) fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Prepared>> {
        let Some(thread) = &self.thread else {
            return Poll::Pending;
        };
        if let Some(exit) = &mut self.exit {
            let _hint = ready!(Pin::new(exit).poll(cx));
            self.exit = None;
        }
        if !thread.is_finished() {
            // The receipt can arrive before thread-local teardown. The actual
            // result remains on the join handle until the thread has exited.
            let timer = self
                .join_recheck
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(JOIN_RECHECK)));
            if timer.as_mut().poll(cx).is_ready() {
                timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + JOIN_RECHECK);
                let _armed = timer.as_mut().poll(cx);
            }
            return Poll::Pending;
        }
        self.join_recheck = None;
        let Some(thread) = self.thread.take() else {
            return Poll::Pending;
        };
        Poll::Ready(
            thread.join().unwrap_or_else(|_| {
                Err(io::Error::other("transparent DNS topology worker panicked"))
            }),
        )
    }
}

impl Drop for Restart {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    use tokio::time::timeout;

    #[test]
    fn restart_reports_the_original_result_only_after_join() -> io::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?
            .block_on(check_restart())
    }

    async fn check_restart() -> io::Result<()> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&cancelled);
        let (exited, exit) = oneshot::channel();
        let (observed, cancellation) = oneshot::channel();
        let (release, hold) = oneshot::channel();
        let thread = thread::Builder::new().spawn(move || {
            let _hint = exited.send(());
            while !stopping.load(Ordering::Acquire) {
                thread::park();
            }
            let _noticed = observed.send(());
            hold.blocking_recv().map_err(io::Error::other)?;
            Err(io::ErrorKind::PermissionDenied.into())
        })?;
        let budget = Duration::from_secs(2);
        let mut restart = Restart {
            until: Instant::now() + budget,
            cancelled,
            thread: Some(thread),
            exit: Some(exit),
            join_recheck: None,
        };

        restart.cancel();
        timeout(budget, cancellation)
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        let is_pending = poll_fn(|cx| Poll::Ready(restart.poll(cx).is_pending())).await;
        if !is_pending || restart.is_joined() {
            return Err(io::Error::other("restart retired a live worker"));
        }

        release
            .send(())
            .map_err(|()| io::Error::other("restart worker ended before release"))?;
        let result = timeout(budget, poll_fn(|cx| restart.poll(cx)))
            .await
            .map_err(io::Error::other)?;
        if !matches!(result, Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
            || !restart.is_joined()
        {
            return Err(io::Error::other("restart lost the original worker result"));
        }
        Ok(())
    }
}
