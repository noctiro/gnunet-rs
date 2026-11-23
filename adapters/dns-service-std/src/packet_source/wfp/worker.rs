//! The original packet file and its upstream sockets stay together off-reactor.
use gnunet_dnsstub_host::SocketReservations;
use gnunet_wfp_dns::device::Completion;
use gnunet_wfp_dns_host::device::{self, Started};
use std::{
    io,
    sync::{Arc, mpsc},
    thread,
};
use tokio::{sync::oneshot, time::Instant};

pub(super) struct Job {
    pub(super) file: Started,
    pub(super) reservations: Arc<SocketReservations>,
    pub(super) observe_reply: bool,
    pub(super) until: Instant,
}

pub(super) struct Receipt {
    pub(super) stop: Result<(), device::Error>,
    pub(super) close: Result<(), device::Error>,
    pub(super) completion: Option<Completion>,
    pub(super) read_error: Option<device::Error>,
    pub(super) wait_error: Option<io::Error>,
}

struct Work {
    job: Box<Job>,
    reply: oneshot::Sender<Receipt>,
}

pub(super) struct Worker(mpsc::SyncSender<Work>);

impl Worker {
    pub(super) fn new() -> io::Result<Self> {
        let (send, receive) = mpsc::sync_channel::<Work>(1);
        thread::Builder::new()
            .name("gnunet-wfp-retire".into())
            .spawn(move || {
                while let Ok(Work { job, reply }) = receive.recv() {
                    let _unobserved = reply.send(retire(*job));
                }
            })?;
        Ok(Self(send))
    }

    pub(super) fn submit(&self, job: Box<Job>) -> Result<oneshot::Receiver<Receipt>, Box<Job>> {
        let (reply, receive) = oneshot::channel();
        self.0
            .try_send(Work { job, reply })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(work) | mpsc::TrySendError::Disconnected(work) => work.job,
            })?;
        Ok(receive)
    }
}

fn retire(job: Job) -> Receipt {
    let Job {
        mut file,
        reservations,
        observe_reply,
        until,
    } = job;
    let stop = file.stop();
    let mut completion = None;
    let mut read_error = None;
    let mut wait_error = None;
    while observe_reply && Instant::now() < until {
        match file.read_completion() {
            Ok(Some(original)) => {
                completion = Some(original);
                break;
            }
            Ok(None) => {}
            Err(error) if error.is_policy_loss() => {
                read_error.get_or_insert(error);
            }
            Err(error) => {
                read_error = Some(error);
                break;
            }
        }
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match file.wait_for_wake(remaining) {
            Ok(_) => {}
            Err(error) => {
                wait_error = Some(error);
                break;
            }
        }
    }
    let close = file.close();
    drop(reservations);
    Receipt {
        stop,
        close,
        completion,
        read_error,
        wait_error,
    }
}
