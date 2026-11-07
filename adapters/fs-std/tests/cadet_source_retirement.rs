//! Two bounded source-owner models; no native service/worker is started.
#![cfg(feature = "server")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Owner models distinguish an admitted operation's actual terminal, an unsubmitted continuation and a permanently unavailable dependency"
)]
use gnunet_fs_host::server::{
    self,
    cadet_server::source::{
        Availability, BlockSource, Datastore, Failure as SourceFailure, Limits, Progress, Retired,
        Retirement, Selection,
    },
    ports::{self, Lookup, LookupProgress, StorePort, StoreState},
};
use gnunet_service_runtime::framing::OwnedFrame;

type Failure = Box<dyn std::error::Error + Send + Sync>;
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    datastore::{DATA_LEN, Data, Response},
    fs::BlockType,
};
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
};

struct Refusal {
    reason: Error,
    permanently_closed: bool,
}
struct Store {
    replies: VecDeque<Result<Option<OwnedFrame>, Refusal>>,
    reads: Rc<RefCell<Vec<Lookup>>>,
    terminal_ready: Rc<Cell<bool>>,
    state: StoreState,
    active: bool,
}
impl StorePort for Store {
    fn state(&self) -> StoreState {
        self.state
    }
    fn start(&mut self, lookup: Lookup) -> Result<(), ports::Error> {
        if self.state == StoreState::Closed {
            return Err(Error::Closed.into());
        }
        if self.active {
            return Err(Error::Conflict.into());
        }
        self.reads.borrow_mut().push(lookup);
        self.active = true;
        Ok(())
    }
    fn poll(&mut self, _cx: &mut Context<'_>) -> Poll<Result<LookupProgress, ports::Error>> {
        if !self.active || !self.terminal_ready.get() {
            return Poll::Pending;
        }
        self.active = false;
        Poll::Ready(match self.replies.pop_front() {
            Some(Ok(frame)) => Ok(LookupProgress::Complete(frame)),
            Some(Err(refusal)) => {
                if refusal.permanently_closed {
                    self.state = StoreState::Closed;
                }
                Err(refusal.reason.into())
            }
            None => Err(Error::Malformed.into()),
        })
    }
    fn close(&mut self) -> Result<(), ports::Error> {
        self.state = StoreState::Closed;
        self.active = false;
        Ok(())
    }
}
fn record(key: &[u8; 64], uid: u64, value: &[u8]) -> Result<OwnedFrame, Error> {
    let response = Response::Data(Data {
        reservation: 0,
        kind: 6,
        priority: 0,
        anonymity: 0,
        replication: 0,
        uid,
        expiration: AbsoluteTime::NEVER,
        key,
        value,
    });
    let mut bytes = vec![0; DATA_LEN + value.len()];
    response.encode(&mut bytes)?;
    Ok(OwnedFrame::new(bytes))
}
fn next(source: &mut Datastore<Store>) -> Result<Progress, SourceFailure> {
    let mut cx = Context::from_waker(Waker::noop());
    match source.poll(&mut cx) {
        Poll::Ready(result) => result,
        Poll::Pending => Err(SourceFailure::operation(Error::WouldBlock)),
    }
}

#[test]
fn retirement_drains_original_get_but_never_admits_its_uid_continuation() -> Result<(), Failure> {
    let selection = Selection {
        block_type: BlockType::DBLOCK,
        query: [0x55; 64],
    };
    let raw = record(&selection.query, 7, &[0x11; 72])?;
    let raw_bytes = raw.bytes().to_vec();
    let bad = record(&selection.query, 9, &[0x22; 71])?;
    let bad_bytes = bad.bytes().to_vec();
    let reads = Rc::new(RefCell::new(Vec::new()));
    let terminal_ready = Rc::new(Cell::new(false));
    let store = Store {
        replies: VecDeque::from([Ok(Some(raw)), Ok(Some(bad)), Ok(None)]),
        reads: reads.clone(),
        terminal_ready: terminal_ready.clone(),
        state: StoreState::Open,
        active: false,
    };
    let mut source = Datastore::new(store, None, Limits::default())?;
    source.start(selection)?;
    assert!(matches!(next(&mut source)?, Progress::Activity));
    source.request_retire();
    source.request_retire();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(source.poll(&mut cx).is_pending());
    let conflict = source
        .start(selection)
        .err()
        .ok_or("retirement lost admitted GET")?;
    assert_eq!(
        conflict.cause().downcast_ref::<Error>(),
        Some(&Error::Conflict)
    );
    assert_eq!(reads.borrow().len(), 1);
    terminal_ready.set(true);
    let Progress::Retired(retired) = next(&mut source)? else {
        return Err("actual GET completion became a fabricated negative/result".into());
    };
    assert_eq!(retired.selection, selection);
    let Retirement::Data(actual) = retired.observation else {
        return Err("retired GET lost its exact original DATA".into());
    };
    assert_eq!(actual.bytes(), raw_bytes);
    assert_eq!(
        reads.borrow().len(),
        1,
        "no fresh resolve/GET follows retirement"
    );

    // This separate live query legitimately observes one rejected row. Its
    // continuation exists locally but has not yet admitted another native GET.
    source.start(selection)?;
    assert!(matches!(next(&mut source)?, Progress::Activity));
    let Progress::Skipped(rejected) = next(&mut source)? else {
        return Err("original rejected row was not observed".into());
    };
    assert_eq!(reads.borrow().len(), 2);
    source.request_retire();
    let Progress::Retired(retired) = next(&mut source)? else {
        return Err("unsubmitted UID continuation did not explicitly retire".into());
    };
    assert_eq!(retired.selection, selection);
    assert!(matches!(retired.observation, Retirement::Unsubmitted));
    assert_eq!(rejected.record().bytes(), bad_bytes);
    assert_eq!(rejected.data()?.uid, 9);
    assert_eq!(
        rejected.cause().cause().downcast_ref::<Error>(),
        Some(&Error::Malformed)
    );
    assert_eq!(
        reads.borrow().len(),
        2,
        "the next UID GET must remain unsubmitted"
    );

    // An explicit subsequent owner still gets its actual DATA_END; it is not a
    // replay or a successful completion inferred from either retirement.
    source.start(selection)?;
    assert!(matches!(next(&mut source)?, Progress::Activity));
    assert!(matches!(next(&mut source)?, Progress::NotFound));
    assert_eq!(reads.borrow().len(), 3);
    source.close()?;
    Ok(())
}

#[test]
fn permanent_port_loss_has_original_cause_and_outranks_local_retirement() -> Result<(), Failure> {
    let selection = Selection {
        block_type: BlockType::DBLOCK,
        query: [0x77; 64],
    };
    let reads = Rc::new(RefCell::new(Vec::new()));
    let store = Store {
        replies: VecDeque::from([
            Ok(Some(record(&selection.query, 3, &[0; 71])?)),
            Err(Refusal {
                reason: Error::WouldBlock,
                permanently_closed: false,
            }),
            Err(Refusal {
                reason: Error::Authentication,
                permanently_closed: true,
            }),
        ]),
        reads: reads.clone(),
        terminal_ready: Rc::new(Cell::new(true)),
        state: StoreState::Open,
        active: false,
    };
    let mut source = Datastore::new(
        store,
        None,
        Limits {
            records: 1,
            ..Limits::default()
        },
    )?;
    source.start(selection)?;
    assert!(matches!(next(&mut source)?, Progress::Activity));
    let Progress::Skipped(row) = next(&mut source)? else {
        return Err("bad row was incorrectly promoted to backend loss".into());
    };
    assert_eq!(
        row.cause().cause().downcast_ref::<Error>(),
        Some(&Error::Malformed)
    );
    let bound = next(&mut source)
        .err()
        .ok_or("row bound invented a terminal result")?;
    assert_eq!(
        bound.cause().downcast_ref::<Error>(),
        Some(&Error::Capacity)
    );
    assert_eq!(source.availability(), Availability::Open);

    source.start(selection)?;
    assert!(matches!(next(&mut source)?, Progress::Activity));
    source.request_retire();
    let Progress::Retired(retired) = next(&mut source)? else {
        return Err("ordinary actual failure lost its retired owner".into());
    };
    assert!(matches!(
        retired
            .cause()
            .and_then(|cause| cause.cause().downcast_ref::<ports::Error>()),
        Some(ports::Error::Protocol(Error::WouldBlock))
    ));
    assert_eq!(source.availability(), Availability::Open);

    source.start(selection)?;
    assert!(matches!(next(&mut source)?, Progress::Activity));
    source.request_retire();
    let Progress::Unavailable {
        selection: original,
        cause,
    } = next(&mut source)?
    else {
        return Err("actual permanent Closed was hidden by local retirement".into());
    };
    assert_eq!(original, selection);
    assert!(matches!(
        cause.cause().downcast_ref::<ports::Error>(),
        Some(ports::Error::Protocol(Error::Authentication))
    ));
    assert_eq!(source.availability(), Availability::Unavailable);
    let error = source
        .start(selection)
        .err()
        .ok_or("closed backend admitted another query")?;
    assert_eq!(error.cause().downcast_ref::<Error>(), Some(&Error::Closed));
    assert_eq!(reads.borrow().len(), 3);

    // Model the exact typed retired cause consumed by the foreground. Scope
    // survives diagnostic wrapping; this is not an actual worker startup/drain.
    let fatal = Retired {
        selection,
        observation: Retirement::Failed(SourceFailure::service(Arc::new(
            server::Error::WorkerGone,
        ))),
    };
    assert!(fatal.cause().is_some_and(SourceFailure::is_fatal));
    assert!(fatal.cause().is_some_and(|cause| matches!(cause.cause().downcast_ref::<Arc<server::Error>>(), Some(error) if error.is_fatal())));
    source.close()?;
    assert_eq!(source.availability(), Availability::Closed);
    Ok(())
}
