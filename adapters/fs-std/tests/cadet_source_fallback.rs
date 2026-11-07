//! Bounded source UID fallback model; this fixture is not a native service.
#![cfg(feature = "server")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Source model assertions distinguish raw record refusals, exact UID continuation and actual DATA_END from local bounds"
)]
use gnunet_fs::content::encode_data;
use gnunet_fs_host::server::{
    cadet_server::source::{
        BlockSource, Datastore, Failure as SourceFailure, Limits, Progress, Selection,
    },
    ports::{self, Lookup, LookupProgress, StorePort},
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
    cell::RefCell,
    collections::VecDeque,
    rc::Rc,
    task::{Context, Poll, Waker},
};

struct Store {
    replies: VecDeque<Option<OwnedFrame>>,
    reads: Rc<RefCell<Vec<Lookup>>>,
    active: bool,
}
impl StorePort for Store {
    fn start(&mut self, lookup: Lookup) -> Result<(), ports::Error> {
        if self.active {
            return Err(Error::Conflict.into());
        }
        self.reads.borrow_mut().push(lookup);
        self.active = true;
        Ok(())
    }
    fn poll(&mut self, _cx: &mut Context<'_>) -> Poll<Result<LookupProgress, ports::Error>> {
        if !self.active {
            return Poll::Pending;
        }
        self.active = false;
        Poll::Ready(
            self.replies
                .pop_front()
                .map(LookupProgress::Complete)
                .ok_or_else(|| Error::Malformed.into()),
        )
    }
    fn close(&mut self) -> Result<(), ports::Error> {
        self.active = false;
        Ok(())
    }
}
fn record(key: &[u8; 64], uid: u64, kind: u32, value: &[u8]) -> Result<OwnedFrame, Error> {
    let response = Response::Data(Data {
        reservation: 0,
        kind,
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
fn bad_type6_rows_preserve_diagnostics_before_real_uid_fallback_finds_a_block()
-> Result<(), Failure> {
    let mut ciphertext = [0; 128];
    let encoded = encode_data(b"actual encrypted fallback block", &mut ciphertext)?;
    let selection = Selection {
        block_type: BlockType::DBLOCK,
        query: encoded.key().query,
    };
    let malformed = record(&selection.query, 7, 6, &[0x55; 71])?;
    let original_malformed = malformed.bytes().to_vec();
    let descriptor = [0x66; 72];
    let unresolved = record(&selection.query, 9, 6, &descriptor)?;
    let good = record(&selection.query, 12, 1, encoded.bytes())?;
    let reads = Rc::new(RefCell::new(Vec::new()));
    let store = Store {
        replies: VecDeque::from([Some(malformed), Some(unresolved), Some(good)]),
        reads: reads.clone(),
        active: false,
    };
    let mut source = Datastore::new(store, None, Limits::default())?;
    source.start(selection)?;
    assert!(matches!(next(&mut source)?, Progress::Activity));
    let Progress::Skipped(first) = next(&mut source)? else {
        return Err("malformed descriptor was not a nonterminal original-row observation".into());
    };
    assert_eq!(first.selection(), selection);
    assert_eq!(first.record().bytes(), original_malformed);
    assert_eq!(first.data()?.uid, 7);
    assert_eq!(*first.data()?.key, selection.query);
    assert_eq!(first.data()?.value.len(), 71);
    assert!(first.descriptor()?.is_none());
    assert_eq!(
        first.cause().cause().downcast_ref::<Error>(),
        Some(&Error::Malformed)
    );
    assert_eq!(
        reads.borrow().len(),
        1,
        "next GET cannot precede its diagnostic"
    );
    let conflict = source
        .start(selection)
        .err()
        .ok_or("Skipped incorrectly released query ownership")?;
    assert_eq!(
        conflict.cause().downcast_ref::<Error>(),
        Some(&Error::Conflict)
    );
    assert!(matches!(next(&mut source)?, Progress::Activity));
    let Progress::Skipped(second) = next(&mut source)? else {
        return Err(
            "missing explicit resolver was not a nonterminal original-row observation".into(),
        );
    };
    assert_eq!(second.data()?.uid, 9);
    assert_eq!(second.descriptor()?, Some(&descriptor));
    assert_eq!(
        second.cause().cause().downcast_ref::<Error>(),
        Some(&Error::Unsupported)
    );
    assert_eq!(reads.borrow().len(), 2);
    assert!(matches!(next(&mut source)?, Progress::Activity));
    let Progress::Found(block) = next(&mut source)? else {
        return Err("a bad first row hid the later actual block".into());
    };
    assert_eq!(block.data()?.uid, 12);
    assert_eq!(block.data()?.kind, 1);
    assert_eq!(block.data()?.value, encoded.bytes());
    let reads = reads.borrow();
    assert_eq!(
        reads
            .iter()
            .map(|lookup| lookup.next_uid)
            .collect::<Vec<_>>(),
        [0, 8, 10]
    );
    assert!(
        reads
            .iter()
            .all(|lookup| lookup.key == selection.query && lookup.kind == 0)
    );
    drop(reads);
    source.close()?;
    Ok(())
}

#[test]
fn local_record_limit_and_uid_overflow_never_turn_into_storage_end() -> Result<(), Failure> {
    let selection = Selection {
        block_type: BlockType::DBLOCK,
        query: [7; 64],
    };
    for (uid, records, expected) in [(10, 1, Error::Capacity), (u64::MAX, 2, Error::Overflow)] {
        let reads = Rc::new(RefCell::new(Vec::new()));
        let bad = record(&selection.query, uid, 6, &[0; 71])?;
        let store = Store {
            replies: VecDeque::from([Some(bad), None]),
            reads: reads.clone(),
            active: false,
        };
        let mut source = Datastore::new(
            store,
            None,
            Limits {
                records,
                ..Limits::default()
            },
        )?;
        source.start(selection)?;
        assert!(matches!(next(&mut source)?, Progress::Activity));
        let Progress::Skipped(row) = next(&mut source)? else {
            return Err("bounded bad record lost its original diagnostic".into());
        };
        assert_eq!(row.data()?.uid, uid);
        let error = next(&mut source)
            .err()
            .ok_or("a local bound became an invented source result")?;
        assert_eq!(error.cause().downcast_ref::<Error>(), Some(&expected));
        assert_eq!(
            reads.borrow().len(),
            1,
            "bound failure must not issue a wrapped/replayed GET"
        );
        source.close()?;
    }
    Ok(())
}
