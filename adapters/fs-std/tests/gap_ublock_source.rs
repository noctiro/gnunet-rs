//! Actual signed source rows, bounded UID continuations and safe retirement.
//! This deterministic StorePort fixture does not claim native DATASTORE IO.
#![cfg(feature = "server")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible source models assert original row/cause/UID and explicit multi-result ownership"
)]
use gnunet_crypto::{gns::EdkeySecret, hash512};
use gnunet_fs::ublock;
use gnunet_fs_host::server::{
    cadet_server::source::{
        BlockSource, Datastore, Failure as SourceFailure, Limits, Progress, Retirement, Selection,
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
    fn start(&mut self, request: Lookup) -> Result<(), ports::Error> {
        if self.active {
            return Err(Error::Conflict.into());
        }
        self.reads.borrow_mut().push(request);
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
fn signed(value: u8) -> Result<([u8; 64], Vec<u8>), Error> {
    let secret = EdkeySecret::from_seed([17; 32]);
    let signer = secret.derive_bytes(b"same query", b"fs-ublock")?;
    let key = signer.public_key();
    let mut bytes = vec![0; 105];
    bytes[64..68].copy_from_slice(&41u32.to_be_bytes());
    bytes[68..72].copy_from_slice(&ublock::PURPOSE.to_be_bytes());
    bytes[72..104].copy_from_slice(&key);
    bytes[104] = value;
    let sig = signer.sign(ublock::PURPOSE, &[&bytes[64..]])?;
    bytes[..64].copy_from_slice(&sig);
    Ok((hash512(&key), bytes))
}
fn row(key: &[u8; 64], uid: u64, value: &[u8]) -> Result<OwnedFrame, Error> {
    let mut bytes = vec![0; DATA_LEN + value.len()];
    Response::Data(Data {
        reservation: 0,
        kind: 9,
        priority: 0,
        anonymity: 0,
        replication: 0,
        uid,
        expiration: AbsoluteTime::NEVER,
        key,
        value,
    })
    .encode(&mut bytes)?;
    Ok(OwnedFrame::new(bytes))
}
fn next(source: &mut Datastore<Store>) -> Result<Progress, SourceFailure> {
    match source.poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result,
        Poll::Pending => Err(SourceFailure::operation(Error::WouldBlock)),
    }
}
#[test]
fn multi_source_pause_precedes_next_get_and_cancel_never_becomes_data_end() -> Result<(), Failure> {
    let (query, first) = signed(1)?;
    let (_, second) = signed(2)?;
    for cancel in [false, true] {
        let mut invalid = first.clone();
        invalid[0] ^= 1;
        let reads = Rc::new(RefCell::new(Vec::new()));
        let store = Store {
            replies: VecDeque::from([
                Some(row(&query, 3, &invalid)?),
                Some(row(&query, 7, &first)?),
                Some(row(&query, 11, &second)?),
                None,
            ]),
            reads: reads.clone(),
            active: false,
        };
        let mut source = Datastore::new(store, None, Limits::default())?;
        let selection = Selection {
            block_type: BlockType::ANY,
            query,
        };
        source.start_stream(selection)?;
        let early_resume = source
            .resume()
            .err()
            .ok_or("resume accepted before any original item")?;
        assert_eq!(
            early_resume.cause().downcast_ref::<Error>(),
            Some(&Error::Conflict)
        );
        assert!(reads.borrow().is_empty());
        assert!(matches!(next(&mut source)?, Progress::Activity));
        let Progress::Skipped(rejected) = next(&mut source)? else {
            return Err("invalid original signed row was hidden".into());
        };
        assert_eq!(rejected.data()?.uid, 3);
        assert_eq!(rejected.record().bytes(), row(&query, 3, &invalid)?.bytes());
        assert_eq!(reads.borrow().len(), 1);
        assert!(matches!(next(&mut source)?, Progress::Activity));
        let Progress::Candidate(one) = next(&mut source)? else {
            return Err("first actual multi-result became terminal".into());
        };
        assert_eq!(one.data()?.value, first);
        assert_eq!(one.data()?.uid, 7);
        assert!(
            source
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(
            reads.borrow().len(),
            2,
            "paused original item cannot admit the next UID GET"
        );
        source.resume()?;
        assert!(matches!(next(&mut source)?, Progress::Activity));
        let Progress::Candidate(two) = next(&mut source)? else {
            return Err("second actual multi-result was lost".into());
        };
        assert_eq!(two.data()?.value, second);
        assert_eq!(two.data()?.uid, 11);
        assert_eq!(
            reads
                .borrow()
                .iter()
                .map(|r| r.next_uid)
                .collect::<Vec<_>>(),
            [0, 4, 8]
        );
        assert!(reads.borrow().iter().all(|r| r.kind == 0 && r.key == query));
        if cancel {
            source.request_retire();
            let Progress::Retired(retired) = next(&mut source)? else {
                return Err("local safe retirement became a storage terminal".into());
            };
            assert_eq!(retired.selection, selection);
            assert!(matches!(retired.observation, Retirement::Unsubmitted));
            assert_eq!(
                reads.borrow().len(),
                3,
                "retirement admitted a needless continuation GET"
            );
        } else {
            source.resume()?;
            assert!(matches!(next(&mut source)?, Progress::Activity));
            assert!(matches!(next(&mut source)?, Progress::NotFound));
            assert_eq!(
                reads
                    .borrow()
                    .iter()
                    .map(|r| r.next_uid)
                    .collect::<Vec<_>>(),
                [0, 4, 8, 12]
            );
        }
        source.close()?;
    }
    Ok(())
}
