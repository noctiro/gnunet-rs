//! Actual official request/response routing against a small deterministic backend.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible service tests assert protocol fields, accounting and before-effect refusal"
)]
use gnunet_datastore::{backend::*, *};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    datastore::{Data, Request, Response},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Debug)]
struct TestError(Failure);
impl BackendError for TestError {
    fn certainty(&self) -> Failure {
        self.0
    }
}
impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "test backend {:?}", self.0)
    }
}
impl std::error::Error for TestError {}
struct Stored {
    meta: Meta,
    value: Vec<u8>,
}
#[derive(Default)]
struct Memory {
    values: Vec<Stored>,
    next: u64,
    fail: Option<Failure>,
    puts: usize,
    selections: usize,
    maintenance: usize,
    drops: usize,
}
impl Memory {
    fn error(&mut self) -> Result<(), TestError> {
        self.fail
            .take()
            .map_or(Ok(()), |failure| Err(TestError(failure)))
    }
}
impl Backend for Memory {
    type Error = TestError;
    fn usage(&self) -> Usage {
        Usage {
            entries: self.values.len() as u64,
            value_bytes: self.values.iter().map(|v| v.value.len() as u64).sum(),
        }
    }
    fn put(&mut self, value: Put<'_>, policy: PutPolicy) -> Result<PutReport, TestError> {
        self.puts += 1;
        self.error()?;
        if let Some(old) = self
            .values
            .iter_mut()
            .find(|old| old.meta.key == *value.key && old.value == value.value)
        {
            old.meta.priority = old.meta.priority.saturating_add(value.priority);
            old.meta.replication = old.meta.replication.saturating_add(value.replication);
            old.meta.expiration = old.meta.expiration.max(value.expiration);
            return Ok(PutReport {
                inserted: false,
                maintenance: Maintenance::default(),
            });
        }
        let used = self
            .usage()
            .charged()
            .map_err(|_| TestError(Failure::BeforeCommit))?;
        if u128::from(used) + value.value.len() as u128 + u128::from(ENTRY_OVERHEAD)
            > u128::from(policy.ceiling_bytes)
        {
            return Err(TestError(Failure::BeforeCommit));
        }
        self.next += 1;
        self.values.push(Stored {
            meta: Meta {
                uid: self.next,
                key: *value.key,
                kind: value.kind,
                priority: value.priority,
                anonymity: value.anonymity,
                replication: value.replication,
                expiration: value.expiration,
            },
            value: value.value.to_vec(),
        });
        Ok(PutReport {
            inserted: true,
            maintenance: Maintenance::default(),
        })
    }
    fn select(
        &mut self,
        selection: Selection<'_>,
        random: u64,
    ) -> Result<Option<Record<'_>>, TestError> {
        self.selections += 1;
        self.error()?;
        let mut candidates: Vec<usize> = self
            .values
            .iter()
            .enumerate()
            .filter(|(_, v)| match selection {
                Selection::Get {
                    key,
                    kind,
                    next_uid,
                    random,
                } => {
                    key.is_none_or(|key| *key == v.meta.key)
                        && (kind == 0 || kind == v.meta.kind)
                        && (random || v.meta.uid >= next_uid)
                }
                Selection::ZeroAnonymity { kind, next_uid } => {
                    kind == v.meta.kind && v.meta.anonymity == 0 && v.meta.uid >= next_uid
                }
                Selection::Replication => true,
            })
            .map(|(i, _)| i)
            .collect();
        if matches!(selection, Selection::Replication) {
            let highest = candidates
                .iter()
                .map(|i| self.values[*i].meta.replication)
                .max();
            candidates.retain(|i| Some(self.values[*i].meta.replication) == highest);
        }
        candidates.sort_unstable_by_key(|i| self.values[*i].meta.uid);
        if candidates.is_empty() {
            return Ok(None);
        }
        let randomized = matches!(
            selection,
            Selection::Get { random: true, .. } | Selection::Replication
        );
        let index = candidates[if randomized {
            (random % candidates.len() as u64) as usize
        } else {
            0
        }];
        let old = self.values[index].meta;
        if matches!(selection, Selection::Replication) {
            self.values[index].meta.replication = old.replication.saturating_sub(1);
        }
        Ok(Some(Record {
            meta: old,
            value: &self.values[index].value,
        }))
    }
    fn remove(&mut self, key: &[u8; 64], value: &[u8]) -> Result<bool, TestError> {
        self.error()?;
        match self
            .values
            .iter()
            .position(|v| v.meta.key == *key && v.value == value)
        {
            Some(i) => {
                self.values.remove(i);
                Ok(true)
            }
            None => Ok(false),
        }
    }
    fn maintain(&mut self, policy: MaintenancePolicy) -> Result<Maintenance, TestError> {
        self.maintenance += 1;
        self.error()?;
        let mut report = Maintenance::default();
        while report.removed_entries < (policy.max_evictions as u64) {
            let Some(index) = self
                .values
                .iter()
                .position(|v| v.meta.expiration <= policy.now)
            else {
                break;
            };
            let old = self.values.remove(index);
            report.removed_entries += 1;
            report.removed_bytes += old.value.len() as u64 + ENTRY_OVERHEAD;
            report.min_expiration = Some(policy.now);
        }
        report.more = self.values.iter().any(|v| v.meta.expiration <= policy.now);
        Ok(report)
    }
    fn drop_all(&mut self) -> Result<(), TestError> {
        self.error()?;
        self.drops += 1;
        self.values.clear();
        Ok(())
    }
}
struct Random(u64);
impl Entropy for Random {
    fn next_u64(&mut self) -> Result<u64, Error> {
        self.0 += 1;
        Ok(self.0)
    }
}
fn now() -> AbsoluteTime {
    AbsoluteTime::from_micros(10)
}
fn data<'a>(key: &'a [u8; 64], value: &'a [u8], rid: u32) -> Data<'a> {
    Data {
        reservation: rid,
        kind: 5,
        priority: 3,
        anonymity: 7,
        replication: 2,
        uid: 0,
        expiration: AbsoluteTime::from_micros(100),
        key,
        value,
    }
}
fn response<'a>(
    action: ReplyAction<TestError>,
    output: &'a [u8],
) -> Result<Response<'a>, Box<dyn std::error::Error>> {
    match action {
        ReplyAction::Reply { bytes, .. } => Ok(Response::decode(&output[..bytes])?),
        _ => Err("expected actual reply".into()),
    }
}
fn code(action: ReplyAction<TestError>, output: &[u8]) -> Result<i32, Box<dyn std::error::Error>> {
    match response(action, output)? {
        Response::Status(s) => Ok(s.code),
        _ => Err("expected status".into()),
    }
}

#[test]
fn reservations_are_connection_owned_and_preflighted_and_duplicates_consume_budget() -> TestResult {
    let mut identity = Instance::new();
    let mut clients = [ClientSlot::default(); 2];
    let mut reservations = [ReservationSlot::default(); 2];
    let mut service = Service::new(
        &mut identity,
        &mut clients,
        &mut reservations,
        Config {
            quota_bytes: 2048,
            ..Config::default()
        },
    )?;
    let a = service.connect()?;
    let b = service.connect()?;
    let mut backend = Memory::default();
    let mut random = Random(0);
    let mut output = [0; STATUS_BUFFER_BYTES];
    let action = service.handle(
        a,
        Request::Reserve {
            amount: 10,
            entries: 2,
        },
        &mut backend,
        &mut output,
        now(),
        &mut random,
    )?;
    let rid = code(action, &output)? as u32;
    assert!(rid > 0);
    assert_eq!(service.accounting(&backend)?.reserved_bytes, 522);
    assert_eq!(
        code(
            service.handle(
                b,
                Request::Release { reservation: rid },
                &mut backend,
                &mut output,
                now(),
                &mut random
            )?,
            &output
        )?,
        -1
    );
    let key = [1; 64];
    let put = Request::Put(Data {
        priority: u32::MAX - 1,
        replication: u32::MAX - 1,
        ..data(&key, b"abc", rid)
    });
    let mut short = [0xa7; STATUS_BUFFER_BYTES - 1];
    assert!(matches!(
        service.handle(a, put, &mut backend, &mut short, now(), &mut random),
        Err(Error::Capacity)
    ));
    assert_eq!(short, [0xa7; STATUS_BUFFER_BYTES - 1]);
    assert_eq!(backend.puts, 0);
    assert_eq!(service.accounting(&backend)?.reserved_bytes, 522);
    assert_eq!(
        code(
            service.handle(a, put, &mut backend, &mut output, now(), &mut random)?,
            &output
        )?,
        1
    );
    let duplicate = Request::Put(Data {
        kind: 99,
        anonymity: 0,
        expiration: AbsoluteTime::from_micros(200),
        ..data(&key, b"abc", rid)
    });
    assert_eq!(
        code(
            service.handle(a, duplicate, &mut backend, &mut output, now(), &mut random)?,
            &output
        )?,
        1
    );
    assert_eq!(backend.values.len(), 1);
    let merged = backend.values[0].meta;
    assert_eq!(
        (
            merged.kind,
            merged.anonymity,
            merged.priority,
            merged.replication
        ),
        (5, 7, u32::MAX, u32::MAX)
    );
    assert_eq!(merged.expiration, AbsoluteTime::from_micros(200));
    assert_eq!(service.accounting(&backend)?.reserved_bytes, 4);
    assert_eq!(
        code(
            service.handle(a, duplicate, &mut backend, &mut output, now(), &mut random)?,
            &output
        )?,
        -1
    );
    assert_eq!(backend.puts, 2);
    assert_eq!(
        code(
            service.handle(
                b,
                Request::Reserve {
                    amount: u64::MAX,
                    entries: u32::MAX
                },
                &mut backend,
                &mut output,
                now(),
                &mut random
            )?,
            &output
        )?,
        0
    );
    assert_eq!(
        code(
            service.handle(
                a,
                Request::Release { reservation: rid },
                &mut backend,
                &mut output,
                now(),
                &mut random
            )?,
            &output
        )?,
        1
    );
    assert_eq!(service.accounting(&backend)?.reserved_bytes, 0);
    assert_eq!(service.disconnect(a)?, 0);
    let replacement = service.connect()?;
    assert_ne!(a, replacement);
    assert!(matches!(
        service.handle(a, Request::Drop, &mut backend, &mut [], now(), &mut random),
        Err(Error::Stale)
    ));
    Ok(())
}

#[test]
fn every_selection_remove_and_deferred_drop_return_actual_official_frames() -> TestResult {
    let mut identity = Instance::new();
    let mut clients = [ClientSlot::default(); 1];
    let mut reservations = [];
    let mut service = Service::new(
        &mut identity,
        &mut clients,
        &mut reservations,
        Config {
            quota_bytes: 8192,
            ..Config::default()
        },
    )?;
    let client = service.connect()?;
    let mut backend = Memory::default();
    let mut random = Random(0);
    let mut output = vec![0; QUERY_BUFFER_BYTES];
    let a = [3; 64];
    let b = [4; 64];
    service.handle(
        client,
        Request::Put(Data {
            anonymity: 0,
            replication: 3,
            ..data(&a, b"a", 0)
        }),
        &mut backend,
        &mut output,
        now(),
        &mut random,
    )?;
    service.handle(
        client,
        Request::Put(Data {
            kind: 9,
            ..data(&b, b"bb", 0)
        }),
        &mut backend,
        &mut output,
        now(),
        &mut random,
    )?;
    let selected = response(
        service.handle(
            client,
            Request::Get {
                key: Some(&a),
                kind: 5,
                next_uid: 0,
                random: false,
            },
            &mut backend,
            &mut output,
            now(),
            &mut random,
        )?,
        &output,
    )?;
    assert!(matches!(selected,Response::Data(d) if d.uid==1&&d.value==b"a"&&d.key==&a));
    let selected = response(
        service.handle(
            client,
            Request::Get {
                key: None,
                kind: 0,
                next_uid: 2,
                random: false,
            },
            &mut backend,
            &mut output,
            now(),
            &mut random,
        )?,
        &output,
    )?;
    assert!(matches!(selected,Response::Data(d) if d.uid==2&&d.value==b"bb"));
    let selected = response(
        service.handle(
            client,
            Request::Get {
                key: None,
                kind: 0,
                next_uid: u64::MAX,
                random: true,
            },
            &mut backend,
            &mut output,
            now(),
            &mut random,
        )?,
        &output,
    )?;
    assert!(matches!(selected, Response::Data(_)));
    let selected = response(
        service.handle(
            client,
            Request::ZeroAnonymity {
                kind: 5,
                next_uid: 0,
            },
            &mut backend,
            &mut output,
            now(),
            &mut random,
        )?,
        &output,
    )?;
    assert!(matches!(selected,Response::Data(d) if d.anonymity==0&&d.uid==1));
    assert_eq!(
        response(
            service.handle(
                client,
                Request::ZeroAnonymity {
                    kind: 9,
                    next_uid: 0
                },
                &mut backend,
                &mut output,
                now(),
                &mut random
            )?,
            &output
        )?,
        Response::End
    );
    let calls = backend.selections;
    let mut too_short = vec![0xa7; QUERY_BUFFER_BYTES - 1];
    assert!(matches!(
        service.handle(
            client,
            Request::Replication,
            &mut backend,
            &mut too_short,
            now(),
            &mut random
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(backend.selections, calls);
    assert_eq!(backend.values[0].meta.replication, 3);
    let selected = response(
        service.handle(
            client,
            Request::Replication,
            &mut backend,
            &mut output,
            now(),
            &mut random,
        )?,
        &output,
    )?;
    assert!(matches!(selected,Response::Data(d) if d.replication==3&&d.uid==1));
    assert_eq!(backend.values[0].meta.replication, 2);
    assert_eq!(
        code(
            service.handle(
                client,
                Request::Remove {
                    key: &b,
                    value: b"bb"
                },
                &mut backend,
                &mut output,
                now(),
                &mut random
            )?,
            &output
        )?,
        1
    );
    assert_eq!(
        code(
            service.handle(
                client,
                Request::Remove {
                    key: &b,
                    value: b"bb"
                },
                &mut backend,
                &mut output,
                now(),
                &mut random
            )?,
            &output
        )?,
        0
    );
    assert!(matches!(
        service.handle(
            client,
            Request::Drop,
            &mut backend,
            &mut [],
            now(),
            &mut random
        )?,
        ReplyAction::NoReply
    ));
    assert_eq!((backend.drops, backend.values.len()), (0, 1));
    assert!(matches!(
        response(
            service.handle(
                client,
                Request::Get {
                    key: Some(&a),
                    kind: 0,
                    next_uid: 0,
                    random: false
                },
                &mut backend,
                &mut output,
                now(),
                &mut random
            )?,
            &output
        )?,
        Response::Data(_)
    ));
    assert!(
        service
            .shutdown(&mut backend)
            .map_err(|_| "shutdown failed")?
    );
    assert_eq!((backend.drops, backend.values.len()), (1, 0));
    assert!(matches!(service.connect(), Err(Error::Closed)));
    Ok(())
}

#[test]
fn failed_puts_consume_reservation_and_unknown_fences_all_clients_without_ack() -> TestResult {
    let mut identity = Instance::new();
    let mut clients = [ClientSlot::default(); 2];
    let mut reservations = [ReservationSlot::default(); 1];
    let mut service = Service::new(
        &mut identity,
        &mut clients,
        &mut reservations,
        Config {
            quota_bytes: 4096,
            ..Config::default()
        },
    )?;
    let a = service.connect()?;
    let b = service.connect()?;
    let mut backend = Memory::default();
    let mut random = Random(0);
    let mut output = [0; STATUS_BUFFER_BYTES];
    let key = [5; 64];
    let rid = code(
        service.handle(
            a,
            Request::Reserve {
                amount: 1,
                entries: 2,
            },
            &mut backend,
            &mut output,
            now(),
            &mut random,
        )?,
        &output,
    )? as u32;
    backend.fail = Some(Failure::BeforeCommit);
    let failed = service.handle(
        a,
        Request::Put(data(&key, b"x", rid)),
        &mut backend,
        &mut output,
        now(),
        &mut random,
    )?;
    assert!(matches!(
        &failed,
        ReplyAction::Reply {
            fault: Some(Fault::Backend(TestError(Failure::BeforeCommit))),
            ..
        }
    ));
    assert_eq!(code(failed, &output)?, -1);
    assert_eq!(service.accounting(&backend)?.reserved_bytes, 256);
    backend.fail = Some(Failure::Unknown);
    output.fill(0xa7);
    assert!(matches!(
        service.handle(
            a,
            Request::Put(data(&key, b"", rid)),
            &mut backend,
            &mut output,
            now(),
            &mut random
        )?,
        ReplyAction::Close {
            fault: Fault::Backend(TestError(Failure::Unknown))
        }
    ));
    assert_eq!(output, [0xa7; STATUS_BUFFER_BYTES]);
    assert!(service.accounting(&backend)?.fenced);
    assert!(matches!(
        service.handle(
            b,
            Request::Reserve {
                amount: 0,
                entries: 0
            },
            &mut backend,
            &mut output,
            now(),
            &mut random
        ),
        Err(Error::OutcomeUnknown)
    ));
    assert!(matches!(
        service.maintain(&mut backend, now()),
        Err(WorkError::Protocol(Error::OutcomeUnknown))
    ));
    assert_eq!(backend.maintenance, 0);
    assert!(matches!(service.connect(), Err(Error::OutcomeUnknown)));
    assert_eq!(service.disconnect(a)?, 0);
    assert_eq!(backend.puts, 2);
    Ok(())
}

#[test]
fn remove_failure_is_error_while_missing_and_removed_stay_distinct() -> TestResult {
    let mut identity = Instance::new();
    let mut clients = [ClientSlot::default(); 1];
    let mut reservations = [];
    let mut service = Service::new(
        &mut identity,
        &mut clients,
        &mut reservations,
        Config::default(),
    )?;
    let client = service.connect()?;
    let mut backend = Memory::default();
    let mut random = Random(0);
    let mut output = [0; STATUS_BUFFER_BYTES];
    let key = [61; 64];
    let value = b"remove-original";
    let put = service.handle(
        client,
        Request::Put(data(&key, value, 0)),
        &mut backend,
        &mut output,
        now(),
        &mut random,
    )?;
    assert_eq!(code(put, &output)?, 1);
    let before = backend.usage();
    let request = Request::Remove { key: &key, value };
    backend.fail = Some(Failure::BeforeCommit);
    let failed = service.handle(
        client,
        request,
        &mut backend,
        &mut output,
        now(),
        &mut random,
    )?;
    assert!(matches!(
        &failed,
        ReplyAction::Reply {
            fault: Some(Fault::Backend(TestError(Failure::BeforeCommit))),
            ..
        }
    ));
    let Response::Status(status) = response(failed, &output)? else {
        return Err("expected actual REMOVE status".into());
    };
    assert_eq!(status.code, -1);
    assert!(
        status
            .message
            .is_some_and(|message| message.ends_with(&[0]))
    );
    assert_eq!(backend.usage(), before);
    assert!(!service.accounting(&backend)?.fenced);

    let missing = service.handle(
        client,
        Request::Remove {
            key: &key,
            value: b"other",
        },
        &mut backend,
        &mut output,
        now(),
        &mut random,
    )?;
    assert_eq!(code(missing, &output)?, 0);
    assert_eq!(backend.usage(), before);
    let removed = service.handle(
        client,
        request,
        &mut backend,
        &mut output,
        now(),
        &mut random,
    )?;
    assert_eq!(code(removed, &output)?, 1);
    assert_eq!(backend.usage().entries, 0);
    Ok(())
}

#[test]
fn remove_unknown_keeps_original_cause_and_fences_without_status() -> TestResult {
    let mut identity = Instance::new();
    let mut clients = [ClientSlot::default(); 1];
    let mut reservations = [];
    let mut service = Service::new(
        &mut identity,
        &mut clients,
        &mut reservations,
        Config::default(),
    )?;
    let client = service.connect()?;
    let mut backend = Memory {
        fail: Some(Failure::Unknown),
        ..Memory::default()
    };
    let mut random = Random(0);
    let mut output = [0xa5; STATUS_BUFFER_BYTES];
    let original = output;
    let key = [67; 64];
    let request = Request::Remove {
        key: &key,
        value: b"unknown",
    };
    let failed = service.handle(
        client,
        request,
        &mut backend,
        &mut output,
        now(),
        &mut random,
    )?;
    assert!(matches!(
        failed,
        ReplyAction::Close {
            fault: Fault::Backend(TestError(Failure::Unknown))
        }
    ));
    assert_eq!(output, original);
    assert!(service.accounting(&backend)?.fenced);
    assert!(matches!(
        service.handle(
            client,
            request,
            &mut backend,
            &mut output,
            now(),
            &mut random
        ),
        Err(Error::OutcomeUnknown)
    ));
    assert_eq!(output, original);
    Ok(())
}
