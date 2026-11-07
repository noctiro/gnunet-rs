//! Canonical-label scoped mutation and existing GNS-client query, with real receipts.
use super::*;
fn ns_limits(limits: Limits) -> ns::Limits {
    ns::Limits {
        operations: 1,
        source_bytes: 65535,
        frame_bytes: 65535,
        io_slice_bytes: limits.io_slice_bytes,
        records: limits.records,
        record_sets: 1,
        reconnect: false,
        retirement_grace: limits.retirement_grace,
        ..ns::Limits::default()
    }
}
fn ns_event(p: &ns::Progress<'_>, observe: &mut impl FnMut(Event)) {
    match p {
        ns::Progress::Connected(e) => observe(Event::Connected {
            provider: Provider::Namestore,
            epoch: e.diagnostic(),
        }),
        ns::Progress::Queued {
            epoch,
            operation,
            request_id,
        } => observe(Event::Queued {
            provider: Provider::Namestore,
            epoch: epoch.diagnostic(),
            operation: operation.diagnostic(),
            rid: *request_id,
        }),
        ns::Progress::Written {
            epoch, operation, ..
        } => observe(Event::Written {
            provider: Provider::Namestore,
            epoch: epoch.diagnostic(),
            operation: operation.diagnostic(),
        }),
        ns::Progress::Activity {
            read_bytes,
            written_bytes,
        } => observe(Event::Bytes {
            provider: Provider::Namestore,
            read: *read_bytes,
            written: *written_bytes,
        }),
        _ => {}
    }
}
fn ns_close(client: &mut ns::Client<'_>, observe: &mut impl FnMut(Event)) {
    if let Some(report) = client.close() {
        observe(Event::Closed {
            provider: Provider::Namestore,
            epoch: report.epoch.map(|e| e.diagnostic()),
            operations: report.operations,
            exposed: report.exposed,
        });
    }
}
fn ns_lost(report: ns::Loss<'_>, cause: ns::LossCause, observe: &mut impl FnMut(Event)) -> Error {
    let epoch = report.epoch.map(|e| e.diagnostic());
    observe(Event::Lost {
        provider: Provider::Namestore,
        epoch,
        exposed: report.exposed,
    });
    Error::SourceLost {
        provider: Provider::Namestore,
        epoch,
        exposed: report.exposed,
        cause: Loss::Namestore(cause),
    }
}
async fn ns_reply<'id>(
    client: &mut ns::Client<'id>,
    operation: ns::Operation<'id>,
    deadline: &Deadline,
    mut cancel: Pin<&mut impl Future<Output = io::Result<()>>>,
    observe: &mut impl FnMut(Event),
) -> Result<ns::Reply> {
    loop {
        let p = step(client.drive(Some(deadline.hard)), deadline, cancel.as_mut()).await?;
        ns_event(&p, observe);
        match p {
            ns::Progress::Completed(c) => {
                if c.operation != operation {
                    return Err(Fault::StaleGeneration.into());
                }
                return match c.outcome {
                    ns::Outcome::Reply(reply) => Ok(reply),
                    ns::Outcome::Local { reason, submission } => {
                        Err(Error::NamestoreLocal { reason, submission })
                    }
                };
            }
            ns::Progress::Lost { report, cause } => return Err(ns_lost(report, cause, observe)),
            ns::Progress::Unavailable(e) => return Err(e.into()),
            ns::Progress::ConnectRetry { error, retry_after } => observe(Event::Retry {
                provider: Provider::Namestore,
                error,
                after: retry_after,
            }),
            ns::Progress::WaitDeadline => return Err(Fault::Deadline.into()),
            ns::Progress::Closed => return Err(Fault::Closed.into()),
            _ => {}
        }
    }
}
async fn ns_retire<'id>(
    client: &mut ns::Client<'id>,
    operation: ns::Operation<'id>,
    deadline: &Deadline,
    grace: Duration,
    observe: &mut impl FnMut(Event),
) {
    if client.pending() == 0 {
        return;
    }
    if let Err(error) = client.cancel(operation) {
        observe(Event::Cleanup {
            provider: Provider::Namestore,
            error,
        });
        return;
    }
    observe(Event::Cancelled {
        provider: Provider::Namestore,
        operation: operation.diagnostic(),
    });
    let Some(until) = Instant::now().min(deadline.hard).checked_add(grace) else {
        return;
    };
    while client.pending() != 0 && Instant::now() < until {
        let p = match native_step(client.drive(Some(until)), until).await {
            Some(Ok(p)) => p,
            Some(Err(error)) => {
                observe(Event::Cleanup {
                    provider: Provider::Namestore,
                    error,
                });
                break;
            }
            None => break,
        };
        ns_event(&p, observe);
        match p {
            ns::Progress::Completed(c) => {
                if c.operation != operation {
                    break;
                }
                if let ns::Outcome::Reply(reply) = c.outcome
                    && let Ok(wire::Response::Generic { code, .. }) = reply.view()
                {
                    observe(Event::Result {
                        provider: Provider::Namestore,
                        operation: operation.diagnostic(),
                        code: i64::from(code),
                    });
                }
                break;
            }
            ns::Progress::Lost { report, cause } => {
                let _original = ns_lost(report, cause, observe);
                break;
            }
            ns::Progress::WaitDeadline | ns::Progress::Closed => break,
            _ => {}
        }
    }
}
impl Client<'_, '_, '_> {
    pub(super) async fn mutate(
        &mut self,
        key: &identity::SecretKey,
        mutation: Mutation<'_>,
        deadline: &Deadline,
        mut cancel: Pin<&mut impl Future<Output = io::Result<()>>>,
        observe: &mut impl FnMut(Event),
    ) -> Result<()> {
        let mut client = ns::Client::new(
            self.instances.namestore,
            self.sources
                .namestore
                .as_ref()
                .ok_or(Fault::Unavailable)?
                .duplicate()?,
            ns_limits(self.limits),
        )?;
        let mut pending = None;
        let result = async {
            checkpoint(deadline, cancel.as_mut()).await?;
            let read = client.lookup(key, did::DOCUMENT_LABEL, 1, deadline.until)?;
            pending = Some(read);
            let original = ns_reply(&mut client, read, deadline, cancel.as_mut(), observe).await?;
            pending = None;
            let wire::Response::Lookup {
                zone,
                label,
                found,
                records,
                ..
            } = original.view()?
            else {
                return Err(Fault::Malformed.into());
            };
            observe(Event::Result {
                provider: Provider::Namestore,
                operation: read.diagnostic(),
                code: i64::from(found),
            });
            if label.bytes() != did::DOCUMENT_LABEL {
                return Err(Fault::Authentication.into());
            }
            let actual = identity::SecretKey::from_serialized(zone.expose_serialized())?;
            if !key.constant_time_eq(&actual) {
                return Err(Fault::Authentication.into());
            }
            drop(actual);
            if found < 0 {
                return Err(Error::LookupCode(found));
            }
            if found == 0 && !records.records().is_empty() {
                return Err(Fault::Malformed.into());
            }
            let mut scratch = Scratch::new(self.limits)?;
            let present = did::select(
                records.records(),
                mutation.did,
                &mut scratch.workspace(),
                self.limits.json,
            )?
            .is_some();
            if mutation.mode == Mode::Create && present {
                return Err(Fault::Conflict.into());
            }
            if mutation.mode != Mode::Create && !present {
                return Err(Fault::NotFound.into());
            }
            let mut body = Zeroizing::new(Vec::new());
            if let Some(document) = mutation.body {
                if document.len() > self.limits.document_bytes {
                    return Err(Fault::TooLarge.into());
                }
                body.try_reserve_exact(document.len() + 1)
                    .map_err(|_| Fault::Capacity)?;
                body.extend_from_slice(document);
                body.push(0);
            }
            let mut retained = Vec::new();
            retained
                .try_reserve_exact(records.records().len() + usize::from(mutation.body.is_some()))
                .map_err(|_| Fault::Capacity)?;
            for record in records.records().iter() {
                let record = record?;
                if did::managed(
                    record,
                    mutation.did,
                    &mut scratch.workspace(),
                    self.limits.json,
                )?
                .is_none()
                {
                    retained.push(record);
                }
            }
            if mutation.body.is_some() {
                retained.push(RecordData {
                    expiration_time: mutation.expiration,
                    record_type: RecordType::DID_DOCUMENT,
                    flags: RecordFlags::RELATIVE_EXPIRATION,
                    data: &body,
                });
            }
            if retained.len() > self.limits.records {
                return Err(Fault::Capacity.into());
            }
            let mut encoded = Zeroizing::new(Vec::new());
            let length = gnunet_gnsrecord::serialized_len(&retained)?;
            encoded
                .try_reserve_exact(length)
                .map_err(|_| Fault::Capacity)?;
            encoded.resize(length, 0);
            gnunet_gnsrecord::serialize(&retained, &mut encoded)?;
            let set = wire::StoreSet {
                label: wire::CString::new(did::DOCUMENT_LABEL)?,
                records: wire::Records::new(
                    &encoded,
                    u16::try_from(retained.len()).map_err(|_| Fault::TooLarge)?,
                )?,
                reserved: 0,
            };
            let mut sets = Zeroizing::new(Vec::new());
            let length = set.encoded_len()?;
            sets.try_reserve_exact(length)
                .map_err(|_| Fault::Capacity)?;
            sets.resize(length, 0);
            set.encode(&mut sets)?;
            let sets = wire::RecordSets::new(&sets, 1)?;
            wire::Request::Store {
                rid: 0,
                zone: key.view()?,
                single_tx: 1,
                reserved: 0,
                sets,
            }
            .encoded_len()?;
            checkpoint(deadline, cancel.as_mut()).await?;
            let store = client.store(key, sets, true, deadline.until)?;
            pending = Some(store);
            let reply = ns_reply(&mut client, store, deadline, cancel.as_mut(), observe).await?;
            pending = None;
            let wire::Response::Generic { code, .. } = reply.view()? else {
                return Err(Fault::Malformed.into());
            };
            observe(Event::Result {
                provider: Provider::Namestore,
                operation: store.diagnostic(),
                code: i64::from(code),
            });
            if code != 0 {
                return Err(Error::NamestoreCode(code));
            }
            Ok(())
        }
        .await;
        if result.is_err()
            && let Some(operation) = pending
        {
            ns_retire(
                &mut client,
                operation,
                deadline,
                self.limits.retirement_grace,
                observe,
            )
            .await;
        }
        ns_close(&mut client, observe);
        result
    }
    pub(super) async fn query(
        &mut self,
        did: did::Did,
        deadline: &Deadline,
        mut cancel: Pin<&mut impl Future<Output = io::Result<()>>>,
        observe: &mut impl FnMut(Event),
    ) -> Result<Resolved> {
        let limits = self.limits;
        let source = self
            .sources
            .gns
            .as_ref()
            .ok_or(Fault::Unavailable)?
            .duplicate()?;
        let mut client = gns::BoundedClient::<1, { gns::MAX_NAME_BYTES }>::new(
            &mut *self.instances.gns,
            source,
            gns::Limits {
                frame_bytes: 65535,
                records: limits.records,
                output: gnunet_service_runtime::framing::Budget {
                    frames: 1,
                    bytes: 65535,
                },
                io_slice_bytes: limits.io_slice_bytes,
            },
        )?;
        let mut pending = None;
        let mut connected = None;
        let mut retired = None;
        let mut sent = 0usize;
        let mut written = false;
        let mut ever_exposed = false;
        let result = async {
            checkpoint(deadline, cancel.as_mut()).await?;
            let parameters = gns::Parameters {
                zone: did.zone(),
                record_type: RecordType::new(0),
                options: gns::LocalOptions::from_bits(limits.gns_options),
                recursion_depth: limits.gns_recursion,
            };
            let total = gns::Lookup::new(gns::WireId([0; 4]), parameters, did::DOCUMENT_LABEL)?
                .encoded_len();
            let query = client.lookup(parameters, did::DOCUMENT_LABEL)?;
            pending = Some(query);
            loop {
                match step(client.drive(Some(deadline.hard)), deadline, cancel.as_mut()).await? {
                    gns::Progress::Connected(epoch) => {
                        if connected.is_some() || retired == Some(epoch) {
                            return Err(Fault::StaleGeneration.into());
                        }
                        connected = Some(epoch);
                        sent = 0;
                        written = false;
                        observe(Event::Connected {
                            provider: Provider::Gns,
                            epoch: epoch.diagnostic(),
                        });
                    }
                    gns::Progress::Written {
                        epoch,
                        query: actual,
                    } => {
                        if actual != query || connected != Some(epoch) || written {
                            return Err(Fault::StaleGeneration.into());
                        }
                        sent = total;
                        written = true;
                        ever_exposed = true;
                        observe(Event::Written {
                            provider: Provider::Gns,
                            epoch: epoch.diagnostic(),
                            operation: actual.diagnostic(),
                        });
                    }
                    gns::Progress::Activity {
                        epoch,
                        read_bytes,
                        written_bytes,
                    } => {
                        ever_exposed |= written_bytes > 0;
                        observe(Event::Bytes {
                            provider: Provider::Gns,
                            read: read_bytes,
                            written: written_bytes,
                        });
                        if connected != Some(epoch) {
                            return Err(Fault::StaleGeneration.into());
                        }
                        sent = sent
                            .checked_add(written_bytes)
                            .filter(|n| *n <= total)
                            .ok_or(Fault::Overflow)?;
                    }
                    gns::Progress::Answer(answer) => {
                        if answer.query() != query || connected != Some(answer.epoch()) || !written
                        {
                            return Err(Fault::StaleGeneration.into());
                        }
                        pending = None;
                        let mut scratch = Scratch::new(limits)?;
                        let selected = did::select(
                            answer.result()?.records(),
                            did,
                            &mut scratch.workspace(),
                            limits.json,
                        )?
                        .ok_or(Fault::NotFound)?;
                        if selected.json().len() > limits.document_bytes {
                            return Err(Fault::TooLarge.into());
                        }
                        let mut body = Zeroizing::new(Vec::new());
                        body.try_reserve_exact(selected.json().len())
                            .map_err(|_| Fault::Capacity)?;
                        body.extend_from_slice(selected.json());
                        return Ok(Resolved {
                            did,
                            body,
                            form: selected.form(),
                        });
                    }
                    gns::Progress::Refused {
                        epoch,
                        query: actual,
                        reason,
                    } => {
                        if actual != query || connected != Some(epoch) || !written {
                            return Err(Fault::StaleGeneration.into());
                        }
                        pending = None;
                        return Err(reason.into());
                    }
                    gns::Progress::Lost {
                        epoch,
                        cause,
                        retained_queries,
                    } => {
                        observe(Event::Lost {
                            provider: Provider::Gns,
                            epoch: Some(epoch.diagnostic()),
                            exposed: usize::from(sent > 0),
                        });
                        // The existing client has physically retired the old MQ
                        // before offering retained readonly intent. Keep only
                        // this exact original query, with unchanged parameters
                        // and outer deadlines; never create a replacement RPC.
                        if connected != Some(epoch) || retained_queries != 1 || !client.live(query)
                        {
                            return Err(Error::SourceLost {
                                provider: Provider::Gns,
                                epoch: Some(epoch.diagnostic()),
                                exposed: usize::from(ever_exposed),
                                cause: Loss::Gns(cause),
                            });
                        }
                        observe(Event::RetainedRead {
                            provider: Provider::Gns,
                            epoch: epoch.diagnostic(),
                            operation: query.diagnostic(),
                            exposed: sent > 0,
                            written,
                            cause: Loss::Gns(cause),
                        });
                        retired = Some(epoch);
                        connected = None;
                        sent = 0;
                        written = false;
                    }
                    gns::Progress::ConnectRetry { error, retry_after } => observe(Event::Retry {
                        provider: Provider::Gns,
                        error,
                        after: retry_after,
                    }),
                    gns::Progress::Unavailable(e) => return Err(e.into()),
                    gns::Progress::WaitDeadline => return Err(Fault::Deadline.into()),
                    gns::Progress::Closed => return Err(Fault::Closed.into()),
                    gns::Progress::Capacity(_) => return Err(Fault::Capacity.into()),
                    _ => {}
                }
            }
        }
        .await;
        if let Some(query) = pending
            && client.live(query)
        {
            match client.cancel(query) {
                Ok(()) => observe(Event::Cancelled {
                    provider: Provider::Gns,
                    operation: query.diagnostic(),
                }),
                Err(error) => observe(Event::Cleanup {
                    provider: Provider::Gns,
                    error,
                }),
            }
        }
        // Every terminal return fences the actual owner, including a pending
        // unattached retry and any original partial immutable suffix. No later
        // poll can restore this callback. Physical close is not remote withdrawal.
        let epoch = match client.close() {
            Some(gns::Progress::Lost { epoch, cause, .. }) => {
                drop(cause);
                Some(epoch.diagnostic())
            }
            _ => None,
        };
        observe(Event::Closed {
            provider: Provider::Gns,
            epoch,
            operations: usize::from(pending.is_some()),
            exposed: usize::from(pending.is_some() && ever_exposed),
        });
        result
    }
}
