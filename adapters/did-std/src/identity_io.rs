//! Actual original IDENTITY operations, including optional explicit-entropy create.
use super::*;
fn limits(limits: Limits, deadline: &Deadline) -> identity::Limits {
    identity::Limits {
        operations: 1,
        egos: limits.egos,
        io_slice_bytes: limits.io_slice_bytes,
        reconnect: false,
        initialization_timeout: deadline.hard.saturating_duration_since(Instant::now()),
        retirement_grace: limits.retirement_grace,
        ..identity::Limits::default()
    }
}
fn event(progress: &identity::Progress<'_>, observe: &mut impl FnMut(Event)) {
    match progress {
        identity::Progress::Connected(e) => observe(Event::Connected {
            provider: Provider::Identity,
            epoch: e.diagnostic(),
        }),
        identity::Progress::Queued { epoch, operation } => observe(Event::Queued {
            provider: Provider::Identity,
            epoch: epoch.diagnostic(),
            operation: operation.diagnostic(),
            rid: None,
        }),
        identity::Progress::Written { epoch, operation } => observe(Event::Written {
            provider: Provider::Identity,
            epoch: epoch.diagnostic(),
            operation: operation.diagnostic(),
        }),
        identity::Progress::Activity {
            read_bytes,
            written_bytes,
        } => observe(Event::Bytes {
            provider: Provider::Identity,
            read: *read_bytes,
            written: *written_bytes,
        }),
        _ => {}
    }
}
fn closed(client: &mut identity::Client<'_>, observe: &mut impl FnMut(Event)) {
    if let Some(report) = client.close() {
        observe(Event::Closed {
            provider: Provider::Identity,
            epoch: report.epoch.map(|e| e.diagnostic()),
            operations: report.operations,
            exposed: report.exposed,
        });
    }
}
fn lost(
    report: identity::Loss<'_>,
    cause: identity::LossCause,
    observe: &mut impl FnMut(Event),
) -> Error {
    let epoch = report.epoch.map(|e| e.diagnostic());
    observe(Event::Lost {
        provider: Provider::Identity,
        epoch,
        exposed: report.exposed,
    });
    Error::SourceLost {
        provider: Provider::Identity,
        epoch,
        exposed: report.exposed,
        cause: Loss::Identity(cause),
    }
}
async fn retire<'id>(
    client: &mut identity::Client<'id>,
    operation: identity::Operation<'id>,
    deadline: &Deadline,
    grace: Duration,
    observe: &mut impl FnMut(Event),
) {
    if client.pending() == 0 {
        return;
    }
    if let Err(error) = client.cancel(operation) {
        observe(Event::Cleanup {
            provider: Provider::Identity,
            error,
        });
        return;
    }
    observe(Event::Cancelled {
        provider: Provider::Identity,
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
                    provider: Provider::Identity,
                    error,
                });
                break;
            }
            None => break,
        };
        event(&p, observe);
        match p {
            identity::Progress::Completed(c) => {
                if c.operation != operation {
                    break;
                }
                match c.outcome {
                    identity::Outcome::Result { code, .. } => observe(Event::Result {
                        provider: Provider::Identity,
                        operation: operation.diagnostic(),
                        code: i64::from(code),
                    }),
                    identity::Outcome::Local {
                        result_code: Some(code),
                        ..
                    } => observe(Event::Result {
                        provider: Provider::Identity,
                        operation: operation.diagnostic(),
                        code: i64::from(code),
                    }),
                    _ => {}
                }
                break;
            }
            identity::Progress::Lost { report, cause } => {
                let _original = lost(report, cause, observe);
                break;
            }
            identity::Progress::Closed => break,
            identity::Progress::ConnectRetry { error, retry_after } => observe(Event::Retry {
                provider: Provider::Identity,
                error,
                after: retry_after,
            }),
            identity::Progress::WaitDeadline => break,
            _ => {}
        }
    }
}
impl Client<'_, '_, '_> {
    pub(super) async fn key(
        &mut self,
        name: &[u8],
        deadline: &Deadline,
        mut cancel: Pin<&mut impl Future<Output = io::Result<()>>>,
        observe: &mut impl FnMut(Event),
    ) -> Result<Option<identity::SecretKey>> {
        let mut lookup = identity::Lookup::exact(
            self.instances.identity,
            self.sources
                .identity
                .as_ref()
                .ok_or(Fault::Unavailable)?
                .duplicate()?,
            name,
            deadline.until,
            limits(self.limits, deadline),
        )?;
        let result = async {
            loop {
                match step(lookup.drive(Some(deadline.hard)), deadline, cancel.as_mut()).await? {
                    identity::LookupProgress::Finished {
                        operation,
                        epoch,
                        outcome: identity::LookupOutcome::Found(identity),
                    } => {
                        observe(Event::LookupFound {
                            operation: operation.diagnostic(),
                            epoch: epoch.map(|e| e.diagnostic()),
                        });
                        return Ok(Some(identity.into_secret()));
                    }
                    identity::LookupProgress::Finished {
                        operation,
                        outcome: identity::LookupOutcome::ResultCode(code),
                        ..
                    } => {
                        observe(Event::Result {
                            provider: Provider::Identity,
                            operation: operation.diagnostic(),
                            code: i64::from(code),
                        });
                        return if code == 200 {
                            Ok(None)
                        } else {
                            Err(Error::IdentityCode(code))
                        };
                    }
                    identity::LookupProgress::Finished {
                        outcome:
                            identity::LookupOutcome::Local {
                                reason,
                                submission,
                                result_code,
                            },
                        ..
                    } => {
                        return Err(Error::IdentityLocal {
                            reason,
                            submission,
                            result_code,
                        });
                    }
                    identity::LookupProgress::Source(p) => {
                        event(&p, observe);
                        match p {
                            identity::Progress::Lost { report, cause } => {
                                return Err(lost(report, cause, observe));
                            }
                            identity::Progress::Unavailable(e) => return Err(e.into()),
                            identity::Progress::ConnectRetry { error, retry_after } => {
                                observe(Event::Retry {
                                    provider: Provider::Identity,
                                    error,
                                    after: retry_after,
                                })
                            }
                            identity::Progress::WaitDeadline => return Err(Fault::Deadline.into()),
                            _ => {}
                        }
                    }
                    identity::LookupProgress::Closed => return Err(Fault::Closed.into()),
                }
            }
        }
        .await;
        if let Some(report) = lookup.close() {
            observe(Event::Closed {
                provider: Provider::Identity,
                epoch: report.epoch.map(|e| e.diagnostic()),
                operations: report.operations,
                exposed: report.exposed,
            });
        }
        result
    }
    pub(super) async fn create_key(
        &mut self,
        name: &[u8],
        entropy: &mut impl Entropy,
        deadline: &Deadline,
        mut cancel: Pin<&mut impl Future<Output = io::Result<()>>>,
        observe: &mut impl FnMut(Event),
    ) -> Result<identity::SecretKey> {
        let mut client = identity::Client::new(
            self.instances.identity,
            self.sources
                .identity
                .as_ref()
                .ok_or(Fault::Unavailable)?
                .duplicate()?,
            limits(self.limits, deadline),
        )?;
        let mut operation = None;
        let result = async {
            checkpoint(deadline, cancel.as_mut()).await?;
            let op =
                client.create_generated(name, identity::KeyType::Eddsa, entropy, deadline.until)?;
            operation = Some(op);
            loop {
                let p = step(client.drive(Some(deadline.hard)), deadline, cancel.as_mut()).await?;
                event(&p, observe);
                match p {
                    identity::Progress::Completed(c) => {
                        if c.operation != op {
                            return Err(Fault::StaleGeneration.into());
                        }
                        match c.outcome {
                            identity::Outcome::Result { code, created } => {
                                observe(Event::Result {
                                    provider: Provider::Identity,
                                    operation: op.diagnostic(),
                                    code: i64::from(code),
                                });
                                return if code == 0 {
                                    created.ok_or_else(|| Fault::Malformed.into())
                                } else {
                                    Err(Error::IdentityCode(code))
                                };
                            }
                            identity::Outcome::Local {
                                reason,
                                submission,
                                result_code,
                                ..
                            } => {
                                return Err(Error::IdentityLocal {
                                    reason,
                                    submission,
                                    result_code,
                                });
                            }
                            _ => return Err(Fault::Malformed.into()),
                        }
                    }
                    identity::Progress::Lost { report, cause } => {
                        return Err(lost(report, cause, observe));
                    }
                    identity::Progress::Unavailable(e) => return Err(e.into()),
                    identity::Progress::ConnectRetry { error, retry_after } => {
                        observe(Event::Retry {
                            provider: Provider::Identity,
                            error,
                            after: retry_after,
                        })
                    }
                    identity::Progress::WaitDeadline => return Err(Fault::Deadline.into()),
                    identity::Progress::Closed => return Err(Fault::Closed.into()),
                    _ => {}
                }
            }
        }
        .await;
        if result.is_err()
            && let Some(op) = operation
        {
            retire(
                &mut client,
                op,
                deadline,
                self.limits.retirement_grace,
                observe,
            )
            .await;
        }
        closed(&mut client, observe);
        result
    }
    pub(super) async fn directory(
        &mut self,
        deadline: &Deadline,
        mut cancel: Pin<&mut impl Future<Output = io::Result<()>>>,
        observe: &mut impl FnMut(Event),
    ) -> Result<Vec<NamedDid>> {
        let mut client = identity::Client::monitor(
            self.instances.identity,
            self.sources
                .identity
                .as_ref()
                .ok_or(Fault::Unavailable)?
                .duplicate()?,
            limits(self.limits, deadline),
        )?;
        let result = async {
            loop {
                let p = step(client.drive(Some(deadline.hard)), deadline, cancel.as_mut()).await?;
                event(&p, observe);
                match p {
                    identity::Progress::Initialized(epoch) => {
                        if !client.initialized() {
                            return Err(Fault::Conflict.into());
                        }
                        let count = client.egos().count();
                        let mut rows = Vec::new();
                        rows.try_reserve_exact(count).map_err(|_| Fault::Capacity)?;
                        for row in client.egos() {
                            let mut name = Vec::new();
                            name.try_reserve_exact(row.name().len())
                                .map_err(|_| Fault::Capacity)?;
                            name.extend_from_slice(row.name());
                            rows.push(NamedDid {
                                name,
                                did: did::Did::from_public(ZoneKey::from_wire(&row.public_key()?)?),
                            });
                        }
                        observe(Event::Initialized {
                            epoch: epoch.diagnostic(),
                            egos: count,
                        });
                        return Ok(rows);
                    }
                    identity::Progress::Lost { report, cause } => {
                        return Err(lost(report, cause, observe));
                    }
                    identity::Progress::Unavailable(e) => return Err(e.into()),
                    identity::Progress::ConnectRetry { error, retry_after } => {
                        observe(Event::Retry {
                            provider: Provider::Identity,
                            error,
                            after: retry_after,
                        })
                    }
                    identity::Progress::WaitDeadline => return Err(Fault::Deadline.into()),
                    identity::Progress::Closed => return Err(Fault::Closed.into()),
                    _ => {}
                }
            }
        }
        .await;
        closed(&mut client, observe);
        result
    }
}
