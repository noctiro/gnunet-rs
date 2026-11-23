//! Drive one standalone invocation, including fresh monitor inventories after loss.

use super::{Result, Service, TIMEOUT};
use crate::identity::{
    Client, Display, EndpointSource, Instance, Observation, Operation, Outcome, Progress, Random,
    SecretKey, SourceLoss, finish_state, keys, messages, observed,
};
use gnunet::clients::identity::{Change, Loss, LossCause};
use gnunet_service_runtime::signals::Termination;
use std::{cell::Cell, future::poll_fn, io::Write};
use tokio::time::Instant;

#[derive(Clone, Copy)]
struct Deadline {
    hard: Instant,
    logical: u64,
}

#[derive(Clone, Copy, Debug)]
enum Mutation {
    Delete,
    Create,
}

#[derive(Default)]
struct Pending<'id> {
    delete: Option<Operation<'id>>,
    create: Option<Operation<'id>>,
}

impl<'id> Pending<'id> {
    fn is_empty(&self) -> bool {
        self.delete.is_none() && self.create.is_none()
    }

    fn complete(&mut self, operation: Operation<'id>) -> Result<Mutation> {
        if self.delete == Some(operation) {
            self.delete = None;
            Ok(Mutation::Delete)
        } else if self.create == Some(operation) {
            self.create = None;
            Ok(Mutation::Create)
        } else {
            Err("foreign or duplicate IDENTITY completion".into())
        }
    }
}

impl Service {
    pub(super) fn required(&self) -> bool {
        self.delete.is_some()
            || self.create.is_some()
            || self.list
            || self.monitor
            || self.encrypted.is_some()
    }

    pub(super) async fn run(
        mut self,
        source: EndpointSource,
        out: &mut impl Write,
        diagnostics: &mut impl Write,
    ) -> Result<()> {
        let instance = Instance::new();
        let deadline = Deadline {
            hard: Instant::now()
                .checked_add(TIMEOUT)
                .ok_or("IDENTITY native deadline overflow")?,
            logical: source
                .clock()
                .sample()?
                .now
                .as_micros()
                .checked_add(u64::try_from(TIMEOUT.as_micros())?)
                .filter(|&until| until != u64::MAX)
                .ok_or("IDENTITY logical deadline overflow")?,
        };
        let mut client = if self.list || self.monitor || self.filter.is_some() {
            Client::monitor(&instance, source, self.limits)?
        } else {
            Client::new(&instance, source, self.limits)?
        };
        let mut pending = Pending::default();
        // The driver sends START before its first mutation and preserves the
        // original admission order. Neither mutation depends on the other's result.
        if let Some(name) = self.delete.take() {
            pending.delete = Some(client.delete(&name, deadline.logical)?);
        }
        if let Some(create) = self.create.take() {
            let key = match create.imported {
                Some(key) => key,
                None => SecretKey::generate(create.key_type, &mut Random)?,
            };
            pending.create = Some(client.create(&create.name, key, deadline.logical)?);
        }
        let mut observation = Observation::default();
        let result = self
            .observe(
                &mut client,
                &mut pending,
                deadline,
                out,
                diagnostics,
                &mut observation,
            )
            .await;
        let report = client.close();
        let retirement = retire(&mut client, &mut pending, &mut observation).await;
        finish_state(out, result, retirement, report, true, Some(observation))
    }

    async fn observe<'id>(
        &mut self,
        client: &mut Client<'id>,
        pending: &mut Pending<'id>,
        deadline: Deadline,
        out: &mut impl Write,
        diagnostics: &mut impl Write,
        observation: &mut Observation,
    ) -> Result<()> {
        let mut termination = Termination::new()?;
        let stopped = Cell::new(false);
        let mut signal = std::pin::pin!(poll_fn(|cx| {
            let result = termination.poll_stop(cx);
            if result.is_ready() {
                stopped.set(true);
            }
            result
        }));
        let clock = client.clock();
        let mut inventory_until =
            (self.list || self.monitor || self.filter.is_some()).then_some(deadline.hard);
        let mut recovering: Option<Loss<'id>> = None;
        let mut failure = None;
        while inventory_until.is_some() || self.monitor || !pending.is_empty() {
            let operation_until =
                (recovering.is_none() && !pending.is_empty()).then_some(deadline.hard);
            let until = inventory_until.into_iter().chain(operation_until).min();
            let Some(progress) = observed(client.drive(until), signal.as_mut()).await? else {
                if !pending.is_empty() {
                    return Err("IDENTITY stopped before all mutation results".into());
                }
                if recovering.is_some() {
                    observation.loss = None;
                }
                break;
            };
            match progress {
                Progress::Connected(epoch)
                    if recovering
                        .is_some_and(|lost| lost.epoch == Some(epoch) || !pending.is_empty()) =>
                {
                    return Err("IDENTITY attached before retiring the original epoch".into());
                }
                Progress::Ego {
                    ego,
                    change,
                    initial,
                } => {
                    let ego = client.ego(ego)?;
                    if self
                        .filter
                        .as_deref()
                        .is_some_and(|name| name != ego.name())
                    {
                        continue;
                    }
                    if let Some(encrypted) = self.encrypted.take() {
                        let result = messages::decrypt(
                            ego.secret(),
                            &encrypted,
                            deadline.hard,
                            (clock.clone(), deadline.logical),
                            signal.as_mut(),
                            out,
                        )
                        .await;
                        if let Err(error) = result {
                            if stopped.get() {
                                return Err(error);
                            }
                            writeln!(diagnostics, "{error}")?;
                            failure.get_or_insert(error);
                        }
                    } else if self.list || self.monitor {
                        let event = match (initial, change) {
                            (true, _) => "identity_initial",
                            (false, Change::Added) => "identity_added",
                            (false, Change::Renamed) => "identity_renamed",
                        };
                        self.display
                            .ego(out, event, ego.name(), ego.secret(), self.private)?;
                    }
                }
                Progress::Initialized(epoch) => {
                    if client.epoch() != Some(epoch) || inventory_until.is_none() {
                        return Err("unexpected IDENTITY inventory completion".into());
                    }
                    inventory_until = None;
                    if recovering.take().is_some() {
                        observation.loss = None;
                    }
                    self.list = false;
                    if self.encrypted.take().is_some() {
                        let name = self
                            .filter
                            .take()
                            .ok_or("missing IDENTITY decryption ego")?;
                        writeln!(
                            diagnostics,
                            "Ego `{}' is not known, cannot decrypt message.",
                            String::from_utf8_lossy(&name)
                        )?;
                    }
                }
                Progress::Completed(completion) => {
                    let mutation = pending.complete(completion.operation)?;
                    if let Some(lost) = recovering {
                        if completion.epoch.is_some() && completion.epoch != lost.epoch {
                            return Err("IDENTITY mutation retired on a foreign epoch".into());
                        }
                        if !matches!(&completion.outcome, Outcome::Local { .. }) {
                            return Err(
                                "IDENTITY mutation changed after original source loss".into()
                            );
                        }
                        let error = format!(
                            "IDENTITY {mutation:?} retired on {:?}: {:?}",
                            completion.epoch, completion.outcome
                        );
                        writeln!(diagnostics, "{error}")?;
                        failure.get_or_insert_with(|| error.into());
                        continue;
                    }
                    match (mutation, completion.outcome) {
                        (
                            Mutation::Delete,
                            Outcome::Result {
                                code: 0,
                                created: None,
                            },
                        ) => {}
                        (
                            Mutation::Delete,
                            Outcome::Result {
                                code,
                                created: None,
                            },
                        ) => {
                            writeln!(diagnostics, "IDENTITY deletion returned code {code}")?;
                        }
                        (
                            Mutation::Create,
                            Outcome::Result {
                                code: 0,
                                created: Some(key),
                            },
                        ) => {
                            if matches!(self.display, Display::Text { verbose: true, .. }) {
                                keys::text(out, None, &key, self.private)?;
                            }
                        }
                        (
                            Mutation::Create,
                            Outcome::Result {
                                code,
                                created: None,
                            },
                        ) if code != 0 => {
                            let error =
                                format!("Failed to create ego: IDENTITY returned code {code}");
                            writeln!(diagnostics, "{error}")?;
                            failure.get_or_insert_with(|| error.into());
                        }
                        (_, outcome) => return Err(unexpected(mutation, outcome)),
                    }
                }
                Progress::Lost { report, cause } => {
                    let retry = self.monitor
                        && matches!(
                            &cause,
                            LossCause::Io(_) | LossCause::Eof | LossCause::RetirementDeadline
                        );
                    observation.loss = Some(SourceLoss {
                        report: report.into(),
                        cause,
                    });
                    if !retry {
                        return Err("IDENTITY lost its active source".into());
                    }
                    // The first loss fixes the whole recovery budget. A connected
                    // socket or incomplete inventory cannot extend it.
                    if inventory_until.is_none() {
                        inventory_until = Some(
                            Instant::now()
                                .checked_add(TIMEOUT)
                                .ok_or("IDENTITY monitor recovery deadline overflow")?,
                        );
                    }
                    recovering = Some(report);
                }
                Progress::WaitDeadline if recovering.is_some() => {
                    return Err("IDENTITY monitor recovery deadline before fresh inventory".into());
                }
                Progress::WaitDeadline => return Err("IDENTITY command deadline".into()),
                Progress::Unavailable(error) => return Err(error.into()),
                Progress::Closed => return Err("IDENTITY source closed before completion".into()),
                _ => {}
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

// The original connection is already closed. Its bounded terminal queue can
// distinguish an unsent mutation from one whose bytes were exposed.
async fn retire<'id>(
    client: &mut Client<'id>,
    pending: &mut Pending<'id>,
    observation: &mut Observation,
) -> Result<()> {
    let mut terminals = Vec::new();
    loop {
        match client.drive(None).await? {
            Progress::Completed(completion) => {
                let mutation = pending.complete(completion.operation)?;
                terminals.push(format!("{mutation:?}: {:?}", completion.outcome));
            }
            Progress::Lost { report, cause } => {
                observation.loss = Some(SourceLoss {
                    report: report.into(),
                    cause,
                });
            }
            Progress::Closed => break,
            _ => {}
        }
    }
    if !pending.is_empty() {
        return Err("IDENTITY closed without all original mutation terminals".into());
    }
    if terminals.is_empty() {
        return Ok(());
    }
    Err(format!("IDENTITY retirement: {}", terminals.join(", ")).into())
}

fn unexpected(mutation: Mutation, outcome: Outcome) -> Box<dyn std::error::Error> {
    // Outcome's native Debug formatter redacts opaque keys and found identities.
    format!("IDENTITY {mutation:?} did not finish normally: {outcome:?}").into()
}
