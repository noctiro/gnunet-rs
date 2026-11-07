//! One actual generation intent across both original consensus rounds. The
//! persistent PILS client moves with its branded identity and signing facts.
use crate::{
    Bounds, Error, Instance, Limits, Request, Round1, Sources,
    finalize::{Finalization, Finalized},
    round2,
};
use gnunet_client_host::EndpointSource;
use gnunet_pils::client::Identity;
use gnunet_pils_host::client as pils;
use gnunet_secretsharing as math;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use std::{
    future::poll_fn,
    mem::size_of,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

/// Actual original source facts, retained independently of the final result.
#[derive(Default)]
pub struct GenerationReport<'id> {
    /// Original first-round commitment/signing/source facts.
    pub round1: Option<crate::Report<'id>>,
    /// Original second-round local/remote/source facts.
    pub round2: Option<round2::Report<'id>>,
    /// Both original consensus rounds and final aggregation actually completed.
    pub completed: bool,
    /// Actual persistent PILS idle state after physical retirement.
    pub pils_idle: bool,
    /// Explicit close requested before completion.
    pub cancelled: bool,
}
impl GenerationReport<'_> {
    /// Actual independently retained failure-evidence containers. Fixed branded
    /// records are part of the enclosing owner; errors/native/RSS are separate.
    pub fn retained_storage_bytes(&self) -> Result<usize, Error> {
        let first = self
            .round1
            .as_ref()
            .map_or(Ok(0), crate::Report::retained_storage_bytes)?;
        let second = self
            .round2
            .as_ref()
            .map_or(Ok(0), round2::Report::retained_storage_bytes)?;
        first
            .checked_add(second)
            .ok_or_else(|| Fault::Overflow.into())
    }
}
/// One bounded original action; only Complete owns a standard result.
#[expect(
    clippy::large_enum_variant,
    reason = "Move the unique final secret and evidence without an additional fallible allocation"
)]
pub enum GenerationProgress<'id> {
    /// Actual bounded arithmetic/source progress.
    Activity,
    /// A first-round original peer element was actually rejected.
    Round1Rejected {
        /// Original claimed peer when available.
        peer: Option<[u8; 32]>,
        /// Actual first-round reason.
        reason: crate::Rejection,
    },
    /// A second-round original reveal was actually rejected.
    Round2Rejected {
        /// Original claimed peer when available.
        peer: Option<[u8; 32]>,
        /// Actual second-round reason.
        reason: round2::Rejection,
    },
    /// The actual whole flow completed; output publication remains caller-owned.
    Complete(Finalized<'id>),
}
#[expect(
    clippy::large_enum_variant,
    reason = "Exclusive phases share inline storage and never allocate a second native owner"
)]
enum Stage<'id> {
    Round1(Round1<'id>),
    Round2(round2::Round2<'id>),
    Finalizing(Finalization<'id>),
    Closed,
}
#[derive(Clone, Copy)]
struct Plan {
    round1: Limits,
    round2: round2::Limits,
    final_bytes: usize,
    maximum_bytes: usize,
}
/// Complete original generation owner. It does not change the general FAIR
/// response profile: an actual unrepresentable response remains an error.
pub struct Generation<'id> {
    stage: Stage<'id>,
    second_source: Option<EndpointSource>,
    clock: Arc<dyn RuntimeClock>,
    bounds: Bounds,
    math: math::Limits,
    plan: Plan,
    report: Option<GenerationReport<'id>>,
}
impl<'id> Generation<'id> {
    fn allowance<T>(maximum: usize) -> Result<usize, Error> {
        let overhead = size_of::<Self>()
            .checked_sub(size_of::<T>())
            .ok_or(Fault::Overflow)?;
        maximum
            .checked_sub(overhead)
            .filter(|n| *n != 0)
            .ok_or_else(|| Fault::Capacity.into())
    }
    fn plan(mut limits: Limits) -> Result<Plan, Error> {
        limits.validate()?;
        let maximum_bytes = limits.retained_bytes;
        let final_bytes = Self::allowance::<Finalization<'id>>(maximum_bytes)?;
        let round2 = round2::Limits {
            math: limits.math,
            paillier: limits.paillier,
            consensus: limits.consensus,
            reveal_bytes: limits
                .consensus
                .frame_bytes
                .checked_sub(6)
                .ok_or(Fault::Capacity)?
                .min(65529),
            retained_bytes: Self::allowance::<round2::Round2<'id>>(maximum_bytes)?,
        };
        round2.validate()?;
        limits.retained_bytes = Self::allowance::<Round1<'id>>(maximum_bytes)?;
        Ok(Plan {
            round1: limits,
            round2,
            final_bytes,
            maximum_bytes,
        })
    }
    /// Construct original sources without starting native IO or entropy.
    pub fn new(
        instance: &'id mut Instance,
        sources: Sources,
        request: Request,
        limits: Limits,
        original: Bounds,
    ) -> Result<Self, Error> {
        let plan = Self::plan(limits)?;
        let second_source = sources.consensus.duplicate()?;
        let clock = sources.pils.clock();
        let round1 = Round1::new(instance, sources, request, plan.round1, original)?;
        let bounds = round1.bounds();
        Ok(Self {
            stage: Stage::Round1(round1),
            second_source: Some(second_source),
            clock,
            bounds,
            math: limits.math,
            plan,
            report: Some(GenerationReport::default()),
        })
    }
    /// Adopt the actual already-observed, idle PILS client, preserving its real
    /// source epoch. Refusal closes that owned client, with no SIGN/native IO.
    pub fn from_pils(
        mut client: pils::Client<'id, 1>,
        identity: Identity<'id>,
        sources: Sources,
        request: Request,
        limits: Limits,
        original: Bounds,
    ) -> Result<Self, Error> {
        let preflight = (|| -> Result<_, Error> {
            let plan = Self::plan(limits)?;
            let second_source = sources.consensus.duplicate()?;
            let clock = sources.pils.clock();
            Ok((plan, second_source, clock))
        })();
        let (plan, second_source, clock) = match preflight {
            Ok(parts) => parts,
            Err(error) => {
                let _retired = client.close();
                return Err(error);
            }
        };
        let round1 = Round1::from_pils(client, identity, sources, request, plan.round1, original)?;
        let bounds = round1.bounds();
        Ok(Self {
            stage: Stage::Round1(round1),
            second_source: Some(second_source),
            clock,
            bounds,
            math: limits.math,
            plan,
            report: Some(GenerationReport::default()),
        })
    }
    fn facts(&mut self) -> Result<&mut GenerationReport<'id>, Error> {
        self.report.as_mut().ok_or_else(|| Fault::Closed.into())
    }
    fn remember_round2(&mut self, mut report: round2::Report<'id>) {
        if let Some(facts) = &mut self.report {
            facts.pils_idle = report.pils_idle;
            if let Some(round1) = report.round1.take() {
                facts.round1 = Some(round1);
            }
            facts.round2 = Some(report);
        }
    }
    fn retire(&mut self) {
        match &mut self.stage {
            Stage::Round1(owner) => {
                let report = owner.take_report().or_else(|| owner.close());
                if let Some(report) = report
                    && let Some(facts) = &mut self.report
                {
                    facts.pils_idle = report.pils_idle;
                    facts.round1 = Some(report);
                }
            }
            Stage::Round2(owner) => {
                if let Some(report) = owner.take_report().or_else(|| owner.close()) {
                    self.remember_round2(report);
                }
            }
            Stage::Finalizing(owner) => owner.cancel(),
            Stage::Closed => {}
        }
        self.stage = Stage::Closed;
        self.second_source = None;
    }
    fn failed(&mut self, error: Error) -> Poll<Result<GenerationProgress<'id>, Error>> {
        self.retire();
        Poll::Ready(Err(error))
    }
    fn guard(&self) -> Result<(), Error> {
        if Instant::now() >= self.bounds.hard {
            return Err(Fault::Deadline.into());
        }
        let now = self.clock.sample()?.now.as_micros();
        if Instant::now() >= self.bounds.hard || now >= self.bounds.expires {
            return Err(Fault::Deadline.into());
        }
        if self.retained_bytes()? > self.plan.maximum_bytes {
            return Err(Fault::Capacity.into());
        }
        Ok(())
    }
    /// Exact fixed wrapper storage plus the active owner's existing dynamic
    /// capacities/reservations. Active inline storage is counted once.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        let (retained, inline) = match &self.stage {
            Stage::Round1(owner) => (owner.retained_bytes()?, size_of::<Round1<'id>>()),
            Stage::Round2(owner) => (owner.retained_bytes()?, size_of::<round2::Round2<'id>>()),
            Stage::Finalizing(owner) => (owner.retained_bytes()?, size_of::<Finalization<'id>>()),
            Stage::Closed => (0, 0),
        };
        let dynamic = retained.checked_sub(inline).ok_or(Fault::Overflow)?;
        let reports = self
            .report
            .as_ref()
            .map_or(Ok(0), GenerationReport::retained_storage_bytes)?;
        size_of::<Self>()
            .checked_add(dynamic)
            .and_then(|n| n.checked_add(reports))
            .ok_or_else(|| Fault::Overflow.into())
    }
    /// One bounded current-source/math turn, preserving the original whole
    /// bounds across all transitions. A source loss never becomes an empty DKG.
    pub fn poll_progress(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<GenerationProgress<'id>, Error>> {
        if matches!(self.stage, Stage::Closed) {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        if let Err(error) = self.guard() {
            return self.failed(error);
        }
        match &mut self.stage {
            Stage::Round1(owner) => match owner.poll_progress(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => self.failed(error),
                Poll::Ready(Ok(crate::Progress::Complete(completed))) => {
                    self.stage = Stage::Closed;
                    let Some(source) = self.second_source.take() else {
                        let (_, mut session) = completed.into_parts();
                        let report = session.close();
                        if let Some(report) = report
                            && let Some(facts) = &mut self.report
                        {
                            facts.pils_idle = report.pils_idle;
                            facts.round1 = Some(report);
                        }
                        return self.failed(Fault::StaleGeneration.into());
                    };
                    match round2::Round2::new(completed, source, self.plan.round2) {
                        Ok(owner) => {
                            self.stage = Stage::Round2(owner);
                            Poll::Ready(Ok(GenerationProgress::Activity))
                        }
                        Err(failure) => {
                            self.remember_round2(failure.report);
                            self.failed(failure.error)
                        }
                    }
                }
                Poll::Ready(Ok(crate::Progress::Rejected { peer, reason })) => {
                    Poll::Ready(Ok(GenerationProgress::Round1Rejected { peer, reason }))
                }
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(GenerationProgress::Activity)),
            },
            Stage::Round2(owner) => match owner.poll_progress(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => self.failed(error),
                Poll::Ready(Ok(round2::Progress::Complete(transcript))) => {
                    let report = owner.take_report();
                    self.stage = Stage::Closed;
                    if let Some(report) = report {
                        self.remember_round2(report);
                    }
                    if !self.report.as_ref().is_some_and(|r| r.pils_idle) {
                        return self.failed(Fault::StaleGeneration.into());
                    }
                    let reports = match self
                        .report
                        .as_ref()
                        .map_or(Ok(0), GenerationReport::retained_storage_bytes)
                    {
                        Ok(bytes) => bytes,
                        Err(error) => return self.failed(error),
                    };
                    let Some(remaining) = self.plan.final_bytes.checked_sub(reports) else {
                        return self.failed(Fault::Capacity.into());
                    };
                    match Finalization::new(transcript, self.math, remaining) {
                        Ok(owner) => {
                            self.stage = Stage::Finalizing(owner);
                            Poll::Ready(Ok(GenerationProgress::Activity))
                        }
                        Err(error) => self.failed(error),
                    }
                }
                Poll::Ready(Ok(round2::Progress::Rejected { peer, reason })) => {
                    Poll::Ready(Ok(GenerationProgress::Round2Rejected { peer, reason }))
                }
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(GenerationProgress::Activity)),
            },
            Stage::Finalizing(owner) => {
                let advance = owner.advance(self.math.units_per_turn);
                match advance {
                    Err(error) => self.failed(error),
                    Ok(math::Progress::Advanced) => Poll::Ready(Ok(GenerationProgress::Activity)),
                    Ok(math::Progress::Ready) => match owner.take_result() {
                        Err(error) => self.failed(error),
                        Ok(result) => {
                            self.stage = Stage::Closed;
                            self.second_source = None;
                            match self.facts() {
                                Ok(facts) => {
                                    facts.completed = true;
                                    Poll::Ready(Ok(GenerationProgress::Complete(result)))
                                }
                                Err(error) => self.failed(error),
                            }
                        }
                    },
                }
            }
            Stage::Closed => Poll::Ready(Err(Fault::Closed.into())),
        }
    }
    /// Cancel-safe observation; dropping it preserves the original source state.
    pub async fn progress(&mut self) -> Result<GenerationProgress<'id>, Error> {
        tokio::task::yield_now().await;
        poll_fn(|cx| self.poll_progress(cx)).await
    }
    /// Physically retire all live original sources before transferring facts.
    pub fn close(&mut self) -> Option<GenerationReport<'id>> {
        if !matches!(self.stage, Stage::Closed)
            && let Some(report) = &mut self.report
        {
            report.cancelled = true;
        }
        self.retire();
        self.report.take()
    }
    /// Transfer facts only after all native owners have retired.
    pub fn take_report(&mut self) -> Option<GenerationReport<'id>> {
        if matches!(self.stage, Stage::Closed) {
            self.report.take()
        } else {
            None
        }
    }
}
impl Drop for Generation<'_> {
    fn drop(&mut self) {
        self.retire();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnunet_service_runtime::clock::SystemClock;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    fn check(ok: bool) -> Result {
        if ok {
            Ok(())
        } else {
            Err("retained original report ownership".into())
        }
    }
    #[test]
    fn closed_generation_charges_original_unwritten_loss_until_report_transfer() -> Result {
        let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
        let bounds = Bounds::new(clock.as_ref(), std::time::Duration::from_secs(30))?;
        let source = EndpointSource::unix_with_clock(
            std::env::temp_dir().join("gnunet-no-poll-consensus"),
            clock.clone(),
        );
        let mut client = gnunet_consensus_client_host::Client::new(
            source,
            gnunet_consensus_client_host::Join {
                session: [7; 64],
                start: bounds.expires - 1_000_000,
                deadline: bounds.expires,
                peers: &[],
            },
            Default::default(),
            bounds,
        )?;
        let _original_insert = client.insert(0, &[0x42; 2048])?;
        // No source was polled or attached. Actual queued JOIN/INSERT facts
        // move to loss while payloads are released; the retained table remains
        // charged. None is labelled written, transmitted or peer accepted.
        let loss = client.close();
        drop(client);
        check(
            !loss.joined
                && loss.epoch.is_none()
                && loss.pending.len() == 2
                && loss.pending.iter().all(|p| p.written == 0 && !p.whole),
        )?;
        let retained = loss.retained_storage_bytes()?;
        check(
            retained > 0
                && retained
                    == loss.pending.capacity() * size_of::<gnunet_consensus_client_host::Pending>(),
        )?;
        let report = GenerationReport {
            round1: Some(crate::Report {
                consensus_loss: Some(loss),
                ..crate::Report::default()
            }),
            ..GenerationReport::default()
        };
        check(report.retained_storage_bytes()? == retained)?;
        let limits = Limits::default();
        let plan = Generation::plan(limits)?;
        let mut generation = Generation {
            stage: Stage::Closed,
            second_source: None,
            clock,
            bounds,
            math: limits.math,
            plan,
            report: Some(report),
        };
        check(generation.retained_bytes()? == size_of::<Generation<'_>>() + retained)?;
        let report = generation.take_report().ok_or(Fault::NotReady)?;
        check(
            generation.retained_bytes()? == size_of::<Generation<'_>>()
                && report.retained_storage_bytes()? == retained,
        )
    }
}
