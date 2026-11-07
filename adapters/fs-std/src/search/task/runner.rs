//! One owned run: ordered reauthentication, durable staging and actual retirement.
use super::{
    Cause, Control, Counts, Event, Failure, Outcome, Phase, Progress, QueryFailure, StopReason,
    append, codec, model,
};
use crate::{
    durable::store::Store,
    ipc,
    search::{self, ResultId, Session, Step, observation::Staged},
};
use gnunet_fs::client::Instance;
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use std::time::Duration;
use tokio::time::Instant;

pub(super) struct Run<'a> {
    pub attempted_stop: Option<StopReason>,
    pub store: &'a mut Store,
    pub state: &'a mut model::State,
    pub active: &'a mut bool,
}
impl Drop for Run<'_> {
    fn drop(&mut self) {
        *self.active = false;
    }
}
struct Stats {
    historical: Counts,
    start_raw: usize,
    replayed: usize,
    new_visible: usize,
    counts: Counts,
    visible: Vec<bool>,
}
impl Stats {
    fn progress(&self, store: &Store, state: &model::State) -> Progress {
        Progress {
            historical: self.historical,
            recorded_observations: state.observations.len(),
            replayed_observations: self.replayed,
            new_observations: state.observations.len() - self.start_raw,
            results: self.counts.results,
            visible_results: self.counts.visible,
            queries: self.counts.queries,
            new_visible_results: self.new_visible,
            state_records: store.record_count(),
        }
    }
    fn summary(&self) -> Counts {
        if self.counts.observations < self.historical.observations {
            return self.historical;
        }
        if self.counts.observations > self.historical.observations {
            return self.counts;
        }
        Counts {
            observations: self.counts.observations,
            results: self.counts.results.max(self.historical.results),
            visible: self.counts.visible.max(self.historical.visible),
            queries: self.counts.queries.max(self.historical.queries),
        }
    }
    fn observe<F, const N: usize>(
        &mut self,
        session: &Session<'_, F, N>,
        step: &Step,
        live: bool,
    ) -> Result<(), Cause>
    where
        F: FnMut() -> Result<ipc::EndpointSource, ipc::Error>,
    {
        self.counts.results = session.results().len();
        self.counts.queries = session.query_count();
        if let Some(id) = result_id(step) {
            let record = session
                .result(id)
                .ok_or(Cause::State("current search result missing"))?;
            let was = self
                .visible
                .get_mut(id.index())
                .ok_or(Cause::State("result exceeds original task bound"))?;
            if record.visible() && !*was {
                *was = true;
                self.counts.visible += 1;
                if live {
                    self.new_visible += 1;
                }
            }
        }
        Ok(())
    }
}
impl Run<'_> {
    fn request(&mut self, reason: StopReason, stats: &Stats) -> Result<StopReason, Cause> {
        self.attempted_stop = Some(reason);
        let phase = if reason == StopReason::Cancelled {
            Phase::CancelRequested
        } else {
            Phase::PauseRequested
        };
        append(
            self.store,
            self.state,
            model::Event::Phase {
                phase,
                counts: stats.summary(),
            },
        )?;
        Ok(reason)
    }
    fn decision(&mut self, decision: Control, stats: &Stats) -> Result<Option<StopReason>, Cause> {
        match decision {
            Control::Continue => Ok(None),
            Control::Pause => self.request(StopReason::CallerPause, stats).map(Some),
            Control::Cancel => self.request(StopReason::Cancelled, stats).map(Some),
        }
    }
    fn checkpoint(
        &mut self,
        clock: &dyn gnunet_service_runtime::clock::RuntimeClock,
        deadline: AbsoluteTime,
        last: &mut Option<AbsoluteTime>,
        stats: &Stats,
        control: &mut impl FnMut(Progress, Event<'_>) -> Control,
    ) -> Result<Option<StopReason>, Cause> {
        let now = clock.sample()?.now;
        if last.is_some_and(|old| now < old) {
            return Err(ProtocolError::TimeUncertain.into());
        }
        *last = Some(now);
        if now >= deadline {
            return self.request(StopReason::Deadline, stats).map(Some);
        }
        let decision = control(stats.progress(self.store, self.state), Event::Tick);
        self.decision(decision, stats)
    }
    pub(super) async fn drive(
        &mut self,
        source: ipc::EndpointSource,
        deadline: AbsoluteTime,
        mut control: impl FnMut(Progress, Event<'_>) -> Control,
    ) -> Result<Outcome, Box<Failure>> {
        let mut stats = Stats {
            historical: self.state.counts,
            start_raw: self.state.observations.len(),
            replayed: 0,
            new_visible: 0,
            counts: Counts::default(),
            visible: Vec::new(),
        };
        let mut cleanup = None;
        let mut query_failures = Vec::new();
        let mut deadline_observation = None;
        let clock = source.clock();
        let mut last = None;
        let result: Result<StopReason, Cause> = async {
            if let Some(reason) =
                self.checkpoint(clock.as_ref(), deadline, &mut last, &stats, &mut control)?
            {
                return Ok(reason);
            }
            let manifest = self.state.manifest.clone();
            let mut options = manifest.options;
            options.deadline = deadline;
            stats
                .visible
                .try_reserve_exact(options.limits.results)
                .map_err(|_| ProtocolError::Capacity)?;
            stats.visible.resize(options.limits.results, false);
            query_failures
                .try_reserve_exact(options.limits.queries)
                .map_err(|_| ProtocolError::Capacity)?;
            let mut identities = Vec::new();
            identities
                .try_reserve_exact(options.limits.queries)
                .map_err(|_| ProtocolError::Capacity)?;
            identities.resize_with(options.limits.queries, Instance::new);
            let query = manifest.query()?;
            let mut session = match Session::<_, 1024>::new(
                query,
                &mut identities,
                || source.duplicate(),
                options,
            ) {
                Ok(session) => session,
                Err(error) if is_deadline(&error) => {
                    deadline_observation = Some(error);
                    return self.request(StopReason::Deadline, &stats);
                }
                Err(error) => return Err(error.into()),
            };
            stats.counts.queries = session.query_count();
            let operation: Result<StopReason, Cause> = async {
                for position in 0..stats.start_raw {
                    if let Some(reason) =
                        self.checkpoint(clock.as_ref(), deadline, &mut last, &stats, &mut control)?
                    {
                        return Ok(reason);
                    }
                    let index = *self
                        .state
                        .observations
                        .get(position)
                        .ok_or(Cause::State("original observation index missing"))?;
                    let record = self
                        .store
                        .read_record(index)?
                        .ok_or(Cause::State("original observation record missing"))?;
                    let observation = codec::observation_view(record.kind, record.bytes)?;
                    let step = session.replay(observation)?;
                    stats.replayed += 1;
                    stats.counts.observations += 1;
                    stats.observe(&session, &step, false)?;
                }
                // Raw journals do not manufacture ResultRecord or availability:
                // only the actual replay above creates these borrowed results.
                for (index, record) in session.results().iter().enumerate() {
                    if !record.visible() {
                        continue;
                    }
                    if let Some(reason) =
                        self.checkpoint(clock.as_ref(), deadline, &mut last, &stats, &mut control)?
                    {
                        return Ok(reason);
                    }
                    let decision = control(
                        stats.progress(self.store, self.state),
                        Event::Restored {
                            result: session.result_id(index),
                            record,
                            query: record
                                .source_namespace_query()
                                .and_then(|id| session.query(id)),
                            continuation: record.continuation().and_then(|id| session.query(id)),
                        },
                    );
                    if let Some(reason) = self.decision(decision, &stats)? {
                        return Ok(reason);
                    }
                }
                loop {
                    if let Some(reason) =
                        self.checkpoint(clock.as_ref(), deadline, &mut last, &stats, &mut control)?
                    {
                        return Ok(reason);
                    }
                    let prepared = match session
                        .drive_staged(Some(Instant::now() + Duration::from_millis(50)))
                        .await
                    {
                        Ok(prepared) => prepared,
                        Err(error) if is_deadline(&error) => {
                            deadline_observation = Some(error);
                            return self.request(StopReason::Deadline, &stats);
                        }
                        Err(error) => return Err(error.into()),
                    };
                    let step = match prepared {
                        Staged::Advertisement => {
                            let observation = session
                                .observation()
                                .ok_or(Cause::State("staged authenticated observation missing"))?;
                            append(
                                self.store,
                                self.state,
                                model::Event::Observation(observation),
                            )?;
                            // The original raw record is durable before any new
                            // aggregate result/update child or caller event.
                            let step = session.accept_staged()?;
                            stats.counts.observations += 1;
                            step
                        }
                        Staged::Step(step) => step,
                    };
                    stats.observe(&session, &step, true)?;
                    let decision = control(
                        stats.progress(self.store, self.state),
                        live_event(&session, &step),
                    );
                    if let Step::Failed { query, cause } = step {
                        if matches!(&cause, ipc::Error::Protocol(ProtocolError::Deadline)) {
                            deadline_observation = Some(search::Error::Transport(cause));
                            if let Some(reason) = self.decision(decision, &stats)? {
                                return Ok(reason);
                            }
                            return self.request(StopReason::Deadline, &stats);
                        }
                        query_failures.push(QueryFailure { query, cause });
                    }
                    if let Some(reason) = self.decision(decision, &stats)? {
                        return Ok(reason);
                    }
                }
            }
            .await;
            cleanup = match session.cancel() {
                Ok(()) | Err(search::Error::Protocol(ProtocolError::Closed)) => None,
                Err(error) => Some(error),
            };
            operation
        }
        .await;
        let (mut cause, requested_stop) = match result {
            Ok(reason) => (None, Some(reason)),
            Err(error) => (Some(error), self.attempted_stop),
        };
        if cause.is_none()
            && cleanup.is_none()
            && let Some(reason) = requested_stop
        {
            let phase = if reason == StopReason::Cancelled {
                Phase::Cancelled
            } else {
                Phase::Paused
            };
            match append(
                self.store,
                self.state,
                model::Event::Phase {
                    phase,
                    counts: stats.summary(),
                },
            ) {
                Ok(()) => {
                    return Ok(Outcome {
                        reason,
                        progress: stats.progress(self.store, self.state),
                        query_failures,
                        deadline_observation,
                    });
                }
                Err(error) => cause = Some(error),
            }
        }
        let mut state_failure = None;
        if !self.store.fenced()
            && self.state.phase != Phase::CancelRequested
            && let Err(error) = append(
                self.store,
                self.state,
                model::Event::Phase {
                    phase: Phase::Failed,
                    counts: stats.summary(),
                },
            )
        {
            state_failure = Some(error);
        }
        Err(Box::new(Failure {
            cause,
            cleanup,
            state_failure,
            progress: stats.progress(self.store, self.state),
            query_failures,
            requested_stop,
            deadline_observation,
        }))
    }
}
fn result_id(step: &Step) -> Option<ResultId> {
    match step {
        Step::Result { result } | Step::Pending { result } | Step::Update { result } => {
            Some(*result)
        }
        _ => None,
    }
}
fn live_event<'s, F, const N: usize>(session: &'s Session<'_, F, N>, step: &'s Step) -> Event<'s>
where
    F: FnMut() -> Result<ipc::EndpointSource, ipc::Error>,
{
    let record = result_id(step).and_then(|id| session.result(id));
    let source = match step {
        Step::Failed { query, .. } | Step::Rejected { query, .. } | Step::Native { query, .. } => {
            Some(*query)
        }
        _ => record.and_then(|r| r.source_namespace_query()),
    };
    Event::Live {
        step,
        record,
        query: source.and_then(|id| session.query(id)),
        continuation: record
            .and_then(|r| r.continuation())
            .and_then(|id| session.query(id)),
    }
}
fn is_deadline(error: &search::Error) -> bool {
    matches!(
        error,
        search::Error::Protocol(ProtocolError::Deadline)
            | search::Error::Transport(ipc::Error::Protocol(ProtocolError::Deadline))
    )
}
