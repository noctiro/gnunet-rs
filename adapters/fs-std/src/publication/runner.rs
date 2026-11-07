//! Owned payload verification, exact original intents and one native PUT runner.
use super::*;
use crate::network::{
    TimeLimit,
    publish::{self, Answer, ExecutionFailure},
};
use gnunet_datastore_host::{
    Client, Instance, Limits as NativeLimits, ProtocolClient, ProtocolLimits, Slot,
};

pub(super) struct Run<'a> {
    pub store: &'a mut Store,
    pub state: &'a mut model::State,
    pub active: &'a mut bool,
}
impl Drop for Run<'_> {
    fn drop(&mut self) {
        *self.active = false;
    }
}
struct Work {
    historical: Counts,
    historical_indexes: usize,
    new_indexes: usize,
    new: Counts,
    verified: bool,
    verification: crate::Progress,
    wanted: Option<StopReason>,
    graph_verified: bool,
    graph_newly: bool,
}
impl Work {
    fn progress(&self, store: &Store, state: &model::State) -> Progress {
        Progress {
            historical: self.historical,
            indexes: IndexProgress {
                historical: self.historical_indexes,
                recorded: state.indexes.accepted.len(),
                new_accepted: self.new_indexes,
                total: state.manifest.plan.index_sources().len(),
                pending: state.indexes.pending,
            },
            graph: graph_runner::progress(state, self.graph_verified, self.graph_newly),
            recorded: state.counts,
            new_accepted: self.new,
            total_puts: state.manifest.plan.puts.len(),
            payloads_verified: self.verified,
            verification: self.verification,
            pending: state.pending,
            state_records: store.record_count(),
        }
    }
}
enum Abort {
    Local(Cause),
    Native,
}
impl From<Cause> for Abort {
    fn from(e: Cause) -> Self {
        Self::Local(e)
    }
}
impl From<ModelError> for Abort {
    fn from(e: ModelError) -> Self {
        Self::Local(e.into())
    }
}
impl From<plan::Error> for Abort {
    fn from(e: plan::Error) -> Self {
        Self::Local(e.into())
    }
}
impl From<ProtocolError> for Abort {
    fn from(e: ProtocolError) -> Self {
        Self::Local(e.into())
    }
}
impl From<ConnectError> for Abort {
    fn from(e: ConnectError) -> Self {
        Self::Local(e.into())
    }
}
impl Run<'_> {
    fn request(&mut self, work: &mut Work, reason: StopReason) -> Result<StopReason, Cause> {
        work.wanted = Some(reason);
        let wanted = if reason == StopReason::Cancelled {
            Phase::CancelRequested
        } else {
            Phase::PauseRequested
        };
        if self.state.requested != Some(wanted) {
            phase(self.store, self.state, wanted)?;
        }
        Ok(reason)
    }
    fn check(
        &mut self,
        work: &mut Work,
        clock: &dyn gnunet_service_runtime::clock::RuntimeClock,
        deadline: AbsoluteTime,
        last: &mut Option<AbsoluteTime>,
        control: &mut impl FnMut(Progress) -> Control,
    ) -> Result<Option<StopReason>, Cause> {
        if let Some(reason) = work.wanted {
            return Ok(Some(reason));
        }
        let now = clock.sample()?.now;
        if last.is_some_and(|old| now < old) {
            return Err(ProtocolError::TimeUncertain.into());
        }
        *last = Some(now);
        let reason = if now >= deadline {
            Some(StopReason::Deadline)
        } else {
            match control(work.progress(self.store, self.state)) {
                Control::Continue => None,
                Control::Pause => Some(StopReason::CallerPause),
                Control::Cancel => Some(StopReason::Cancelled),
            }
        };
        reason.map(|r| self.request(work, r)).transpose()
    }
    pub(super) async fn drive(
        &mut self,
        mut graph: Option<&mut crate::namespace::graph::Graph>,
        fs_source: Option<EndpointSource>,
        source: EndpointSource,
        buffers: &mut Buffers,
        deadline: AbsoluteTime,
        mut control: impl FnMut(Progress) -> Control,
    ) -> Result<Outcome, Box<Failure>> {
        let mut work = Work {
            historical: self.state.counts,
            historical_indexes: self.state.indexes.accepted.len(),
            new_indexes: 0,
            new: Counts::default(),
            verified: false,
            verification: crate::Progress::default(),
            wanted: None,
            graph_verified: false,
            graph_newly: false,
        };
        let mut verified = None;
        let mut last_native = None;
        let mut last_index = None;
        let mut last_graph = None;
        let mut graph_prepared = None;
        let mut cleanup = None;
        let mut last = None;
        let clock = source.clock();
        let mut result:Result<StopReason,Abort>=async {
            if let Some(reason)=self.check(&mut work,clock.as_ref(),deadline,&mut last,&mut control)?{return Ok(reason);}
            let mut repo=Repository::open_child(self.store.directory(),OsStr::new("objects")).map_err(plan::Error::Host)?;
            // Local verification may cooperatively stop before there is a native
            // owner. Its decision is journaled before any later native effect.
            let proof=self.state.manifest.plan.verify(&mut repo,buffers,self.state.manifest.limits,|progress|{
                work.verification=progress;
                let decision=control(work.progress(self.store,self.state));
                match decision {Control::Continue=>crate::Control::Continue,Control::Pause=>{work.wanted=Some(StopReason::CallerPause);crate::Control::Cancel},Control::Cancel=>{work.wanted=Some(StopReason::Cancelled);crate::Control::Cancel}}
            });
            if let Some(reason)=work.wanted {
                self.request(&mut work,reason)?;
                match proof {Err(plan::Error::Host(crate::Error::Cancelled))=>return Ok(reason),Err(error)=>return Err(error.into()),Ok(proof)=>{work.verified=true;verified=Some(proof);return Ok(reason);}}
            }
            verified=Some(proof?);work.verified=true;
            let blocks=self.state.manifest.blocks;let mut body=Vec::new();let mut wire=Vec::new();
            verify_history(self.store,self.state,&mut repo,&mut body,&mut wire)?;
            if let Some(graph)=graph.as_deref_mut() { graph_prepared=graph_runner::prepare(self.state,*self.store.task_id(),graph)?; }
            if let Some(reason)=self.check(&mut work,clock.as_ref(),deadline,&mut last,&mut control)?{return Ok(reason);}
            while self.state.indexes.accepted.len()<self.state.manifest.plan.index_sources().len() {
                if let Some(reason)=self.check(&mut work,clock.as_ref(),deadline,&mut last,&mut control)?{return Ok(reason);}
                let index=self.state.indexes.accepted.len();
                let original=self.state.manifest.plan.index_sources().get(index).ok_or(ProtocolError::Stale)?.clone();
                let guard=plan::indexed::SourceGuard::open(&original)?;
                let fs=fs_source.as_ref().ok_or(Cause::State("indexed publication has no FS source"))?.duplicate()?;
                let mut time=TimeLimit::new(fs.clock(),deadline).map_err(Cause::Transfer)?;
                let request_hash=index_runner::request_hash(&original)?;
                append(self.store,self.state,model::Event::Index(registration::Event::Intent{index,request_hash}))?;
                let attempt=self.state.indexes.pending.ok_or(Cause::State("original registration intent missing"))?.attempt;
                let task=*self.store.task_id();let mut control_error=None;let mut cancelled=false;
                let answer=publish::register_index_controlled(fs,original.file_id,original.path(),&mut time,deadline,||{
                    match self.check(&mut work,clock.as_ref(),deadline,&mut last,&mut control) {
                        Ok(None)=>true,Ok(Some(_))=>{cancelled=true;false},Err(error)=>{control_error=Some(error);cancelled=true;false}
                    }
                }).await;
                let native=match answer {Ok(answer)=>NativeIndexResult::answer(task,attempt,answer),Err(error)=>NativeIndexResult::failed(task,attempt,error,cancelled)};
                if native.registration()==network::IndexRegistration::Acknowledged {work.new_indexes=work.new_indexes.checked_add(1).ok_or(ProtocolError::Overflow)?;}
                last_index=Some(native);
                let native=last_index.as_ref().ok_or(Cause::State("original registration result missing"))?;
                if let Some(error)=control_error {return Err(error.into());}
                let effect=native.record_inner(self.store,self.state)?;
                if native.retirement_error().is_some() {return Err(Abort::Native);}
                match effect {
                    Effect::Accepted=>{guard.stable()?;if let Some(reason)=work.wanted{return Ok(reason);}},
                    Effect::NotApplied=>{if let Some(reason)=work.wanted{return Ok(reason);}return Err(Abort::Native);},
                    Effect::Refused|Effect::Uncertain=>{if work.wanted==Some(StopReason::Cancelled){return Ok(StopReason::Cancelled);}return Err(Abort::Native);}
                }
            }
            if let Some(reason)=self.check(&mut work,clock.as_ref(),deadline,&mut last,&mut control)?{return Ok(reason);}
            if self.state.counts.accepted==self.state.manifest.plan.puts.len(){check_sources(&self.state.manifest.plan)?;return Ok(StopReason::Complete);}
            let mut identity=Instance::new();let mut frame=vec![0;65_535];let mut slots=[Slot::new(&mut frame)];let mut reservations=[];
            let protocol=ProtocolClient::new(&mut identity,&mut slots,&mut reservations,ProtocolLimits {max_pending:1,..Default::default()})?;
            let mut client=Client::new(protocol,source,NativeLimits {reply_frames:1,reply_bytes:65_535,..Default::default()})?;
            let mut time=match TimeLimit::new(client.clock(),deadline) {
                Ok(time)=>time,
                Err(error)=>{cleanup=client.close().err();return Err(Cause::Transfer(error).into());}
            };
            let operation:Result<StopReason,Abort>=async {
                let mut source_guard:Option<plan::indexed::SourceGuard>=None;
                while self.state.counts.accepted<self.state.manifest.plan.puts.len() {
                    if let Some(reason)=self.check(&mut work,clock.as_ref(),deadline,&mut last,&mut control)?{return Ok(reason);}
                    let index=self.state.counts.accepted;let put=*self.state.manifest.plan.puts.get(index).ok_or(ProtocolError::Stale)?;
                    // Hold only the current source FD; its genuine complete
                    // content was verified above and its original stamp/path
                    // must remain stable around each actual mutation.
                    let selected=self.state.manifest.plan.source_for_put(index);
                    if !matches!((source_guard.as_ref(),selected),(Some(guard),Some(source)) if guard.matches(source)) {
                        source_guard=selected.map(plan::indexed::SourceGuard::open).transpose()?;
                    }
                    if let Some(guard)=source_guard.as_ref(){guard.stable()?;}
                    let request_hash=read_request(&mut repo,&put,blocks,&mut body,&mut wire)?;
                    append(self.store,self.state,model::Event::Intent{index,request_hash})?;
                    let attempt=self.state.pending.ok_or(Cause::State("original publication intent missing"))?.attempt;
                    let task=*self.store.task_id();let mut control_error=None;
                    let answer=publish::execute_controlled(&mut client,&mut time,request(&put,blocks,&body),None,Some(put.key),||{
                        match self.check(&mut work,clock.as_ref(),deadline,&mut last,&mut control) {
                            Ok(None)=>true,Ok(Some(_))=>false,Err(error)=>{control_error=Some(error);false}
                        }
                    }).await;
                    let native=match answer {Ok(answer)=>NativeResult::answer(task,attempt,answer),Err(error)=>NativeResult::failure(task,attempt,*error)};
                    if matches!(native.outcome(),Some(NativeOutcome::Status{code,..}) if code>=0) {
                        work.new.accepted=work.new.accepted.checked_add(1).ok_or(ProtocolError::Overflow)?;
                        work.new.bytes=work.new.bytes.checked_add(put.payload.bytes as u128).ok_or(ProtocolError::Overflow)?;
                    }
                    last_native=Some(native);
                    let native=last_native.as_ref().ok_or(Cause::State("original native result missing"))?;
                    // A failed intent/lifecycle write fences the writer, but its
                    // actual native result remains available independently.
                    if let Some(error)=control_error{return Err(error.into());}
                    let effect=native.record_inner(self.store,self.state)?;
                    if native.retirement_failed(){return Err(Abort::Native);}
                    match effect {
                        Effect::Accepted=>{
                            if let Some(guard)=source_guard.as_ref(){guard.stable()?;}
                            if let Some(reason)=work.wanted{return Ok(reason);}
                            if native.failed{return Err(Abort::Native);}
                            if let Some(interruption)=native.interruption() {
                                let reason=match interruption {Interruption::Cancelled=>StopReason::CallerPause,Interruption::TimedOut=>StopReason::Deadline};
                                return Ok(self.request(&mut work,reason)?);
                            }
                        }
                        Effect::NotApplied=>{
                            if let Some(reason)=work.wanted{return Ok(reason);}
                            return Err(Abort::Native);
                        }
                        Effect::Refused|Effect::Uncertain=>{
                            if work.wanted==Some(StopReason::Cancelled){return Ok(StopReason::Cancelled);}
                            return Err(Abort::Native);
                        }
                    }
                }
                if let Some(reason)=self.check(&mut work,clock.as_ref(),deadline,&mut last,&mut control)?{return Ok(reason);}
                check_sources(&self.state.manifest.plan)?;
                Ok(StopReason::Complete)
            }.await;
            cleanup=client.close().err();operation
        }.await;
        if matches!(result, Ok(StopReason::Complete))
            && let Some(prepared) = graph_prepared.as_ref()
        {
            let operation: Result<(), Cause> = (|| {
                let graph = graph
                    .as_deref_mut()
                    .ok_or(Cause::State("original namespace graph is missing"))?;
                let actual = graph_runner::commit(self.state, graph, prepared)?;
                work.graph_verified = true;
                work.graph_newly = actual.receipt().newly_recorded();
                last_graph = Some(actual);
                // Caller control observes the actual graph success before the
                // independent task WAL barrier; failures retain its receipt.
                if let Some(reason) =
                    self.check(&mut work, clock.as_ref(), deadline, &mut last, &mut control)?
                {
                    result = Ok(reason);
                }
                last_graph
                    .as_ref()
                    .ok_or(ProtocolError::Stale)?
                    .record_inner(self.store, self.state)?;
                Ok(())
            })();
            if let Err(error) = operation {
                result = Err(Abort::Local(error));
            }
        }
        let (mut cause, reason) = match result {
            Ok(reason) => (None, Some(reason)),
            Err(Abort::Local(error)) => (Some(error), None),
            Err(Abort::Native) => (None, None),
        };
        if let Some(reason) = reason
            && (cleanup.is_none() || reason == StopReason::Complete)
        {
            let target = match reason {
                StopReason::Complete => Phase::Complete,
                StopReason::Cancelled => Phase::Cancelled,
                _ => Phase::Paused,
            };
            match phase(self.store, self.state, target) {
                Ok(()) => {
                    let progress = work.progress(self.store, self.state);
                    let completed = if reason == StopReason::Complete {
                        Some(Completed {
                            verified: verified.ok_or_else(|| {
                                empty_failure(Cause::State(
                                    "complete publication lacks current payload proof",
                                ))
                            })?,
                            progress,
                        })
                    } else {
                        None
                    };
                    return Ok(Outcome {
                        reason,
                        progress,
                        completed,
                        last_native,
                        last_index,
                        last_graph,
                        cleanup,
                    });
                }
                Err(error) => cause = Some(error),
            }
        }
        let mut state_failure = None;
        if !self.store.fenced() && self.state.phase != Phase::CancelRequested {
            let target = if self.state.uncertain() {
                Phase::Uncertain
            } else {
                Phase::Failed
            };
            if let Err(error) = phase(self.store, self.state, target) {
                state_failure = Some(error);
            }
        }
        Err(Box::new(Failure {
            cause,
            native: last_native,
            index: last_index,
            graph: last_graph,
            cleanup,
            state_failure,
            progress: work.progress(self.store, self.state),
            requested_stop: work.wanted,
        }))
    }
}
pub(super) fn verify_history(
    store: &mut Store,
    state: &model::State,
    repo: &mut Repository,
    body: &mut Vec<u8>,
    wire: &mut Vec<u8>,
) -> Result<(), Cause> {
    // All prior ACK bindings are checked against the actual freshly
    // verified bytes before a new weighted request may be issued.
    for accepted in &state.accepted {
        let put = state
            .manifest
            .plan
            .puts
            .get(accepted.attempt.index)
            .ok_or(ProtocolError::Stale)?;
        let digest = read_request(repo, put, state.manifest.blocks, body, wire)?;
        if digest != accepted.attempt.request_hash {
            return Err(Cause::State(
                "historical PUT differs from prepared artifact",
            ));
        }
        let record = store
            .read_record(accepted.record_index)?
            .ok_or(ProtocolError::Stale)?;
        let (attempt, reply, interruption) = codec::accepted_view(record.kind, record.bytes)?;
        if attempt != accepted.attempt
            || interruption != accepted.interruption
            || !matches!(Response::decode(reply)?,Response::Status(status) if status.code>=0)
        {
            return Err(Cause::State("historical original reply differs"));
        }
    }
    for accepted in &state.indexes.accepted {
        let source = state
            .manifest
            .plan
            .index_sources()
            .get(accepted.attempt.index)
            .ok_or(ProtocolError::Stale)?;
        if index_runner::request_hash(source)? != accepted.attempt.request_hash {
            return Err(Cause::State(
                "historical INDEX_START differs from original source",
            ));
        }
        let record = store
            .read_record(accepted.record_index)?
            .ok_or(ProtocolError::Stale)?;
        let (attempt, reply, interruption) =
            registration::accepted_view(record.kind, record.bytes)?;
        if attempt != accepted.attempt
            || interruption != accepted.interruption
            || !matches!(
                gnunet_wire::official::fs::Response::decode(reply)?,
                gnunet_wire::official::fs::Response::IndexStarted
            )
        {
            return Err(Cause::State(
                "historical original registration reply differs",
            ));
        }
    }
    Ok(())
}
fn check_sources(plan: &plan::Plan) -> Result<(), plan::Error> {
    for source in plan.index_sources() {
        plan::indexed::SourceGuard::open(source)?.stable()?;
    }
    Ok(())
}
impl NativeResult {
    fn answer(task: [u8; 32], attempt: Attempt, answer: Answer<'_>) -> Self {
        let outcome = answer.taken.completion.outcome;
        let interruption = answer.taken.completion.interruption;
        Self {
            task,
            attempt,
            submission: Submission::Submitted,
            outcome: Some(outcome),
            interruption,
            requested_cancel: answer.requested_cancel,
            cause: answer.cause,
            settlement_error: None,
            frame: answer.taken.into_frame(),
            failed: false,
        }
    }
    fn failure(task: [u8; 32], attempt: Attempt, error: ExecutionFailure) -> Self {
        let (outcome, interruption) = match &error.cause {
            network::Error::Store(store) => (Some(store.outcome), store.interruption),
            _ => (None, None),
        };
        Self {
            task,
            attempt,
            submission: match error.submission {
                publish::Submission::Submitted => Submission::Submitted,
                publish::Submission::NotSubmitted => Submission::NotSubmitted,
            },
            outcome,
            interruption,
            requested_cancel: error.requested_cancel,
            cause: Some(error.cause),
            settlement_error: error.settlement_error,
            frame: None,
            failed: true,
        }
    }
    fn retirement_failed(&self) -> bool {
        self.settlement_error.is_some()
            || matches!(self.cause.as_ref(),Some(network::Error::Store(failure)) if failure.retirement_error.is_some())
    }
    pub(super) fn record_inner(
        &self,
        store: &mut Store,
        state: &mut model::State,
    ) -> Result<Effect, Cause> {
        if &self.task != store.task_id() {
            return Err(Cause::State(
                "completion belongs to another publication task",
            ));
        }
        if let Some(accepted) = state.accepted.get(self.attempt.index) {
            let original = store
                .read_record(accepted.record_index)?
                .ok_or(ProtocolError::Stale)?;
            let (attempt, response, interruption) =
                codec::accepted_view(original.kind, original.bytes)?;
            if attempt == self.attempt
                && self.response_bytes() == Some(response)
                && self.interruption == interruption
            {
                return Ok(Effect::Accepted);
            }
            return Err(Cause::State(
                "completion differs from original accepted row",
            ));
        }
        let pending = state
            .pending
            .ok_or(Cause::State("original intent is no longer pending"))?;
        if pending.attempt != self.attempt {
            return Err(Cause::State(
                "completion belongs to another intent generation",
            ));
        }
        if pending.disposition != Disposition::Intent {
            return Err(Cause::State(
                "original disposition already recorded; do not repeat it",
            ));
        }
        let mut effect = Effect::Uncertain;
        let event = if self.submission == Submission::NotSubmitted {
            effect = Effect::NotApplied;
            model::Event::NotApplied {
                attempt: self.attempt,
                reason: NoEffect::NotSubmitted,
                interruption: self.interruption,
            }
        } else {
            match self.outcome {
                Some(NativeOutcome::NotSent) => {
                    effect = Effect::NotApplied;
                    model::Event::NotApplied {
                        attempt: self.attempt,
                        reason: NoEffect::NotSent,
                        interruption: self.interruption,
                    }
                }
                Some(NativeOutcome::Cancelled) => {
                    effect = Effect::NotApplied;
                    model::Event::NotApplied {
                        attempt: self.attempt,
                        reason: NoEffect::CancelledBeforeSend,
                        interruption: self.interruption,
                    }
                }
                Some(NativeOutcome::TimedOut) => {
                    effect = Effect::NotApplied;
                    model::Event::NotApplied {
                        attempt: self.attempt,
                        reason: NoEffect::TimedOutBeforeSend,
                        interruption: self.interruption,
                    }
                }
                Some(outcome) => {
                    let response = self.response_bytes();
                    let actual = response.and_then(|bytes| Response::decode(bytes).ok());
                    if matches!((outcome,&actual),(NativeOutcome::Status{code,min_expiration},Some(Response::Status(status))) if code==status.code&&min_expiration==status.min_expiration)
                    {
                        let bytes = response.ok_or(ProtocolError::NotReady)?;
                        if matches!(outcome,NativeOutcome::Status{code,..} if code>=0) {
                            effect = Effect::Accepted;
                            model::Event::Accepted {
                                attempt: self.attempt,
                                response: bytes,
                                interruption: self.interruption,
                            }
                        } else {
                            effect = Effect::Refused;
                            model::Event::Refused {
                                attempt: self.attempt,
                                response: bytes,
                                interruption: self.interruption,
                            }
                        }
                    } else {
                        model::Event::Unknown {
                            attempt: self.attempt,
                            outcome,
                            response,
                            interruption: self.interruption,
                        }
                    }
                }
                None => return Ok(Effect::Uncertain),
            }
        };
        append(store, state, event)?;
        Ok(effect)
    }
}
