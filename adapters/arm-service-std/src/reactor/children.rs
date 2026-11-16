//! Original process launch, signal and consuming-reap settlements.
use super::*;

impl<'view, 'scope, 'spec, 'slots, 'bytes, C: Clock>
    Driver<'view, 'scope, 'spec, 'slots, 'bytes, C>
{
    /// Force termination only through the original native process authority:
    /// SIGKILL on Unix, TerminateProcess on Windows. Cooperative control is
    /// bypassed. Actual child exit and consuming waits remain separate.
    pub fn kill_remaining(&mut self) {
        for index in 0..self.state.children.len() {
            let original = self.state.children[index].original.clone();
            if self.children.owns(&original) {
                if let Err(error) = process::kill(self.children, &original) {
                    self.state.diagnostic(Diagnostic::Signal(error))
                }
                self.state.counters.kill_attempts =
                    self.state.counters.kill_attempts.saturating_add(1);
            }
        }
    }
    pub(super) fn spawn_service(
        &mut self,
        service: ServiceId<'scope>,
        mode: process::ControlMode,
    ) -> Result<SpawnResult, Error> {
        let index = self
            .state
            .services
            .iter()
            .position(|id| *id == service)
            .ok_or(Error::Mapping)?;
        let entry = self.registry.services().get(index).ok_or(Error::Mapping)?;
        if self.state.children.len() == self.state.limits.services {
            return Err(Error::Capacity);
        }
        let mut listeners = Vec::new();
        listeners
            .try_reserve_exact(self.managed.len())
            .map_err(|_| Error::Capacity)?;
        for i in 0..self.managed.len() {
            if self.managed.service_index(i) == Some(index) {
                let id = self.managed.id(i).ok_or(Error::Mapping)?;
                listeners.push(self.managed.descriptor(id).ok_or(Error::Mapping)?);
            }
        }
        process::spawn(
            process::Request {
                context: self.launch,
                recipe: &entry.recipe,
                mode,
                listeners,
            },
            self.state.limits.process,
            self.children,
        )
        .map_err(|error| match error {
            LaunchError::Capacity => Error::AdmissionCapacity,
            other => Error::Native(other),
        })
    }
    pub(super) fn native(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        self.state.native_waiting = false;
        if self.state.pending_native.is_none() {
            self.state.pending_native = self.owner.take_native()?.map(|effect| match effect {
                NativeEffect::Spawn {
                    ticket,
                    child,
                    service,
                    pipe_control,
                    ..
                } => Native::Spawn {
                    ticket,
                    child,
                    service,
                    pipe: pipe_control,
                },
                NativeEffect::Term { ticket, child } => Native::Term { ticket, child },
            });
        }
        let Some(effect) = self.state.pending_native else {
            return Ok(false);
        };
        match effect {
            Native::Spawn {
                ticket,
                child,
                service,
                pipe,
            } => {
                if !self.owner.native_current(ticket) {
                    return Err(Error::Mapping);
                }
                if self.state.spawn_outcome.is_none() {
                    match self.spawn_service(
                        service,
                        if pipe {
                            process::ControlMode::Pipe
                        } else {
                            process::ControlMode::Native
                        },
                    ) {
                        Ok(SpawnResult::Admitted(receipt)) => {
                            self.state.children.push(Child {
                                core: child,
                                original: receipt.child,
                                control: receipt.control,
                                service: self
                                    .state
                                    .services
                                    .iter()
                                    .position(|id| *id == service)
                                    .ok_or(Error::Mapping)?,
                            });
                            if let Some(error) = receipt.diagnostic {
                                self.state.diagnostic(Diagnostic::Startup(error));
                            }
                            self.state.spawn_outcome = Some(SpawnOutcome::Admitted);
                            self.state.counters.spawned =
                                self.state.counters.spawned.saturating_add(1);
                        }
                        Ok(SpawnResult::Refused { error }) => {
                            self.state.spawn_outcome = Some(SpawnOutcome::Failed);
                            self.state.counters.spawn_refused =
                                self.state.counters.spawn_refused.saturating_add(1);
                            self.state.diagnostic(Diagnostic::Spawn(error));
                        }
                        Err(error @ Error::AdmissionCapacity) => {
                            // A real no-child resource/preparation refusal is a
                            // visible host profile, never a retry that blocks
                            // original child cleanup or a manufactured admission.
                            self.state.spawn_outcome = Some(SpawnOutcome::Failed);
                            self.state.counters.spawn_refused =
                                self.state.counters.spawn_refused.saturating_add(1);
                            self.state.diagnostic(Diagnostic::Admission(error));
                        }
                        Err(error) => return Err(error),
                    }
                }
                let utc = self.utc()?;
                let outcome = self.state.spawn_outcome.ok_or(Error::State)?;
                let report = self.owner.spawned(ticket, outcome, utc)?;
                self.state.spawn_outcome = None;
                self.state.pending_native = None;
                let _closures = report.resource_closures;
            }
            Native::Term { ticket, child } => {
                if !self.owner.native_current(ticket) {
                    return Err(Error::Mapping);
                }
                if !self.state.term_attempted {
                    let index = self
                        .state
                        .children
                        .iter()
                        .position(|owned| owned.core == child)
                        .ok_or(Error::Mapping)?;
                    let owned = &mut self.state.children[index];
                    if !self.children.owns(&owned.original) {
                        return Err(Error::Mapping);
                    }
                    let result = match process::poll_stop(
                        self.children,
                        &owned.original,
                        &mut owned.control,
                        cx,
                    ) {
                        Poll::Pending => {
                            self.state.native_waiting = true;
                            return Ok(false);
                        }
                        Poll::Ready(result) => result,
                    };
                    let notice = process::take_signal_notice(&mut owned.control);
                    if let Some(error) = notice {
                        self.state.diagnostic(Diagnostic::Signal(error));
                    }
                    if let Err(error) = result {
                        self.state.diagnostic(Diagnostic::Signal(error));
                    }
                    self.state.term_attempted = true;
                    self.state.counters.term_attempts =
                        self.state.counters.term_attempts.saturating_add(1);
                }
                self.owner.term_attempted(ticket)?;
                self.state.term_attempted = false;
                self.state.pending_native = None;
            }
        }
        Ok(true)
    }
    pub(super) fn reap(&mut self) -> Result<bool, Error> {
        if self.state.resource_event.is_some() {
            return Ok(false);
        }
        if self.state.pending_reap.is_none() {
            // This is a dedicated daemon registry. A visible unrelated original
            // must not be consumed by a different source service owner.
            if self.children.children().any(|original| {
                !self
                    .state
                    .children
                    .iter()
                    .any(|owned| owned.original == *original)
            }) {
                return Err(Error::Mapping);
            }
            process::reap_completed(self.children)?;
            if let Some((event, usage)) = self.children.take_completed_with_usage() {
                self.state.pending_reap = Some(event);
                self.state.pending_usage = usage;
            }
        }
        let Some(reap) = self.state.pending_reap.as_ref() else {
            return Ok(false);
        };
        let Some(index) = self
            .state
            .children
            .iter()
            .position(|c| c.original == reap.child)
        else {
            // Preserve the actual observation as an explicit error capability;
            // never silently count it as this formal daemon's successful reap.
            let event = self.state.pending_reap.take().ok_or(Error::State)?;
            return Err(Error::ForeignCompletion(event));
        };
        let id = self.state.children[index].core;
        if let Some(usage) = self.state.pending_usage.take() {
            self.state.resource_event = Some(ResourceEvent {
                service: self.state.children[index].service,
                event: reap.clone(),
                usage,
            });
        }
        let exit = process::exit(reap);
        let utc = self.utc()?;
        let report = self.owner.reaped(id, exit, utc)?;
        let _closures = report.resource_closures;
        self.state.children.remove(index);
        if self.state.next_child > index {
            self.state.next_child -= 1;
        }
        if self.state.next_child >= self.state.children.len() {
            self.state.next_child = 0;
        }
        self.state.pending_reap = None;
        self.state.counters.reaped = self.state.counters.reaped.saturating_add(1);
        // Actual reaped(nonzero) requested an IDLE task; settle its cancellation
        // before allowing any unrelated callback to run.
        Ok(true)
    }
    pub(super) fn poll_controls(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        let length = self.state.children.len();
        if length == 0 {
            return Ok(false);
        }
        let first = self.state.next_child % length;
        for index in (first..length).chain(0..first) {
            let child = &mut self.state.children[index];
            if let Poll::Ready(result) =
                process::poll_control(&mut child.control, self.children, &child.original, cx)
            {
                self.state.next_child = (index + 1) % length;
                match result {
                    Ok(event) => {
                        #[cfg(unix)]
                        match event {}
                        #[cfg(windows)]
                        match event {
                            process::ControlEvent::Ready => {
                                self.state.counters.startup_ready =
                                    self.state.counters.startup_ready.saturating_add(1)
                            }
                            process::ControlEvent::RetirementRequested => {
                                self.state.counters.preparation_retired =
                                    self.state.counters.preparation_retired.saturating_add(1)
                            }
                        }
                    }
                    Err(error) => self.state.diagnostic(Diagnostic::Startup(error)),
                }
                return Ok(true);
            }
        }
        Ok(false)
    }
}
