use crate::{Failure, options::Settings, terminal::Descriptor};
use gnunet_conversation_client_host::{Audio, Bounds, Call, Epoch};
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_service_runtime::process::{self, ChildRegistry, OriginalChild, Reaped};
use gnunet_wire::official::{MessageHeader, conversation::Message, message_type};
use std::sync::Arc;
use std::{
    collections::VecDeque,
    future::Future,
    os::fd::AsFd,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Side {
    Phone,
    Outgoing,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Binding {
    pub side: Side,
    pub call: Call,
    pub epoch: Epoch,
}
struct FrameBudget {
    bounds: Bounds,
    canonical: Pin<Box<Deadline>>,
    native: Pin<Box<tokio::time::Sleep>>,
}
impl FrameBudget {
    fn new(
        clock: Arc<dyn RuntimeClock>,
        life: std::time::Duration,
        original: Bounds,
    ) -> Result<Self, Failure> {
        let mut bounds = Bounds::new(clock.as_ref(), life)?;
        bounds.expires = bounds.expires.min(original.expires);
        bounds.hard = bounds.hard.min(original.hard);
        let canonical = Box::pin(Deadline::at(
            clock,
            gnunet_types::AbsoluteTime::from_micros(bounds.expires),
        )?);
        Ok(Self {
            bounds,
            canonical,
            native: Box::pin(tokio::time::sleep_until(bounds.hard.into())),
        })
    }
    fn poll(&mut self, cx: &mut Context<'_>, clock: &dyn RuntimeClock) -> Result<(), Failure> {
        self.bounds.check(clock)?;
        if self.native.as_mut().poll(cx).is_ready() {
            return Err(gnunet_types::Error::Deadline.into());
        }
        match self.canonical.as_mut().poll(cx) {
            Poll::Pending => Ok(()),
            Poll::Ready(Ok(())) => Err(gnunet_types::Error::Deadline.into()),
            Poll::Ready(Err(e)) => Err(e.into()),
        }
    }
}
struct Playback {
    budget: FrameBudget,
    audio: Audio,
    header: [u8; 4],
    at: usize,
}
struct Stop {
    hard: Instant,
    alarm: Pin<Box<tokio::time::Sleep>>,
    killed: bool,
}
#[derive(Debug)]
pub(super) struct Report {
    pub binding: Binding,
    pub bounds: Bounds,
    pub record_child: Option<OriginalChild>,
    pub playback_child: Option<OriginalChild>,
    pub exits: Vec<Reaped>,
    pub recorded_bytes: u64,
    pub submitted_bytes: u64,
    pub playback_frames: u64,
    pub partial_record: usize,
    pub partial_playback: usize,
    pub original: Option<Failure>,
    pub cleanup: Vec<Failure>,
    pub cleanup_overflow: bool,
    pub undrained: usize,
    pub term_succeeded: [bool; 2],
    pub kill_succeeded: [bool; 2],
}
impl Report {
    fn error(&mut self, error: Failure) {
        if self.cleanup.len() < 16 {
            self.cleanup.push(error);
        } else {
            self.cleanup_overflow = true;
        }
    }
}
pub(super) enum Event {
    Activity,
    Ended,
}
/// One explicitly owned process pair, never a SDK background worker.
pub(super) struct Media {
    registry: ChildRegistry,
    record: Option<Descriptor>,
    playback: Option<Descriptor>,
    input: Zeroizing<Vec<u8>>,
    used: usize,
    need: usize,
    segment: usize,
    output: VecDeque<Playback>,
    frames: usize,
    stop: Option<Stop>,
    report: Option<Report>,
    reap_error: bool,
    read_first: bool,
    clock: Arc<dyn RuntimeClock>,
    input_budget: Option<FrameBudget>,
    input_timeout: std::time::Duration,
    write_timeout: std::time::Duration,
    facts: crate::run::Shared,
}
impl Media {
    pub fn new(
        frames: usize,
        facts: crate::run::Shared,
        clock: Arc<dyn RuntimeClock>,
        input_timeout: std::time::Duration,
        write_timeout: std::time::Duration,
    ) -> Result<Self, Failure> {
        let registry = ChildRegistry::new(2)?;
        let mut input = Zeroizing::new(Vec::new());
        input.try_reserve_exact(65535)?;
        if input.capacity() > 65535 {
            return Err("media input capacity exceeds official framing".into());
        }
        input.resize(65535, 0);
        let mut output = VecDeque::new();
        output.try_reserve_exact(frames)?;
        Ok(Self {
            registry,
            record: None,
            playback: None,
            input,
            used: 0,
            need: 4,
            segment: 4,
            output,
            frames,
            stop: None,
            report: None,
            reap_error: false,
            read_first: true,
            clock,
            input_budget: None,
            input_timeout,
            write_timeout,
            facts,
        })
    }
    pub fn idle(&self) -> bool {
        self.report.is_none() && self.registry.pending_children() == 0
    }
    pub fn binding(&self) -> Option<&Binding> {
        self.report.as_ref().map(|r| &r.binding)
    }
    pub fn stopping(&self) -> bool {
        self.stop.is_some()
    }
    pub fn start(
        &mut self,
        binding: Binding,
        bounds: Bounds,
        c: &gnunet_config::Configuration,
        s: &Settings,
    ) -> Result<(), Failure> {
        if !self.idle() {
            return Err("previous actual media children have not been reaped".into());
        }
        bounds.check(self.clock.as_ref())?;
        let mut exits = Vec::new();
        exits.try_reserve_exact(2)?;
        let mut cleanup = Vec::new();
        cleanup.try_reserve_exact(16)?;
        self.report = Some(Report {
            binding,
            bounds,
            record_child: None,
            playback_child: None,
            exits,
            recorded_bytes: 0,
            submitted_bytes: 0,
            playback_frames: 0,
            partial_record: 0,
            partial_playback: 0,
            original: None,
            cleanup,
            cleanup_overflow: false,
            undrained: 0,
            term_succeeded: [false; 2],
            kill_succeeded: [false; 2],
        });
        self.reap_error = false;
        let clock = self.clock.clone();
        let result = (|| -> Result<(), Failure> {
            let (rec_read, rec_write) = process::pipe()?;
            let (play_read, play_write) = process::pipe()?;
            for fd in [&rec_write, &play_read] {
                use nix::fcntl::{FcntlArg, OFlag, fcntl};
                let flags = OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL)?);
                fcntl(fd, FcntlArg::F_SETFL(flags & !OFlag::O_NONBLOCK))?;
            }
            self.record = Some(Descriptor::pipe(rec_read)?);
            self.playback = Some(Descriptor::pipe(play_write)?);
            let spawn = |path: &std::path::Path,
                         mapping: process::DescriptorMap<'_>,
                         registry: &mut ChildRegistry|
             -> Result<OriginalChild, Failure> {
                let filename = path.as_os_str().to_os_string();
                let command = process::NativeCommand {
                    filename: filename.clone(),
                    argv: vec![filename],
                    environment: process::EnvironmentSnapshot::system()?,
                    environment_changes: Vec::new(),
                    cwd: None,
                    stdio: 4,
                    stdio_snapshot: None,
                    listeners: Vec::new(),
                    mappings: vec![mapping],
                };
                // Same original call budget after synchronous environment /
                // descriptor preparation, including before the second child.
                bounds.check(clock.as_ref())?;
                match process::spawn(
                    c,
                    &s.launcher,
                    command,
                    process::ProcessLimits {
                        launch: process::LaunchLimits {
                            max_children: 2,
                            max_arguments: 8,
                            max_command_bytes: 16384,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    registry,
                )? {
                    process::SpawnResult::Admitted(child) => Ok(child.child),
                    process::SpawnResult::Refused { error: Some(e) } => Err(e.into()),
                    process::SpawnResult::Refused { error: None } => {
                        Err("media executable/native admission was refused without a child".into())
                    }
                }
            };
            let child = spawn(
                &s.record,
                process::DescriptorMap {
                    source: rec_write.as_fd(),
                    target: 1,
                },
                &mut self.registry,
            )?;
            self.report
                .as_mut()
                .ok_or("media report missing after actual admission")?
                .record_child = Some(child);
            let child = spawn(
                &s.playback,
                process::DescriptorMap {
                    source: play_read.as_fd(),
                    target: 0,
                },
                &mut self.registry,
            )?;
            self.report
                .as_mut()
                .ok_or("media report missing after actual admission")?
                .playback_child = Some(child);
            Ok(())
        })();
        if let Err(error) = result {
            self.report.as_mut().ok_or("media report missing")?.original = Some(error);
            self.begin_stop(s.shutdown);
            return Err(
                "actual media preparation failed; original error and child cleanup remain retained"
                    .into(),
            );
        }
        Ok(())
    }
    fn children(&self) -> [Option<OriginalChild>; 2] {
        match &self.report {
            Some(report) => [
                report
                    .record_child
                    .clone()
                    .filter(|c| self.registry.owns(c)),
                report
                    .playback_child
                    .clone()
                    .filter(|c| self.registry.owns(c)),
            ],
            None => [None, None],
        }
    }
    fn signal_all(&mut self, signal: i32) {
        for (index, child) in self.children().into_iter().enumerate() {
            if let Some(child) = child {
                let result = self.registry.signal_native(&child, signal);
                if let Some(report) = &mut self.report {
                    match result {
                        Ok(()) => {
                            if signal == nix::libc::SIGTERM {
                                report.term_succeeded[index] = true;
                            } else if signal == nix::libc::SIGKILL {
                                report.kill_succeeded[index] = true;
                            }
                        }
                        Err(e) => report.error(e.into()),
                    }
                }
            }
        }
    }
    pub fn playback_room(&self) -> bool {
        self.output.len() < self.frames
    }
    pub fn begin_stop(&mut self, grace: std::time::Duration) {
        if self.report.is_none() || self.stop.is_some() {
            return;
        }
        // Withdraw all old source input/output before sending any child signal.
        if let Some(mut fd) = self.record.take()
            && let Some(error) = fd.close()
            && let Some(report) = &mut self.report
        {
            report.error(error.into());
        }
        if let Some(mut fd) = self.playback.take()
            && let Some(error) = fd.close()
            && let Some(report) = &mut self.report
        {
            report.error(error.into());
        }
        if let Some(report) = &mut self.report {
            report.partial_record = self.used;
            report.partial_playback = self.output.front().map_or(0, |p| p.at);
        }
        self.output.clear();
        self.input_budget = None;
        self.input.zeroize();
        self.used = 0;
        self.need = 4;
        self.segment = 4;
        let start = Instant::now();
        let hard = start.checked_add(grace).unwrap_or(start);
        let kill_at = start.checked_add(grace / 2).unwrap_or(start);
        self.stop = Some(Stop {
            hard,
            alarm: Box::pin(tokio::time::sleep_until(kill_at.into())),
            killed: false,
        });
        self.signal_all(nix::libc::SIGTERM);
    }
    pub fn record_chunk(&self, maximum: usize) -> Option<&[u8]> {
        if self.stop.is_some()
            || self.used != self.need
            || self.need == 4
            || self.segment >= self.need
        {
            return None;
        }
        let end = self.segment.saturating_add(maximum).min(self.need);
        Some(&self.input[self.segment..end])
    }
    pub fn consume_record(&mut self, bytes: usize) -> Result<(), Failure> {
        let remaining = self
            .need
            .checked_sub(self.segment)
            .ok_or("record segment cursor invalid")?;
        if self.used != self.need || bytes > remaining {
            return Err("record segment exceeds original730".into());
        }
        self.segment += bytes;
        if self.segment == self.need {
            self.input[..self.used].zeroize();
            self.used = 0;
            self.need = 4;
            self.segment = 4;
        }
        Ok(())
    }
    pub fn enqueue(&mut self, binding: &Binding, audio: Audio) -> Result<(), (Failure, Audio)> {
        let fail = |message: &str, audio: Audio| Err((message.into(), audio));
        if self.stop.is_some() || self.binding() != Some(binding) {
            return fail("audio belongs to another original media Call/Epoch", audio);
        }
        if self.output.len() >= self.frames {
            return fail("playback audio queue is full", audio);
        }
        let n = match audio.bytes().len().checked_add(4) {
            Some(n) => n,
            None => return fail("helper audio extent overflow", audio),
        };
        let mut header = [0; 4];
        let result = MessageHeader::from_total_size(message_type::CONVERSATION_AUDIO, n)
            .and_then(|h| h.encode(&mut header));
        if let Err(e) = result {
            return Err((Box::new(e), audio));
        }
        let original = match self.report.as_ref() {
            Some(report) => report.bounds,
            None => return fail("media original report unavailable", audio),
        };
        let budget = match FrameBudget::new(self.clock.clone(), self.write_timeout, original) {
            Ok(budget) => budget,
            Err(e) => return Err((e, audio)),
        };
        self.output.push_back(Playback {
            budget,
            audio,
            header,
            at: 0,
        });
        Ok(())
    }
    fn read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, Failure>> {
        if self.used == self.need && self.need > 4 {
            return Poll::Pending;
        }
        let first = if self.used == 0 {
            let original = self
                .report
                .as_ref()
                .ok_or("record original report missing")?
                .bounds;
            let mut bounds = Bounds::new(self.clock.as_ref(), self.input_timeout)?;
            bounds.expires = bounds.expires.min(original.expires);
            bounds.hard = bounds.hard.min(original.hard);
            Some(bounds)
        } else {
            None
        };
        let Some(fd) = &mut self.record else {
            return Poll::Pending;
        };
        let original = self
            .report
            .as_ref()
            .ok_or("original media report missing before pipe read")?
            .bounds;
        original.check(self.clock.as_ref())?;
        if let Some(budget) = &mut self.input_budget {
            budget.poll(cx, self.clock.as_ref())?;
        }
        match fd.read(cx, &mut self.input[self.used..self.need]) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(0)) => Poll::Ready(Err(
                "record helper EOF while media was active; no call result is inferred".into(),
            )),
            Poll::Ready(Ok(n)) => {
                self.used += n;
                {
                    let report = self
                        .report
                        .as_mut()
                        .ok_or("record owner has no original report")?;
                    report.recorded_bytes = report
                        .recorded_bytes
                        .checked_add(u64::try_from(n)?)
                        .ok_or(gnunet_types::Error::Overflow)?;
                }
                if let Some(bounds) = first {
                    self.input_budget = Some(FrameBudget {
                        bounds,
                        canonical: Box::pin(Deadline::at(
                            self.clock.clone(),
                            gnunet_types::AbsoluteTime::from_micros(bounds.expires),
                        )?),
                        native: Box::pin(tokio::time::sleep_until(bounds.hard.into())),
                    });
                }
                if self.used == 4 && self.need == 4 {
                    let header = MessageHeader::decode(&self.input[..4])?;
                    if header.message_type() != message_type::CONVERSATION_AUDIO
                        || header.size() == 4
                    {
                        return Poll::Ready(Err(
                            "record helper did not produce nonempty standard730 Ogg bytes".into(),
                        ));
                    }
                    self.need = header.size();
                }
                if self.used == self.need {
                    if let Some(budget) = &mut self.input_budget {
                        budget.poll(cx, self.clock.as_ref())?;
                    }
                    self.input_budget = None;
                    match Message::decode(&self.input[..self.need])? {
                        Message::HelperAudio(_) => {}
                        _ => return Poll::Ready(Err("wrong original media helper frame".into())),
                    }
                }
                Poll::Ready(Ok(Event::Activity))
            }
        }
    }
    fn write(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, Failure>> {
        let Some(fd) = &mut self.playback else {
            return Poll::Pending;
        };
        let Some(front) = self.output.front_mut() else {
            return Poll::Pending;
        };
        front.budget.poll(cx, self.clock.as_ref())?;
        let bytes = if front.at < 4 {
            &front.header[front.at..]
        } else {
            &front.audio.bytes()[front.at - 4..]
        };
        match fd.write(cx, bytes) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(0)) => Poll::Ready(Err("playback helper write made no progress".into())),
            Poll::Ready(Ok(n)) => {
                front.at += n;
                let report = self
                    .report
                    .as_mut()
                    .ok_or("playback owner has no original report")?;
                report.submitted_bytes = report
                    .submitted_bytes
                    .checked_add(u64::try_from(n)?)
                    .ok_or(gnunet_types::Error::Overflow)?;
                if front.at == 4 + front.audio.bytes().len() {
                    let _original = self.output.pop_front();
                    report.playback_frames = report
                        .playback_frames
                        .checked_add(1)
                        .ok_or(gnunet_types::Error::Overflow)?;
                }
                Poll::Ready(Ok(Event::Activity))
            }
        }
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, Failure>> {
        if self.report.is_none() {
            return Poll::Pending;
        }
        let waited = self.registry.reap_completed();
        if let Err(error) = waited
            && !self.reap_error
        {
            if let Some(report) = &mut self.report {
                report.error(error.into());
            }
            self.reap_error = true;
        }
        while let Some(reaped) = self.registry.take_reaped() {
            if let Some(report) = &mut self.report {
                if report.exits.len() < 2 {
                    report.exits.push(reaped);
                } else {
                    report.cleanup_overflow = true;
                }
            }
        }
        if self.stop.is_none() && self.report.as_ref().is_some_and(|r| !r.exits.is_empty()) {
            return Poll::Ready(Err(
                "original media helper terminated while active; real exit retained".into(),
            ));
        }
        if self.registry.pending_children() == 0 {
            return if self.stop.is_some() {
                Poll::Ready(Ok(Event::Ended))
            } else {
                Poll::Ready(Err(
                    "media helper exited before explicit stop; actual exit retained".into(),
                ))
            };
        }
        if let Some(stop) = &mut self.stop {
            if stop.alarm.as_mut().poll(cx).is_ready() {
                if !stop.killed {
                    stop.killed = true;
                    stop.alarm.as_mut().reset(stop.hard.into());
                    self.signal_all(nix::libc::SIGKILL);
                } else {
                    if let Some(report) = &mut self.report {
                        report.undrained = self.registry.pending_children();
                    }
                    return Poll::Ready(Err(
                        "original media stop target expired with unreaped child debt".into(),
                    ));
                }
            }
        } else {
            self.report
                .as_ref()
                .ok_or("original media whole owner is missing")?
                .bounds
                .check(self.clock.as_ref())?;
            if let Some(budget) = &mut self.input_budget {
                budget.poll(cx, self.clock.as_ref())?;
            }
            for output in &mut self.output {
                output.budget.poll(cx, self.clock.as_ref())?;
            }
            let first = self.read_first;
            self.read_first = !first;
            for read in [first, !first] {
                let event = if read { self.read(cx) } else { self.write(cx) };
                if event.is_ready() {
                    return event;
                }
            }
        }
        match self.registry.poll_child_signal(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(Event::Activity)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
    pub fn take_report(&mut self) -> Option<Report> {
        if self.registry.pending_children() != 0 {
            return None;
        }
        self.record = None;
        self.playback = None;
        self.stop = None;
        self.output.clear();
        self.input_budget = None;
        self.input.zeroize();
        self.used = 0;
        self.need = 4;
        self.segment = 4;
        self.report.take()
    }
    pub fn pending_children(&self) -> usize {
        self.registry.pending_children()
    }
}
impl Drop for Media {
    fn drop(&mut self) {
        // This fallback performs no new allocation and never claims a reap. The
        // explicit foreground cleanup normally drains these owners beforehand.
        self.record = None;
        self.playback = None;
        self.output.clear();
        self.signal_all(nix::libc::SIGKILL);
        if let Err(e) = self.registry.reap_completed()
            && let Some(report) = &mut self.report
        {
            report.error(e.into());
        }
        while let Some(reaped) = self.registry.take_reaped() {
            if let Some(report) = &mut self.report {
                if report.exits.len() < 2 {
                    report.exits.push(reaped);
                } else {
                    report.cleanup_overflow = true;
                }
            }
        }
        if let Some(mut report) = self.report.take() {
            report.undrained = self.registry.pending_children();
            self.facts.borrow_mut().media(report);
        }
    }
}
