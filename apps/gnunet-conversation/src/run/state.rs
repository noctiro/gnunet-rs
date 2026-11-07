use super::{
    Bounds, Control, Failure, Shared,
    sources::{Selectors, Sources},
};
use crate::{
    media::{self, Binding, Side},
    options::{self, Command, Settings},
    terminal::{self, Terminal},
};
use gnunet_conversation_client_host as phone;
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

pub(super) enum Next {
    Continue,
    Call(Vec<u8>),
    Quit,
}
pub(super) enum Event {
    Activity,
    Command(Vec<u8>),
    Eof,
}
#[derive(Clone, Copy)]
enum Action {
    Accept,
    Suspend,
    Resume,
    Cancel,
}
struct Intent {
    action: Action,
    bounds: Bounds,
    operation: Option<phone::Operation>,
    alarm: Pin<Box<tokio::time::Sleep>>,
}
struct Entry {
    number: u64,
    side: Side,
    info: phone::CallInfo,
    intent: Option<Intent>,
}
/// UI numbers only address this bounded table. Every native action continues
/// to require the original opaque Call and observed physical Epoch.
pub(super) struct State<'id, 'p> {
    pub config: gnunet_config::Configuration,
    pub settings: Settings,
    pub selectors: Selectors,
    pub original: Bounds,
    sources: Sources<'id, 'p>,
    phone: Option<phone::Line>,
    phone_recovery: Option<Pin<Box<tokio::time::Sleep>>>,
    outgoing: Option<phone::Line>,
    port: [u8; 64],
    terminal: Terminal,
    media: media::Media,
    calls: Vec<Entry>,
    next_number: u64,
    active: Option<u64>,
    audio: VecDeque<(Binding, phone::Audio)>,
    turn: usize,
    closed: bool,
    finished: bool,
    quit: bool,
    output_failed: bool,
    cleanup_media_error: bool,
    facts: Shared,
    pub resolving: bool,
    pub cancel_resolution: bool,
}
impl<'id, 'p> State<'id, 'p> {
    pub fn new(
        config: gnunet_config::Configuration,
        settings: Settings,
        line: Vec<u8>,
        sources: Sources<'id, 'p>,
        selectors: Selectors,
        original: Bounds,
        facts: Shared,
    ) -> Result<Self, Failure> {
        let mut calls = Vec::new();
        calls.try_reserve_exact(settings.calls)?;
        let mut audio = VecDeque::new();
        audio.try_reserve_exact(settings.playback_frames)?;
        let media = media::Media::new(
            settings.playback_frames,
            facts.clone(),
            selectors.conversation.clock(),
            settings.native.input_timeout,
            settings.native.write_timeout,
        )?;
        let terminal = Terminal::new(settings.command_bytes, settings.output_bytes)?;
        Ok(Self {
            config,
            port: gnunet_crypto::hash512(&line),
            settings,
            selectors,
            original,
            sources,
            phone: None,
            phone_recovery: None,
            outgoing: None,
            terminal,
            media,
            calls,
            next_number: 1,
            active: None,
            audio,
            turn: 0,
            closed: false,
            finished: false,
            quit: false,
            output_failed: false,
            cleanup_media_error: false,
            facts,
            resolving: false,
            cancel_resolution: false,
        })
    }
    pub fn history(&self) -> Shared {
        self.facts.clone()
    }
    pub fn quit_requested(&self) -> bool {
        self.quit
    }
    pub fn ready(&self) -> bool {
        self.sources.ready()
    }
    pub fn register(&mut self) -> Result<(), Failure> {
        self.sources.check()?;
        self.phone = Some(phone::Line::register(
            self.selectors.conversation.duplicate()?,
            &self.port,
            self.settings.native,
            self.original,
        )?);
        self.terminal.message(b"Phone source initialized. Register731 is still only a local request. /help lists commands.\n")
    }
    pub fn poll_startup(
        &mut self,
        cx: &mut Context<'_>,
        startup: Bounds,
    ) -> Poll<Result<(), Failure>> {
        startup.check(self.selectors.conversation.clock().as_ref())?;
        if let Poll::Ready(e) = self.sources.poll(cx) {
            return Poll::Ready(e);
        }
        match self.terminal.poll(cx) {
            Poll::Ready(Ok(terminal::Event::Command(bytes))) => {
                let command = options::command(&bytes);
                match command {
                    Ok(Command::Quit) => {
                        self.quit = true;
                        return Poll::Ready(Ok(()));
                    }
                    Ok(Command::Help(_)) => self.help()?,
                    _ => self.terminal.message(
                        b"Waiting for actual IDENTITY initial list and verified PILS identity.\n",
                    )?,
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(terminal::Event::Eof)) => {
                self.quit = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(terminal::Event::Activity)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
    pub fn notice(&mut self, prefix: &[u8], bytes: &[u8]) -> Result<(), Failure> {
        let mut text = self.terminal.text();
        text.push(prefix)?;
        text.escaped(bytes)?;
        text.push(b"\n")?;
        self.terminal.enqueue(text)
    }
    fn help(&mut self) -> Result<(), Failure> {
        self.terminal.message(b"/address  /call FULL_GNS_NAME  /accept [#N]  /suspend  /resume [#N]  /cancel [#N]  /status  /quit  /help\nCall numbers address original local handles. Only actual pickup/local whole acceptance can activate media. /address does not publish.\n")
    }
    fn line_mut(&mut self, side: Side) -> Result<&mut phone::Line, Failure> {
        match side {
            Side::Phone => self.phone.as_mut(),
            Side::Outgoing => self.outgoing.as_mut(),
        }
        .ok_or_else(|| "original Conversation Line is unavailable".into())
    }
    fn record_loss(&mut self, loss: phone::Loss) {
        self.facts.borrow_mut().sdk(loss);
    }
    fn binding(entry: &Entry) -> Result<Binding, Failure> {
        Ok(Binding {
            side: entry.side,
            call: entry.info.call.clone(),
            epoch: entry
                .info
                .epoch
                .clone()
                .ok_or("call has no actually observed physical epoch")?,
        })
    }
    fn eligible(entry: &Entry) -> bool {
        entry.info.phase == phone::Phase::Connected
            && !entry.info.suspended_local
            && !entry.info.suspended_remote
            && (entry.info.pickup_written || entry.info.remote_pickup)
            && entry.intent.is_none()
    }
    fn update(&mut self, side: Side, info: phone::CallInfo) -> Result<u64, Failure> {
        if let Some(entry) = self
            .calls
            .iter_mut()
            .find(|e| e.side == side && e.info.call == info.call)
        {
            entry.info = info;
            return Ok(entry.number);
        }
        if self.calls.len() >= self.settings.calls {
            return Err("bounded simultaneous call table is full".into());
        }
        let number = self.next_number;
        self.next_number = number.checked_add(1).ok_or(gnunet_types::Error::Overflow)?;
        self.calls.push(Entry {
            number,
            side,
            info,
            intent: None,
        });
        Ok(number)
    }
    fn status_one(&mut self, index: usize) -> Result<(), Failure> {
        let e = &self.calls[index];
        let mut text = self.terminal.text();
        text.push(b"#")?;
        text.number(e.number)?;
        text.push(match e.side {
            Side::Phone => b" incoming ",
            Side::Outgoing => b" outgoing ",
        })?;
        text.push(format!("{:?}", e.info.phase).as_bytes())?;
        text.push(if e.info.suspended_local {
            b" local-suspended"
        } else {
            b""
        })?;
        text.push(if e.info.suspended_remote {
            b" remote-suspended"
        } else {
            b""
        })?;
        if let Some(caller) = &e.info.caller {
            text.push(b" caller=")?;
            let mut name = [0u8; 58];
            let n = gnunet_gnsrecord::encode_base32(caller, &mut name)?;
            text.push(&name[..n])?;
        }
        text.push(b"\n")?;
        self.terminal.enqueue(text)
    }
    fn announce(&mut self, number: u64, prefix: &[u8]) -> Result<(), Failure> {
        let mut text = self.terminal.text();
        text.push(prefix)?;
        text.push(b" #")?;
        text.number(number)?;
        text.push(b"\n")?;
        self.terminal.enqueue(text)
    }
    fn source_event(&mut self, side: Side, event: phone::Progress) -> Result<(), Failure> {
        match event {
            phone::Progress::Attached(_)
            | phone::Progress::Activity { .. }
            | phone::Progress::Ignored { .. } => {}
            phone::Progress::Retry { error, .. } => {
                self.facts.borrow_mut().retry("CONVERSATION", error);
            }
            phone::Progress::Written { receipt, .. } => {
                {
                    let mut facts = self.facts.borrow_mut();
                    facts.native_write_events = facts.native_write_events.saturating_add(1);
                    facts.last_write = Some(receipt.clone());
                }
                if !receipt.complete {
                    return Ok(());
                }
                let kind = receipt.kind;
                let call = receipt.call.clone();
                if let Some(call) = call {
                    let info = self.line_mut(side)?.info(&call)?;
                    let number = self.update(side, info)?;
                    if let Some(entry) = self.calls.iter_mut().find(|e| e.number == number)
                        && entry
                            .intent
                            .as_ref()
                            .is_some_and(|p| p.operation.as_ref() == Some(&receipt.operation))
                    {
                        entry.intent = None;
                    }
                    if matches!(kind, phone::Kind::PickUp | phone::Kind::Resume) {
                        // A second activation may have been queued before the
                        // first actual whole receipt set active. Settle the
                        // original receipt first, then suspend the now-observed
                        // prior active call rather than silently abandoning it.
                        if let Some(old) = self.active
                            && old != number
                        {
                            let index = self
                                .calls
                                .iter()
                                .position(|e| e.number == old)
                                .ok_or("previous active call lost its original handle")?;
                            if self.calls[index].info.phase == phone::Phase::Connected
                                && !self.calls[index].info.suspended_local
                            {
                                self.automatic_suspend(index)?;
                            }
                            self.stop_media();
                        }
                        self.active = Some(number);
                    }
                    if kind != phone::Kind::Audio {
                        self.announce(
                            number,
                            b"Whole original local control written (not remote ACK)",
                        )?;
                    }
                } else if kind == phone::Kind::Register {
                    self.terminal.message(b"Whole Register731 written locally; no remote/media readiness is inferred.\n")?;
                }
            }
            phone::Progress::Unsent { receipt } => {
                if let Some(call) = receipt.call
                    && let Some(e) = self
                        .calls
                        .iter_mut()
                        .find(|e| e.side == side && e.info.call == call)
                {
                    e.intent = None;
                }
                self.terminal.message(
                    b"Original control retired before any byte; no service processing result.\n",
                )?;
            }
            phone::Progress::Ring { info } => {
                let number = self.update(side, info)?;
                self.announce(number, b"Actual incoming Ring735")?;
            }
            phone::Progress::PickedUp { info } => {
                let number = self.update(side, info)?;
                if self.active.is_none() {
                    self.active = Some(number);
                } else if self.active != Some(number) {
                    let index = self
                        .calls
                        .iter()
                        .position(|e| e.number == number)
                        .ok_or("actual picked-up original call missing")?;
                    self.automatic_suspend(index)?;
                }
                self.announce(number, b"Actual outgoing PickedUp738")?;
            }
            phone::Progress::HangUp { info } => {
                let number = self.update(side, info)?;
                if self.active == Some(number) {
                    self.active = None;
                    self.stop_media();
                }
                self.announce(
                    number,
                    b"Actual service HangUp733 (peer delivery is not inferred)",
                )?;
            }
            phone::Progress::Suspended { info } | phone::Progress::Resumed { info } => {
                let number = self.update(side, info)?;
                if !self.media.stopping()
                    && self.media.binding().is_some_and(|b| {
                        self.calls.iter().any(|e| {
                            e.number == number && e.info.call == b.call && !Self::eligible(e)
                        })
                    })
                {
                    self.stop_media();
                }
                self.announce(number, b"Actual remote suspension-state notification")?;
            }
            phone::Progress::Audio { info, audio } => {
                let number = self.update(side, info)?;
                if self.active == Some(number) {
                    let entry = self
                        .calls
                        .iter()
                        .find(|e| e.number == number)
                        .ok_or("audio call table lost original handle")?;
                    if Self::eligible(entry) {
                        let binding = Self::binding(entry)?;
                        if self.audio.len() >= self.settings.playback_frames {
                            return Err("finite observed audio queue exhausted".into());
                        }
                        self.audio.push_back((binding, audio));
                    }
                }
            }
            phone::Progress::Lost(loss) => return self.source_lost(side, loss),
        }
        Ok(())
    }
    fn source_lost(&mut self, side: Side, loss: phone::Loss) -> Result<(), Failure> {
        let recover =
            side == Side::Phone && self.phone.as_ref().is_some_and(phone::Line::can_reregister);
        self.record_loss(loss);
        if !recover {
            self.stop_media();
            return Err(
                "original Conversation source lost; old exposed controls are not replayed".into(),
            );
        }
        // Withdraw only the old registered phone's calls. An independently
        // owned outgoing Line and its media are neither resumed nor stopped.
        if self.active.is_some_and(|number| {
            self.calls
                .iter()
                .any(|e| e.number == number && e.side == Side::Phone)
        }) {
            self.active = None;
        }
        self.calls.retain(|entry| entry.side != Side::Phone);
        self.audio
            .retain(|(binding, _)| binding.side != Side::Phone);
        if self
            .media
            .binding()
            .is_some_and(|binding| binding.side == Side::Phone)
        {
            self.media.begin_stop(self.settings.shutdown);
        }
        let line = self
            .phone
            .as_ref()
            .ok_or("retired registered phone is missing")?;
        let at = std::time::Instant::now()
            .checked_add(std::time::Duration::from_millis(100))
            .ok_or(gnunet_types::Error::Overflow)?
            .min(line.native_deadline());
        self.phone_recovery = Some(Box::pin(tokio::time::sleep_until(at.into())));
        let mut facts = self.facts.borrow_mut();
        facts.phone_recovery_losses = facts.phone_recovery_losses.saturating_add(1);
        drop(facts);
        self.terminal
            .message(b"Phone service disconnected. Previous incoming calls ended; reconnecting.\n")
    }
    fn recover_phone(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        let Some(alarm) = self.phone_recovery.as_mut() else {
            return Ok(());
        };
        if alarm.as_mut().poll(cx).is_pending()
            || self
                .media
                .binding()
                .is_some_and(|binding| binding.side == Side::Phone)
        {
            return Ok(());
        }
        // A Phone-bound media report remains installed until real child reap
        // and report consumption. No replacement MQ is created before that.
        self.sources.check()?;
        let old = self
            .phone
            .take()
            .ok_or("retired registered phone is missing")?;
        self.phone = Some(old.reregister()?);
        self.phone_recovery = None;
        let mut facts = self.facts.borrow_mut();
        facts.phone_reregistrations = facts.phone_reregistrations.saturating_add(1);
        drop(facts);
        self.terminal
            .message(b"Phone connection restarted; waiting for registration.\n")
    }
    fn advance(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        self.sources.check()?;
        self.recover_phone(cx)?;
        for i in 0..self.calls.len() {
            let Some(intent) = self.calls[i].intent.as_mut() else {
                continue;
            };
            intent
                .bounds
                .check(self.selectors.conversation.clock().as_ref())?;
            if intent.alarm.as_mut().poll(cx).is_ready() {
                return Err(gnunet_types::Error::Deadline.into());
            }
            if intent.operation.is_some() {
                continue;
            }
            let side = self.calls[i].side;
            let call = self.calls[i].info.call.clone();
            let action = self.calls[i]
                .intent
                .as_ref()
                .ok_or("control intent lost")?
                .action;
            let result = match action {
                Action::Accept => self.line_mut(side)?.pick_up(&call),
                Action::Suspend => self.line_mut(side)?.suspend(&call),
                Action::Resume => self.line_mut(side)?.resume(&call),
                Action::Cancel => self.line_mut(side)?.hang_up(&call),
            };
            match result {
                Ok(op) => {
                    self.calls[i]
                        .intent
                        .as_mut()
                        .ok_or("control intent lost")?
                        .operation = Some(op)
                }
                Err(phone::Error::Protocol(gnunet_types::Error::WouldBlock)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        if let Some(number) = self.active
            && let Some(entry) = self.calls.iter().find(|e| e.number == number)
        {
            if Self::eligible(entry) {
                let binding = Self::binding(entry)?;
                if self.media.idle() {
                    let bounds = self.line_mut(binding.side)?.bounds();
                    self.media
                        .start(binding, bounds, &self.config, &self.settings)?;
                } else if self.media.binding() != Some(&binding) && !self.media.stopping() {
                    self.stop_media();
                }
            } else {
                self.stop_media();
            }
        }
        if let Some(binding) = self.media.binding().cloned()
            && !self.media.stopping()
        {
            while self.media.playback_room() {
                let Some((original, audio)) = self.audio.pop_front() else {
                    break;
                };
                if original == binding
                    && let Err((cause, _audio)) = self.media.enqueue(&binding, audio)
                {
                    return Err(cause);
                }
            }
            if let Some(chunk) = self.media.record_chunk(self.settings.native.audio_bytes) {
                let side = binding.side;
                let result = match side {
                    Side::Phone => self.phone.as_mut(),
                    Side::Outgoing => self.outgoing.as_mut(),
                }
                .ok_or("record original Line missing")?
                .audio(&binding.call, chunk);
                match result {
                    Ok(_original) => {
                        let n = chunk.len();
                        self.media.consume_record(n)?;
                    }
                    Err(phone::Error::Protocol(gnunet_types::Error::WouldBlock)) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        // Ended handles can be released only after their original SDK debts
        // actually settle. Display numbers are never recycled on this process.
        let mut i = 0;
        while i < self.calls.len() {
            if self.calls[i].info.phase == phone::Phase::Ended && self.calls[i].intent.is_none() {
                let side = self.calls[i].side;
                let call = self.calls[i].info.call.clone();
                match self.line_mut(side)?.release(&call) {
                    Ok(_) => {
                        self.calls.remove(i);
                        continue;
                    }
                    Err(phone::Error::Protocol(
                        gnunet_types::Error::WouldBlock | gnunet_types::Error::NotReady,
                    )) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            i += 1;
        }
        if self.outgoing.as_ref().is_some_and(|l| l.pending() == 0)
            && !self.calls.iter().any(|e| e.side == Side::Outgoing)
            && let Some(mut line) = self.outgoing.take()
            && let Some(loss) = line.close()
        {
            self.record_loss(loss);
        }
        Ok(())
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, Failure>> {
        for side in [Side::Phone, Side::Outgoing] {
            let loss = match side {
                Side::Phone => self.phone.as_mut(),
                Side::Outgoing => self.outgoing.as_mut(),
            }
            .and_then(|line| line.poll_native_guard(cx));
            if let Some(loss) = loss {
                self.source_lost(side, loss)?;
                return Poll::Ready(Ok(Event::Activity));
            }
        }
        self.advance(cx)?;
        let start = self.turn;
        self.turn = (start + 1) % 5;
        for offset in 0..5 {
            match (start + offset) % 5 {
                0 => {
                    if let Poll::Ready(event) = self.sources.poll(cx) {
                        event?;
                        return Poll::Ready(Ok(Event::Activity));
                    }
                }
                1 | 2 => {
                    let side = if (start + offset) % 5 == 1 {
                        Side::Phone
                    } else {
                        Side::Outgoing
                    };
                    let line = match side {
                        Side::Phone => self.phone.as_mut(),
                        Side::Outgoing => self.outgoing.as_mut(),
                    };
                    if let Some(line) = line
                        && !line.is_closed()
                    {
                        match line.poll_progress(cx) {
                            Poll::Pending => {}
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                            Poll::Ready(Ok(event)) => {
                                self.source_event(side, event)?;
                                return Poll::Ready(Ok(Event::Activity));
                            }
                        }
                    }
                }
                3 => match self.media.poll(cx) {
                    Poll::Pending => {}
                    Poll::Ready(Ok(media::Event::Ended)) => {
                        if let Some(report) = self.media.take_report() {
                            let recovering =
                                self.phone_recovery.is_some() && report.binding.side == Side::Phone;
                            let clean = report.original.is_none()
                                && report.cleanup.is_empty()
                                && !report.cleanup_overflow
                                && report.undrained == 0;
                            self.facts.borrow_mut().media(report);
                            if recovering && !clean {
                                return Poll::Ready(Err("old phone media retirement failed; registration was not replaced".into()));
                            }
                        }
                        return Poll::Ready(Ok(Event::Activity));
                    }
                    Poll::Ready(Ok(media::Event::Activity)) => {
                        return Poll::Ready(Ok(Event::Activity));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                },
                _ => match self.terminal.poll(cx) {
                    Poll::Pending => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(event)) => {
                        return Poll::Ready(Ok(match event {
                            terminal::Event::Command(bytes) => Event::Command(bytes),
                            terminal::Event::Eof => Event::Eof,
                            terminal::Event::Activity => Event::Activity,
                        }));
                    }
                },
            }
        }
        Poll::Pending
    }
    fn pick(&self, number: Option<u64>, action: Action) -> Result<usize, Failure> {
        let eligible = |e: &Entry| match action {
            Action::Accept => e.info.phase == phone::Phase::Ringing,
            Action::Resume => e.info.phase == phone::Phase::Connected && e.info.suspended_local,
            Action::Suspend => {
                self.active == Some(e.number) && e.info.phase == phone::Phase::Connected
            }
            Action::Cancel => e.info.phase != phone::Phase::Ended,
        };
        if let Some(n) = number {
            return self
                .calls
                .iter()
                .position(|e| e.number == n && eligible(e))
                .ok_or_else(|| "selected call is not in a suitable actual phase".into());
        }
        let mut candidates = self.calls.iter().enumerate().filter(|(_, e)| eligible(e));
        let first = candidates.next().ok_or("no suitable call")?.0;
        if candidates.next().is_some() {
            return Err("multiple suitable calls; specify original local #N".into());
        }
        Ok(first)
    }
    fn automatic_suspend(&mut self, index: usize) -> Result<(), Failure> {
        if self.calls[index].intent.is_some() {
            return Err("actual newly connected call already has a control intent".into());
        }
        let clock = self.selectors.conversation.clock();
        let mut bounds = Bounds::new(clock.as_ref(), self.settings.control)?;
        let original = self.line_mut(self.calls[index].side)?.bounds();
        bounds.expires = bounds.expires.min(original.expires);
        bounds.hard = bounds.hard.min(original.hard);
        self.calls[index].intent = Some(Intent {
            action: Action::Suspend,
            bounds,
            operation: None,
            alarm: Box::pin(tokio::time::sleep_until(bounds.hard.into())),
        });
        Ok(())
    }
    fn intent(&mut self, index: usize, action: Action, control: &Control) -> Result<(), Failure> {
        if self.calls[index].intent.is_some() {
            return Err("original call already has an unsettled local control".into());
        }
        let bounds = control.bounded(self.settings.control)?;
        let alarm = Box::pin(tokio::time::sleep_until(bounds.hard.into()));
        self.calls[index].intent = Some(Intent {
            action,
            bounds,
            operation: None,
            alarm,
        });
        if matches!(action, Action::Suspend | Action::Cancel)
            && self.active == Some(self.calls[index].number)
        {
            self.active = None;
            self.stop_media();
        }
        Ok(())
    }
    fn switch(&mut self, index: usize, action: Action, control: &Control) -> Result<(), Failure> {
        let target = self.calls[index].number;
        if let Some(old) = self.active
            && old != target
        {
            let previous = self
                .calls
                .iter()
                .position(|e| e.number == old)
                .ok_or("active call lost its original handle")?;
            if self.calls[previous].intent.is_some() {
                return Err("active original control has not settled".into());
            }
            self.intent(previous, Action::Suspend, control)?;
        }
        self.stop_media();
        self.intent(index, action, control)
    }
    fn address(&mut self) -> Result<(), Failure> {
        self.sources.check()?;
        let peer = self.sources.peer()?;
        let record = gnunet_wire::official::conversation::PhoneRecord::v1(peer, self.port);
        let mut binary = [0u8; 104];
        record.encode(&mut binary)?;
        let mut stage = [0u8; 2048];
        let mut names = [0u8; 1024];
        let mut work = [0u8; 2048];
        let mut result = [0u8; 512];
        let mut idna_work = gnunet_idna::Workspace::new();
        let idna = gnunet_idna::Backend::new(
            &mut idna_work,
            gnunet_idna::Limits::GNUNET,
            gnunet_idna::NativeProfile::Libunistring1_5Unicode18_0,
        );
        let mut codec = gnunet_gnsrecord_text::Codec::new(
            &idna,
            gnunet_gnsrecord_text::Workspace::new(&mut stage, &mut names, &mut work),
            gnunet_gnsrecord_text::Profile::NATIVE_255,
            Default::default(),
        )?;
        let n = codec.value_to_string(gnunet_gnsrecord::RecordType::PHONE, &binary, &mut result)?;
        let mut text = self.terminal.text();
        text.push(b"PHONE ")?;
        text.push(&result[..n])?;
        text.push(b"\nPublish this PHONE value under your chosen NAMESTORE label; /address has not published anything. The peer above is the verified current PILS network peer, not the caller ego.\n")?;
        self.terminal.enqueue(text)
    }
    pub fn handle(&mut self, event: Event, control: &Control) -> Result<Next, Failure> {
        let bytes = match event {
            Event::Activity => return Ok(Next::Continue),
            Event::Eof => return Ok(Next::Quit),
            Event::Command(bytes) => bytes,
        };
        let result = (|| -> Result<Next, Failure> {
            match options::command(&bytes)? {
                Command::Quit => Ok(Next::Quit),
                Command::Help(topic) => {
                    if let Some(topic) = topic {
                        self.notice(b"Help topic: ", &topic)?;
                    }
                    self.help()?;
                    Ok(Next::Continue)
                }
                Command::Address => {
                    self.address()?;
                    Ok(Next::Continue)
                }
                Command::Status => {
                    if self.resolving {
                        self.terminal.message(b"Original full-name PHONE query is pending; /cancel cancels its callback locally.\n")?;
                    }
                    if self.calls.is_empty() {
                        self.terminal.message(b"No current calls.\n")?;
                    }
                    for i in 0..self.calls.len() {
                        self.status_one(i)?;
                    }
                    Ok(Next::Continue)
                }
                Command::Call(name) => {
                    if self.resolving || self.outgoing.is_some() {
                        return Err(
                            "an original outgoing call/query already exists; cancel it first"
                                .into(),
                        );
                    }
                    if self.calls.len() >= self.settings.calls {
                        return Err("call table is full".into());
                    }
                    if let Some(active) = self.active {
                        let previous = self.pick(Some(active), Action::Suspend)?;
                        self.intent(previous, Action::Suspend, control)?;
                    }
                    Ok(Next::Call(name))
                }
                Command::Accept(n) => {
                    let i = self.pick(n, Action::Accept)?;
                    self.switch(i, Action::Accept, control)?;
                    Ok(Next::Continue)
                }
                Command::Suspend => {
                    let i = self.pick(self.active, Action::Suspend)?;
                    self.intent(i, Action::Suspend, control)?;
                    Ok(Next::Continue)
                }
                Command::Resume(n) => {
                    let i = self.pick(n, Action::Resume)?;
                    self.switch(i, Action::Resume, control)?;
                    Ok(Next::Continue)
                }
                Command::Cancel(n) => {
                    if self.resolving && n.is_none() {
                        self.cancel_resolution = true;
                        return Ok(Next::Continue);
                    }
                    let i = self.pick(n.or(self.active), Action::Cancel)?;
                    let side = self.calls[i].side;
                    if self.calls[i].info.cid.is_none() {
                        // There is no guessed outgoing CID0: retire the actual MQ.
                        if let Some(mut line) = match side {
                            Side::Phone => self.phone.take(),
                            Side::Outgoing => self.outgoing.take(),
                        } && let Some(loss) = line.close()
                        {
                            self.record_loss(loss);
                        }
                        let number = self.calls[i].number;
                        self.calls.remove(i);
                        if self.active == Some(number) {
                            self.active = None;
                            self.stop_media();
                        }
                    } else {
                        self.intent(i, Action::Cancel, control)?;
                    }
                    Ok(Next::Continue)
                }
            }
        })();
        match result {
            Ok(next) => Ok(next),
            Err(error) => {
                self.notice(b"Command refused: ", error.to_string().as_bytes())?;
                Ok(Next::Continue)
            }
        }
    }
    pub fn begin_call(
        &mut self,
        record: gnunet_wire::official::conversation::PhoneRecord,
        bounds: Bounds,
    ) -> Result<(), Failure> {
        self.sources.check()?;
        if record.version != 1 || record.reserved != 0 {
            return Err("unsupported PHONE record version/reserved profile".into());
        }
        let line = phone::Line::call(
            self.selectors.conversation.duplicate()?,
            &record.peer,
            &record.port,
            self.sources.secret()?,
            self.settings.native,
            bounds,
        )?;
        let call = line
            .outgoing()
            .ok_or("outgoing original Call was not created")?;
        let info = line.info(&call)?;
        self.outgoing = Some(line);
        let number = self.update(Side::Outgoing, info)?;
        self.announce(number, b"Original call admitted; remote pickup is pending")
    }
    pub fn stop_media(&mut self) {
        self.audio.clear();
        self.media.begin_stop(self.settings.shutdown);
    }
    pub fn close_sources(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.phone_recovery = None;
        self.sources.close();
        for mut line in [self.phone.take(), self.outgoing.take()]
            .into_iter()
            .flatten()
        {
            if let Some(loss) = line.close() {
                self.record_loss(loss);
            }
        }
        self.audio.clear();
    }
    pub fn cleanup_done(&self) -> bool {
        self.media.pending_children() == 0 && (self.output_failed || self.terminal.drained())
    }
    pub fn poll_cleanup(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Failure>> {
        let mut activity = false;
        match self.media.poll(cx) {
            Poll::Ready(Ok(_)) => {
                if let Some(report) = self.media.take_report() {
                    self.facts.borrow_mut().media(report);
                }
                activity = true;
            }
            Poll::Ready(Err(error)) => {
                if !self.cleanup_media_error {
                    self.facts.borrow_mut().cleanup(error);
                    self.cleanup_media_error = true;
                }
            }
            Poll::Pending => {}
        }
        if !self.output_failed {
            match self.terminal.poll_write(cx) {
                Poll::Ready(Ok(_)) => activity = true,
                Poll::Ready(Err(error)) => {
                    self.output_failed = true;
                    self.facts.borrow_mut().cleanup(error);
                    self.terminal.abort_output();
                    activity = true;
                }
                Poll::Pending => {}
            }
        }
        // An error from one native cleanup source never skips the other
        // original owner. The outer fixed native grace remains the final fence.
        if activity {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    pub fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.close_sources();
        self.stop_media();
        if let Some(report) = self.media.take_report() {
            self.facts.borrow_mut().media(report);
        }
        let report = self.terminal.close();
        let mut facts = self.facts.borrow_mut();
        facts.cleanup_failed |= !report.output_drained
            || report.input_restore.is_some()
            || report.output_restore.is_some();
        facts.terminal = Some(report);
    }
}
impl Drop for State<'_, '_> {
    fn drop(&mut self) {
        self.finish();
    }
}
