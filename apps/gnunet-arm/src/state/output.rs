//! Catalog rendering and permanent output-failure ownership for ARM callbacks.
use super::{Kind, State};
use gnunet_arm_core::wire::{RequestStatus, ServiceInfo};
use gnunet_program_host::format::Argument as Value;
use std::io;

#[derive(Debug)]
pub(super) enum OutputState {
    Active,
    Failed(Option<io::Error>),
}

/// Original request-status string; it does not infer processing acknowledgement.
pub fn req_string(status: u32) -> &'static [u8] {
    match status {
        0 => b"Message was sent successfully",
        2 => b"We disconnected from ARM before we could send a request",
        _ => b"Unknown request status",
    }
}
/// Original ARM result string, including punctuation for an unknown future code.
pub fn ret_string(result: u32) -> &'static [u8] {
    match result {
        0 => b"is stopped",
        1 => b"is stopping",
        2 => b"is starting",
        3 => b"is starting already",
        4 => b"is stopping already",
        5 => b"is started already",
        6 => b"is stopped already",
        7 => b"service is not known to ARM",
        8 => b"service failed to start",
        9 => b"service cannot be manipulated because ARM is shutting down",
        _ => b"Unknown result code.",
    }
}
/// Rounded native-byte time text from the shared GNUnet string formatter.
pub fn relative_time(value: u64) -> Vec<u8> {
    gnunet_program_host::diagnostics::relative_time(value, true)
}

impl State {
    /// Consume the original catalog/format failure without clearing shutdown.
    pub fn take_output_error(&mut self) -> Option<io::Error> {
        match &mut self.output {
            OutputState::Active => None,
            OutputState::Failed(error) => error.take(),
        }
    }

    /// Whether output authority failed, even after its original error was taken.
    #[must_use]
    pub fn output_failed(&self) -> bool {
        matches!(self.output, OutputState::Failed(_))
    }

    fn failed(&mut self, error: io::Error) {
        if matches!(self.output, OutputState::Active) {
            self.output = OutputState::Failed(Some(error));
        }
        self.done = true;
        self.ret = 1;
    }

    fn out(&mut self, message: io::Result<Vec<u8>>) {
        if matches!(self.output, OutputState::Active) {
            match message {
                Ok(message) => self.stdout.extend_from_slice(&message),
                Err(error) => self.failed(error),
            }
        }
    }

    pub(super) fn err(&mut self, message: io::Result<Vec<u8>>) {
        if matches!(self.output, OutputState::Active) {
            match message {
                Ok(message) => self.stderr.extend_from_slice(&message),
                Err(error) => self.failed(error),
            }
        }
    }

    pub(super) fn result_failure(&mut self, kind: Kind, status: RequestStatus, value: u32) {
        let sent = status == RequestStatus::SentOk;

        let reason = match self.locale.text(if sent {
            ret_string(value)
        } else {
            req_string(2)
        }) {
            Ok(reason) => reason,
            Err(error) => {
                self.failed(error);
                return;
            }
        };
        match kind {
            Kind::Start => self.out(self.locale.format(
                b"Failed to start the ARM service: %s\n",
                &[Value::Bytes(&reason)],
            )),
            Kind::End => self.out(self.locale.format(
                if sent {
                    b"Failed to stop the ARM service: %s\n"
                } else {
                    b"Failed to send a stop request to the ARM service: %s\n"
                },
                &[Value::Bytes(&reason)],
            )),
            Kind::Init | Kind::Term => {
                let name = if kind == Kind::Init {
                    self.options.init.as_deref()
                } else {
                    self.options.term.as_deref()
                }
                .unwrap_or_default();
                if kind == Kind::Term && !sent {
                    self.out(self.kill_request(name, &reason));
                    self.done = true;
                    return;
                }
                let template: &[u8] = match (kind, sent) {
                    (Kind::Init, true) => b"Failed to start the `%s' service: %s\n",
                    (Kind::Init, false) => {
                        b"Failed to send a request to start the `%s' service: %s\n"
                    }
                    (Kind::Term, true) => b"Failed to kill the `%s' service: %s\n",
                    _ => b"Failed to send a request to kill the `%s' service: %s\n",
                };
                self.out(
                    self.locale
                        .format(template, &[Value::Bytes(name), Value::Bytes(&reason)]),
                );
            }
            Kind::List => self.list_disconnected(),
        }
    }

    fn kill_request(&self, name: &[u8], reason: &[u8]) -> io::Result<Vec<u8>> {
        // The official msgid escapes its second-pass reason as %%s. Bind name
        // and reason to typed positions for one render; no native argument is
        // ever reused as a format string.
        let translated = self
            .locale
            .text(b"Failed to send a request to kill the `%s' service: %%s\n")?;
        let mut corrected = Vec::new();
        let extra = translated
            .iter()
            .filter(|byte| **byte == b'%')
            .count()
            .checked_mul(2)
            .ok_or(io::ErrorKind::OutOfMemory)?;
        let capacity = translated
            .len()
            .checked_add(extra)
            .ok_or(io::ErrorKind::OutOfMemory)?;
        corrected
            .try_reserve_exact(capacity)
            .map_err(io::Error::other)?;
        let mut at = 0;
        let mut next = b'1';
        while at < translated.len() {
            if translated[at..].starts_with(b"%%s") {
                corrected.extend_from_slice(b"%2$s");
                at += 3;
            } else if translated[at..].starts_with(b"%%") {
                corrected.extend_from_slice(b"%%");
                at += 2;
            } else if translated[at] == b'%' {
                let mut end = at + 1;
                while translated.get(end).is_some_and(u8::is_ascii_digit) {
                    end += 1;
                }
                if end > at + 1 && translated.get(end) == Some(&b'$') {
                    corrected.push(b'%');
                } else {
                    if next > b'2' {
                        return Err(io::ErrorKind::InvalidInput.into());
                    }
                    corrected.extend_from_slice(&[b'%', next, b'$']);
                    next += 1;
                }
                at += 1;
            } else {
                corrected.push(translated[at]);
                at += 1;
            }
        }
        gnunet_program_host::format::render(&corrected, &[Value::Bytes(name), Value::Bytes(reason)])
    }

    /// Match the failed request plus NULL list callback path.
    pub fn list_disconnected(&mut self) {
        if matches!(self.output, OutputState::Failed(_)) {
            return;
        }
        self.waiting = None;
        match self.locale.text(req_string(2)) {
            Ok(reason) => self.out(self.locale.format(
                b"Failed to request a list of services: %s\n",
                &[Value::Bytes(&reason)],
            )),
            Err(error) => self.failed(error),
        }
        if self.output_failed() {
            return;
        }
        self.err(
            self.locale
                .text(b"Error communicating with ARM. ARM not running?\n"),
        );
        if self.output_failed() {
            return;
        }
        self.ret = 3;
        self.done = true;
    }

    /// Both list passes are intentional. Stopping/unknown rows print twice.
    pub fn list(&mut self, rows: &[ServiceInfo<'_>], now: u64) {
        if matches!(self.output, OutputState::Failed(_)) {
            return;
        }
        self.waiting = None;
        let mut counts = [0usize; 5];
        for row in rows {
            if let Some(n) = counts.get_mut(row.status.0 as usize) {
                *n += 1;
            }
            if row.status.0 >= 4 {
                self.row(row, now);
            }
        }
        if !self.quiet {
            self.out(self.locale.text(if self.options.all {
                b"All services:\n"
            } else {
                b"Services (excluding stopped services):\n"
            }));
            if self.output_failed() {
                return;
            }
            if counts.iter().any(|n| *n != 0) {
                self.stdout.push(b'(');
                let mut first = true;
                for (index, name) in [
                    (1, "started"),
                    (2, "failed"),
                    (4, "stopping"),
                    (0, "stopped"),
                    (3, "finished"),
                ] {
                    if counts[index] != 0 {
                        if !first {
                            self.stdout.extend_from_slice(b" / ");
                        }
                        self.stdout
                            .extend_from_slice(format!("{name}: {}", counts[index]).as_bytes());
                        first = false;
                    }
                }
                self.stdout.extend_from_slice(b")\n");
            } else {
                self.out(self.locale.text(b"(No services configured.)\n"));
            }
        }
        if matches!(self.output, OutputState::Failed(_)) {
            return;
        }
        for row in rows {
            if row.status.0 != 0 || self.options.all {
                self.row(row, now);
            }
        }
    }

    fn row(&mut self, row: &ServiceInfo<'_>, now: u64) {
        self.stdout.extend_from_slice(row.name);
        self.stdout.extend_from_slice(b" (binary='");
        self.stdout.extend_from_slice(row.binary);
        self.stdout.extend_from_slice(b"', status=");
        let name: &[u8] = match row.status.0 {
            0 => b"stopped",
            1 => b"started",
            2 => b"failed",
            3 => b"finished",
            4 => b"stopping",
            _ => b"unknown",
        };
        self.stdout.extend_from_slice(name);
        if row.status.0 == 2 {
            let remaining = if row.restart_at == u64::MAX {
                u64::MAX
            } else {
                row.restart_at.saturating_sub(now)
            };
            self.stdout.extend_from_slice(
                format!(
                    ", exit_status={}, restart_delay='",
                    row.public_exit_status()
                )
                .as_bytes(),
            );
            self.stdout.extend_from_slice(&relative_time(remaining));
            self.stdout.push(b'\'');
        }
        self.stdout.extend_from_slice(b")\n");
    }

    /// MONITORING_STARTED is silent; quiet is force-cleared by the monitor phase.
    pub fn monitor(&mut self, service: &[u8], status: u32) {
        if matches!(self.output, OutputState::Failed(_)) {
            return;
        }
        if status == 0 || self.quiet {
            return;
        }
        let message = match status {
            1 => self
                .locale
                .format(b"Stopped %s.\n", &[Value::Bytes(service)]),
            2 => self
                .locale
                .format(b"Starting %s...\n", &[Value::Bytes(service)]),
            3 => self
                .locale
                .format(b"Stopping %s...\n", &[Value::Bytes(service)]),
            _ => self.locale.format(
                b"Unknown status %u for service %s.\n",
                &[Value::Unsigned(u64::from(status)), Value::Bytes(service)],
            ),
        };
        self.err(message);
    }
}
