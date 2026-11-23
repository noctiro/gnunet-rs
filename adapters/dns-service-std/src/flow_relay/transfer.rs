//! Original byte cursors and independent TCP half-close propagation.
use super::{Chunk, TcpRelay};
use gnunet_native::dns_proxy::TcpRead;
use std::{
    io,
    task::{Context, Poll},
};
use tokio::{io::ReadBuf, time::Instant};

impl TcpRelay {
    pub(super) fn step(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        if self.closing {
            let _open = self.flow.poll_open(cx);
            let _read = self.flow.poll_read(cx);
            if let Poll::Ready(Some(Ok(()))) = self.flow.poll_write(cx) {
                self.report.late_application_write_accepted = true;
                self.report.upstream_to_application = self
                    .report
                    .upstream_to_application
                    .saturating_add(self.to_flow_len as u64);
            }
            if !self.flow_retired
                && let Poll::Ready(retirement) = self.flow.poll_retirement(cx)
            {
                self.report.retirement = Some(retirement);
                self.flow_retired = true;
            }
            if !self.upstream_retired
                && let Poll::Ready(retirement) = self.upstream.poll_retirement(cx)
            {
                self.report.upstream_retirement = retirement;
                self.upstream_retired = true;
            }
            if self.flow_retired && self.upstream_retired {
                self.stopped = true;
                return Ok(true);
            }
            return Ok(false);
        }
        if self.opening {
            if !self.flow_opened
                && let Poll::Ready(Some(result)) = self.flow.poll_open(cx)
            {
                result?;
                self.flow_opened = true;
            }
            let upstream_ready = match self.upstream.poll_ready(cx) {
                Poll::Ready(result) => {
                    result?;
                    true
                }
                Poll::Pending => false,
            };
            if Instant::now() >= self.open_until {
                return Err(timeout("native TCP flow opening expired"));
            }
            if self.flow_opened && upstream_ready {
                self.opening = false;
                self.activity();
                return Ok(true);
            }
            return Ok(false);
        }
        // Completion polling always precedes new work and deadline refusal.
        if self.writing_flow
            && let Poll::Ready(Some(result)) = self.flow.poll_write(cx)
        {
            self.writing_flow = false;
            let expired = self
                .write_until
                .take()
                .is_some_and(|until| Instant::now() >= until);
            result?;
            self.report.upstream_to_application = self
                .report
                .upstream_to_application
                .saturating_add(self.to_flow_len as u64);
            self.to_flow.fill(0);
            self.to_flow_len = 0;
            if expired {
                self.report.late_application_write_accepted = true;
                return Err(timeout("native TCP write completed after deadline"));
            }
            self.activity();
            return Ok(true);
        }
        let now = Instant::now();
        if now >= self.idle_until
            || self.write_until.is_some_and(|until| now >= until)
            || self.shutdown_until.is_some_and(|until| now >= until)
            || self
                .from_flow
                .as_ref()
                .is_some_and(|chunk| now >= chunk.until)
        {
            return Err(timeout("TCP relay original operation expired"));
        }
        if self.report.application_eof
            && self.report.upstream_eof
            && self.upstream_half_closed
            && !self.writing_flow
            && self.from_flow.is_none()
        {
            self.close();
            return Ok(true);
        }
        for from_application in [self.turn, !self.turn] {
            let progressed = if from_application {
                self.application_to_upstream(cx)?
            } else {
                self.upstream_to_application(cx)?
            };
            if progressed {
                self.turn = !from_application;
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn application_to_upstream(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        if let Some(chunk) = &mut self.from_flow {
            let stream = &mut self.upstream;
            match stream.poll_write(cx, &chunk.bytes[chunk.written..]) {
                Poll::Pending => return Ok(false),
                Poll::Ready(Err(error)) => return Err(error),
                Poll::Ready(Ok(0)) => return Err(io::ErrorKind::WriteZero.into()),
                Poll::Ready(Ok(bytes)) => {
                    chunk.written = chunk
                        .written
                        .checked_add(bytes)
                        .ok_or_else(|| io::Error::other("TCP write cursor overflow"))?;
                    if chunk.written > chunk.bytes.len() {
                        return Err(io::Error::other("TCP write exceeded original chunk"));
                    }
                    self.report.application_to_upstream = self
                        .report
                        .application_to_upstream
                        .saturating_add(bytes as u64);
                    if chunk.written == chunk.bytes.len() {
                        self.from_flow = None;
                    }
                    self.activity();
                    return Ok(true);
                }
            }
        }
        if self.report.application_eof {
            if self.upstream_half_closed {
                return Ok(false);
            }
            self.shutdown_until
                .get_or_insert_with(|| Instant::now() + self.limits.write_timeout);
            let stream = &mut self.upstream;
            return match stream.poll_shutdown(cx) {
                Poll::Pending => Ok(false),
                Poll::Ready(result) => {
                    result?;
                    self.upstream_half_closed = true;
                    self.shutdown_until = None;
                    self.activity();
                    Ok(true)
                }
            };
        }
        if !self.reading_flow {
            self.flow.begin_read(self.limits.buffer_bytes)?;
            self.reading_flow = true;
        }
        match self.flow.poll_read(cx) {
            Poll::Ready(Some(result)) => {
                self.reading_flow = false;
                match result? {
                    TcpRead::End => {
                        self.report.application_eof = true;
                        self.flow.close_read();
                    }
                    TcpRead::Data(bytes) => {
                        self.from_flow = Some(Chunk {
                            bytes,
                            written: 0,
                            until: Instant::now() + self.limits.write_timeout,
                        });
                    }
                }
                self.activity();
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    fn upstream_to_application(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        if self.writing_flow || self.report.upstream_eof {
            return Ok(false);
        }
        let stream = &mut self.upstream;
        let mut buffer = ReadBuf::new(&mut self.to_flow);
        match stream.poll_read(cx, &mut buffer) {
            Poll::Pending => Ok(false),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Ready(Ok(())) => {
                self.to_flow_len = buffer.filled().len();
                if self.to_flow_len == 0 {
                    self.report.upstream_eof = true;
                    self.flow.close_write();
                } else {
                    self.flow.begin_write(&self.to_flow[..self.to_flow_len])?;
                    self.writing_flow = true;
                    self.write_until = Some(Instant::now() + self.limits.write_timeout);
                }
                self.activity();
                Ok(true)
            }
        }
    }
}
fn timeout(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}
