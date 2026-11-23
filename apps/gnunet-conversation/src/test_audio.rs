//! Five seconds of original recording, followed by bounded local playback.
#[cfg(unix)]
#[path = "test_audio/unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "test_audio/windows.rs"]
mod platform;

use crate::Failure;
use gnunet_conversation_audio_host::{Limits, ogg::Page};
use gnunet_service_startup::StopSignals;
use gnunet_types::Error as Fault;
use gnunet_wire::official::{Frame, HEADER_LEN, message_type as mt};
use std::{
    fmt,
    future::poll_fn,
    io::{self, Write},
    path::Path,
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::{Instant, sleep_until, timeout_at},
};
use zeroize::Zeroizing;

const RECORD_TIME: Duration = Duration::from_secs(5);
const PLAYBACK_TIME: Duration = Duration::from_secs(10);
const RETIRE_TIMEOUT: Duration = Duration::from_secs(2);
const RECORD_BYTES: usize = 256 * 1024;
const BOOTSTRAP: &[&str] = &[
    "GNUNET_OS_CONTROL_PIPE",
    "LISTEN_PID",
    "LISTEN_FDS",
    "LISTEN_FDNAMES",
    "GNUNET_RS_ACTIVATION_HANDLE",
    "GNUNET_RS_DETACH_PIPE",
];

struct Recording {
    bytes: Zeroizing<Vec<u8>>,
    used: usize,
    complete: usize,
    has_samples: bool,
}

impl Recording {
    fn new() -> Result<Self, Failure> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(RECORD_BYTES)?;
        if bytes.capacity() > RECORD_BYTES {
            return Err(Fault::Capacity.into());
        }
        bytes.resize(RECORD_BYTES, 0);
        Ok(Self {
            bytes: Zeroizing::new(bytes),
            used: 0,
            complete: 0,
            has_samples: false,
        })
    }

    fn parse_complete(&mut self) -> Result<(), Failure> {
        let limits = Limits::default();
        while self.used - self.complete >= HEADER_LEN {
            let available = &self.bytes[self.complete..self.used];
            let (frame, remaining) = match Frame::decode_prefix(available) {
                Ok(decoded) => decoded,
                Err(Fault::Truncated) => break,
                Err(error) => return Err(error.into()),
            };
            if frame.header().message_type() != mt::CONVERSATION_AUDIO {
                return Err(Fault::Malformed.into());
            }
            // The installed recorder sends one checksum-checked page per frame.
            let page = Page::decode(frame.payload(), limits)?;
            let granule = page.granule()?;
            self.has_samples |= granule > 0 && granule != u64::MAX;
            self.complete = self.used - remaining.len();
        }
        Ok(())
    }

    async fn capture(
        &mut self,
        mut pipe: impl AsyncRead + Unpin,
        until: Instant,
        signals: &mut StopSignals,
    ) -> Result<(), Failure> {
        let alarm = sleep_until(until);
        tokio::pin!(alarm);
        loop {
            if self.used == RECORD_BYTES {
                return Err(Fault::Capacity.into());
            }
            let count = tokio::select! {
                biased;
                stopped = poll_fn(|cx| signals.poll_stop(cx)) => {
                    stopped?;
                    return Err(Fault::Cancelled.into());
                },
                _ = &mut alarm => break,
                count = pipe.read(&mut self.bytes[self.used..]) => count?,
            };
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "recorder ended during capture",
                )
                .into());
            }
            self.used += count;
            self.parse_complete()?;
        }
        if !self.has_samples {
            return Err("the recorder provided no audio samples".into());
        }
        Ok(())
    }

    fn playable(&self) -> &[u8] {
        &self.bytes[..self.complete]
    }
}

#[derive(Debug)]
struct CleanupFailure {
    original: Failure,
    cleanup: Failure,
}
impl fmt::Display for CleanupFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}. Audio helper cleanup failed ({})",
            self.original, self.cleanup
        )
    }
}
impl std::error::Error for CleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original.as_ref())
    }
}

fn retain(original: Result<(), Failure>, cleanup: Result<(), Failure>) -> Result<(), Failure> {
    match (original, cleanup) {
        (Err(original), Err(cleanup)) => Err(Box::new(CleanupFailure { original, cleanup })),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

async fn retire(
    child: &mut platform::Child,
    mut input: Option<platform::Input>,
) -> Result<(), Failure> {
    let until = Instant::now() + RETIRE_TIMEOUT;
    let cancelled = platform::cancel(&mut input).map_err(Into::into);
    let terminated = child.terminate().map_err(Into::into);
    let (settled, reaped) = tokio::join!(
        async {
            timeout_at(until, platform::settle(input))
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "audio write completion was not observed",
                    )
                })??;
            Ok(())
        },
        async {
            timeout_at(until, child.wait()).await.map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "audio helper exit was not observed",
                )
            })??;
            Ok(())
        }
    );
    retain(retain(cancelled, settled), retain(terminated, reaped))
}

async fn check_stop(signals: &mut StopSignals) -> Result<(), Failure> {
    poll_fn(|cx| {
        Poll::Ready(match signals.poll_stop(cx) {
            Poll::Pending => Ok(()),
            Poll::Ready(Ok(())) => Err(Fault::Cancelled.into()),
            Poll::Ready(Err(error)) => Err(error.into()),
        })
    })
    .await
}

pub(super) async fn run(
    record: &Path,
    play: &Path,
    signals: &mut StopSignals,
) -> Result<(), Failure> {
    let mut recording = Recording::new()?;
    writeln!(
        io::stderr().lock(),
        "Recording for five seconds. Playback will follow."
    )?;
    check_stop(signals).await?;
    let until = Instant::now() + RECORD_TIME;
    let (mut recorder, output) = platform::record(record)?;
    let capture = match output {
        Some(output) => recording.capture(output, until, signals).await,
        None => Err("the recording helper's output pipe is missing".into()),
    };
    retain(capture, retire(&mut recorder, None).await)?;

    writeln!(io::stderr().lock(), "Playing the recording back.")?;
    check_stop(signals).await?;
    let until = Instant::now() + PLAYBACK_TIME;
    let (mut player, mut input) = platform::playback(play)?;
    let playback = tokio::select! {
        biased;
        stopped = poll_fn(|cx| signals.poll_stop(cx)) => {
            stopped.map_err(Into::into).and(Err(Fault::Cancelled.into()))
        },
        _ = sleep_until(until) => Err(Fault::Deadline.into()),
        result = async {
            let writer = input.as_mut().ok_or("the playback helper's input pipe is missing")?;
            platform::write(writer, recording.playable()).await?;
            input = None; // EOF lets the original helper finish its actual audio drain.
            let status = player.wait().await?;
            if status.success() {
                Ok(())
            } else {
                Err(io::Error::other(format!("playback helper exited with {status}")).into())
            }
        } => result,
    };
    if playback.is_err() {
        return retain(playback, retire(&mut player, input).await);
    }
    writeln!(io::stderr().lock(), "Playback finished.")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnunet_conversation_audio_host::{framing, ogg::Mux};

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Check frame boundaries across capture cutoff"
    )]
    fn recording_replays_only_whole_frames_with_real_granules() -> Result<(), Failure> {
        let limits = Limits::default();
        let mut mux = Mux::new(1, limits)?;
        let mut frames = Vec::new();
        framing::write_frame(&mut frames, mux.packet(b"head", 2, 0)?, limits)?;
        let head = frames.len();
        framing::write_frame(&mut frames, mux.packet(b"audio", 0, 1920)?, limits)?;
        let audio = frames.len();
        framing::write_frame(&mut frames, mux.packet(b"audio too", 0, 3840)?, limits)?;

        let mut recording = Recording::new()?;
        recording.bytes[..frames.len()].copy_from_slice(&frames);
        recording.used = head;
        recording.parse_complete()?;
        assert!(!recording.has_samples);
        recording.used = audio + HEADER_LEN + 1;
        recording.parse_complete()?;
        assert!(recording.has_samples);
        assert_eq!(recording.playable(), &frames[..audio]);
        recording.used = frames.len();
        recording.parse_complete()?;
        assert_eq!(recording.playable(), &frames[..]);
        Ok(())
    }
}
