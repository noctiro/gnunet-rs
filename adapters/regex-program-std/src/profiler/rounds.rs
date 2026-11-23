//! Schedule exactly three locally completed publication rounds.
use super::policy;
use crate::Failure;
use gnunet_regex_server_host::{dht::Provider, driver::Driver};
use std::{future::Future, num::NonZeroU32, pin::Pin, task::Context, time::Duration};
use tokio::time::{Instant, Sleep};

const ROUNDS: u64 = 3;

enum Phase {
    Waiting,
    Publishing(Pin<Box<Sleep>>),
}

pub(crate) struct Rounds {
    maximum_delay: NonZeroU32,
    round_timeout: Duration,
    next: Pin<Box<Sleep>>,
    phase: Phase,
    issued: u64,
}

pub(crate) enum RoundProgress {
    Idle,
    Started,
    Completed,
    Done,
}

impl Rounds {
    pub(crate) fn new(maximum_delay: NonZeroU32, round_timeout: Duration) -> Self {
        Self {
            maximum_delay,
            round_timeout,
            next: Box::pin(tokio::time::sleep_until(Instant::now())),
            phase: Phase::Waiting,
            issued: 0,
        }
    }

    pub(crate) fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        match &mut self.phase {
            Phase::Waiting => false,
            Phase::Publishing(hard) => {
                Instant::now() >= hard.deadline() || hard.as_mut().poll(cx).is_ready()
            }
        }
    }

    pub(crate) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        driver: &mut Driver<'_, impl Provider>,
    ) -> Result<RoundProgress, Failure> {
        let completed = driver.server().local_rounds()?;
        match &mut self.phase {
            Phase::Waiting => {
                if self.next.as_mut().poll(cx).is_pending() {
                    return Ok(RoundProgress::Idle);
                }
                if completed == ROUNDS {
                    return Ok(RoundProgress::Done);
                }
                let delay = policy::random_delay(self.maximum_delay)?;
                self.next.as_mut().reset(Instant::now() + delay);
                driver.announce_local()?;
                self.issued += 1;
                self.phase = Phase::Publishing(Box::pin(tokio::time::sleep(self.round_timeout)));
                Ok(RoundProgress::Started)
            }
            Phase::Publishing(_) => {
                if completed == self.issued {
                    self.phase = Phase::Waiting;
                    return Ok(RoundProgress::Completed);
                }
                Ok(RoundProgress::Idle)
            }
        }
    }
}
