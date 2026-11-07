use crate::Error;
use gnunet_types::Error as Fault;
use std::{
    sync::{Arc, Mutex},
    task::{Context, Waker},
};

#[derive(Default)]
struct State {
    frames: usize,
    bytes: usize,
    waker: Option<Waker>,
}
pub(crate) struct Quota {
    state: Mutex<State>,
    frames: usize,
    bytes: usize,
}
impl Quota {
    pub fn new(frames: usize, bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            frames,
            bytes,
        })
    }
    pub fn snapshot(&self) -> Option<(usize, usize)> {
        self.state.lock().ok().map(|s| (s.frames, s.bytes))
    }
    pub fn ready(&self, cx: &mut Context<'_>, bytes: usize) -> Result<bool, Error> {
        if bytes > self.bytes {
            return Err(Fault::Capacity.into());
        }
        // RawWaker clone/drop/wake may run caller code; none runs under quota lock.
        let candidate = cx.waker().clone();
        let mut old = None;
        let ready = {
            let mut s = self.state.lock().map_err(|_| Fault::Conflict)?;
            if s.frames >= self.frames
                || s.bytes.checked_add(bytes).ok_or(Fault::Overflow)? > self.bytes
            {
                if s.waker.as_ref().is_none_or(|w| !w.will_wake(&candidate)) {
                    old = s.waker.replace(candidate);
                }
                false
            } else {
                old = s.waker.take();
                true
            }
        };
        drop(old);
        Ok(ready)
    }
    pub fn reserve(self: &Arc<Self>, bytes: usize) -> Result<Lease, Error> {
        let mut s = self.state.lock().map_err(|_| Fault::Conflict)?;
        let total = s.bytes.checked_add(bytes).ok_or(Fault::Overflow)?;
        if s.frames >= self.frames || total > self.bytes {
            return Err(Fault::WouldBlock.into());
        }
        s.frames += 1;
        s.bytes = total;
        Ok(Lease {
            quota: self.clone(),
            bytes,
        })
    }
}
pub(crate) struct Lease {
    quota: Arc<Quota>,
    bytes: usize,
}
impl Drop for Lease {
    fn drop(&mut self) {
        let wake = if let Ok(mut s) = self.quota.state.lock() {
            s.frames -= 1;
            s.bytes -= self.bytes;
            s.waker.take()
        } else {
            None
        };
        if let Some(wake) = wake {
            wake.wake();
        }
    }
}
