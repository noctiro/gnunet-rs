//! Bounded real worker lifetime, reentry fencing and PID-scoped bookkeeping.
use crate::{Completion, Error, Family, Limits};
use gnunet_types::Error as Fault;
use std::{
    cell::Cell,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};
const MAX_CALLS: u32 = 16;
const STACK_BYTES: usize = 512 * 1024;
// No runtime, native source, mutex or private material is cached here. A child
// process atomically starts its own count rather than inheriting ghost workers.
static CALLS: AtomicU64 = AtomicU64::new(0);
thread_local! {static ENTERED:Cell<(u32,bool)>=const{Cell::new((0,false))};}
struct Count {
    pid: u32,
}
impl Count {
    fn enter(pid: u32) -> Result<Self, Error> {
        let mut old = CALLS.load(Ordering::Acquire);
        loop {
            let previous = (old >> 32) as u32;
            let active = old as u32;
            if previous == pid && active >= MAX_CALLS {
                return Err(Error::Busy);
            }
            let next =
                (u64::from(pid) << 32) | u64::from(if previous == pid { active + 1 } else { 1 });
            match CALLS.compare_exchange_weak(old, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(Self { pid }),
                Err(value) => old = value,
            }
        }
    }
}
impl Drop for Count {
    fn drop(&mut self) {
        let mut old = CALLS.load(Ordering::Acquire);
        loop {
            if (old >> 32) as u32 != self.pid {
                return;
            }
            let active = old as u32;
            if active == 0 {
                return;
            }
            let next = (u64::from(self.pid) << 32) | u64::from(active - 1);
            match CALLS.compare_exchange_weak(old, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return,
                Err(v) => old = v,
            }
        }
    }
}
struct Entered {
    pid: u32,
}
impl Entered {
    fn enter(pid: u32) -> Result<Self, Error> {
        ENTERED.with(|state| {
            let (previous, busy) = state.get();
            if previous == pid && busy {
                return Err(Error::Reentered);
            }
            state.set((pid, true));
            Ok(Self { pid })
        })
    }
}
impl Drop for Entered {
    fn drop(&mut self) {
        ENTERED.with(|s| {
            if s.get().0 == self.pid {
                s.set((self.pid, false));
            }
        })
    }
}
#[expect(
    unsafe_code,
    reason = "Read-only POSIX identity/PID queries have no pointers and perform no privilege mutation"
)]
fn identity() -> Option<u32> {
    // SAFETY: these libc getters take no arguments and only return process IDs.
    let (pid, uid, euid, gid, egid) = unsafe {
        (
            libc::getpid(),
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
        )
    };
    if pid <= 0 || uid == 0 || euid == 0 || uid != euid || gid != egid {
        None
    } else {
        u32::try_from(pid).ok()
    }
}
// OS bootstrap may run only on this already-suppressed actual worker thread.
// GNU libc's synchronous callback therefore hits Entered::enter before Count or
// thread creation and returns Error::Reentered/UNAVAIL from the original DSO.
pub(crate) fn bootstrap_suppressed() -> bool {
    identity().is_some_and(|pid| ENTERED.with(|state| state.get() == (pid, true)))
}
/// Blocking OS-host boundary. Every accepted lookup has one original5s default
/// budget and one scoped thread; it is joined after real native cleanup. No
/// caller runtime is entered/nested, and no permanent task or child process exists.
pub fn lookup(name: &[u8], family: Family, limits: Limits) -> Completion {
    let Some(hard) = Instant::now().checked_add(limits.timeout) else {
        return Completion::failed(Fault::Overflow.into());
    };
    if limits.timeout.is_zero()
        || limits.addresses == 0
        || limits.addresses > 16
        || limits.name_bytes == 0
        || limits.name_bytes > 1024
        || name.is_empty()
        || name.len() > limits.name_bytes
        || name.contains(&0)
    {
        return Completion::failed(Fault::InvalidInput.into());
    }
    let Some(pid) = identity() else {
        return Completion::failed(Error::Privileged);
    };
    let _entered = match Entered::enter(pid) {
        Ok(v) => v,
        Err(e) => return Completion::failed(e),
    };
    let _count = match Count::enter(pid) {
        Ok(v) => v,
        Err(e) => return Completion::failed(e),
    };
    let mut owned = Vec::new();
    if owned.try_reserve_exact(name.len()).is_err() {
        return Completion::failed(Fault::Capacity.into());
    }
    owned.extend_from_slice(name);
    let original = std::thread::Builder::new()
        .name("gnunet-nss".into())
        .stack_size(STACK_BYTES)
        .spawn(move || {
            let _entered = match Entered::enter(pid) {
                Ok(v) => v,
                Err(e) => return Completion::failed(e),
            };
            if Instant::now() >= hard {
                return Completion::failed(Error::Deadline);
            }
            crate::lookup::worker(owned, family, limits, hard)
        });
    let original = match original {
        Ok(handle) => handle,
        Err(e) => return Completion::failed(Error::Io(e)),
    };
    match original.join() {
        Ok(mut done) => {
            done.report.worker_started = true;
            done.report.worker_joined = true;
            done
        }
        Err(_payload) => {
            let mut done = Completion::failed(Error::WorkerPanicked);
            done.report.worker_started = true;
            done.report.worker_joined = true;
            done
        }
    }
}
