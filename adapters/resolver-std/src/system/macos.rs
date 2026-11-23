//! DNS-SD one-shot queries on original serial dispatch queues.
use super::{Answer, Question};
use gnunet_dns::{MAX_NAME_LENGTH, MAX_WIRE_NAME_LENGTH, Name, class};
use std::{
    ffi::{CStr, CString, c_char, c_void},
    future::Future,
    io,
    net::Ipv4Addr,
    pin::Pin,
    ptr::{self, NonNull},
    slice,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Context, Poll},
};
use tokio::sync::{OwnedSemaphorePermit, oneshot};

const MORE_COMING: u32 = 0x1;
const ADD: u32 = 0x2;
// DNS-SD reports negative records only when this flag is enabled. The daemon
// tries its own search domains before emitting the final negative result.
const RETURN_INTERMEDIATES: u32 = 0x1000;
const TIMEOUT: u32 = 0x10000;
const NO_SUCH_RECORD: i32 = -65554;

#[derive(Clone, Copy)]
#[repr(u16)]
enum Kind {
    A = 1,
    Ptr = 12,
    Aaaa = 28,
}

pub(super) struct Request {
    operation: Option<Arc<Operation>>,
    receiver: oneshot::Receiver<io::Result<Vec<Answer>>>,
}

pub(super) fn start(
    question: Question<'_>,
    limit: usize,
    permit: OwnedSemaphorePermit,
) -> io::Result<Request> {
    let mut reverse = [0; 80];
    let name = question.name(&mut reverse)?;
    let kind = match question {
        Question::A(_) => Kind::A,
        Question::Aaaa(_) => Kind::Aaaa,
        Question::Ptr(_) => Kind::Ptr,
    };
    if name.is_empty() || name.strip_suffix('.').unwrap_or(name).len() > MAX_NAME_LENGTH {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let name = CString::new(name)?;
    let (sender, receiver) = oneshot::channel();
    let operation = Arc::new(Operation {
        queue: Queue::new()?,
        kind,
        limit,
        state: Mutex::new(State {
            reference: None,
            completion: Some(Completion { sender, permit }),
            rows: Vec::new(),
        }),
    });
    operation
        .queue
        .submit(Job::Start(Arc::clone(&operation), name));
    Ok(Request {
        operation: Some(operation),
        receiver,
    })
}

impl Request {
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Vec<Answer>>> {
        Pin::new(&mut self.receiver).poll(cx).map(|ready| {
            drop(self.operation.take());
            ready.map_err(|_| io::Error::other("DNS-SD completion channel closed"))?
        })
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        self.receiver.close();
        if let Some(operation) = self.operation.take() {
            operation.queue.submit(Job::Cancel(Arc::clone(&operation)));
        }
    }
}

enum Job {
    Start(Arc<Operation>, CString),
    Cancel(Arc<Operation>),
}

struct Queue(NonNull<c_void>);

#[expect(
    unsafe_code,
    reason = "libdispatch queues have thread-safe reference ownership"
)]
// SAFETY: libdispatch queue references can be submitted to and released from
// any thread. The retained object outlives every borrow of this owner.
unsafe impl Send for Queue {}
#[expect(unsafe_code, reason = "libdispatch accepts concurrent submissions")]
// SAFETY: libdispatch serializes work independently of the submitting threads.
unsafe impl Sync for Queue {}

impl Queue {
    #[expect(
        unsafe_code,
        reason = "create and submit to an original libdispatch queue"
    )]
    fn new() -> io::Result<Self> {
        // SAFETY: the label is terminated and a null attribute selects a serial queue.
        let raw =
            unsafe { dispatch_queue_create(c"org.gnunet.resolver.query".as_ptr(), ptr::null()) };
        NonNull::new(raw)
            .map(Self)
            .ok_or_else(|| io::Error::new(io::ErrorKind::OutOfMemory, "DNS-SD dispatch queue"))
    }

    #[expect(
        unsafe_code,
        reason = "transfer one job to its original queue callback"
    )]
    fn submit(&self, job: Job) {
        let context = Box::into_raw(Box::new(job)).cast();
        // SAFETY: this retains the queue and passes the owned job to run_job exactly once.
        unsafe { dispatch_async_f(self.0.as_ptr(), context, run_job) };
    }
}

impl Drop for Queue {
    #[expect(unsafe_code, reason = "release the exact owned libdispatch queue")]
    fn drop(&mut self) {
        // SAFETY: dispatch_queue_create transferred a +1 reference to this owner.
        unsafe { dispatch_release(self.0.as_ptr()) };
    }
}

#[expect(
    unsafe_code,
    reason = "recover one transferred job on the serial queue"
)]
extern "C" fn run_job(context: *mut c_void) {
    // SAFETY: Queue::submit transfers a Box<Job> to this invocation exactly once.
    let job = unsafe { Box::from_raw(context.cast::<Job>()) };
    match *job {
        Job::Start(operation, name) => operation.launch(&name),
        Job::Cancel(operation) => operation.finish(Err(io::ErrorKind::Interrupted.into())),
    }
}

struct Operation {
    queue: Queue,
    kind: Kind,
    limit: usize,
    state: Mutex<State>,
}

struct State {
    reference: Option<Reference>,
    completion: Option<Completion>,
    rows: Vec<(u32, Answer)>,
}

struct Completion {
    sender: oneshot::Sender<io::Result<Vec<Answer>>>,
    permit: OwnedSemaphorePermit,
}

impl Operation {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn launch(self: Arc<Self>, name: &CStr) {
        if self
            .state()
            .completion
            .as_ref()
            .is_some_and(|completion| completion.sender.is_closed())
        {
            self.finish(Err(io::ErrorKind::Interrupted.into()));
            return;
        }
        // The DNS-SD request acknowledgement may block this queue. Callbacks
        // and queued cancellation cannot run until launch returns.
        match Reference::start(&self, name) {
            Ok(reference) => self.state().reference = Some(reference),
            Err(error) => self.finish(Err(error)),
        }
    }

    fn finish(&self, reply: io::Result<Vec<Answer>>) {
        let (reference, completion) = {
            let mut state = self.state();
            (state.reference.take(), state.completion.take())
        };
        drop(reference);
        if let Some(Completion { sender, permit }) = completion {
            drop(permit);
            // A caller-owned waker cannot unwind through the native queue.
            let _delivered =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sender.send(reply)));
        }
    }

    fn receive(&self, flags: u32, interface: u32, answer: io::Result<Option<Answer>>) {
        let answer = match answer {
            Ok(answer) => answer,
            Err(error) => {
                self.finish(Err(error));
                return;
            }
        };
        let result = {
            let mut state = self.state();
            if let Some(answer) = answer {
                let rows = &mut state.rows;
                let previous = rows
                    .iter()
                    .position(|(index, value)| *index == interface && value == &answer);
                match (flags & ADD != 0, previous) {
                    (true, None) if rows.len() == self.limit => {
                        drop(state);
                        self.finish(Err(io::ErrorKind::OutOfMemory.into()));
                        return;
                    }
                    (true, None) => rows.push((interface, answer)),
                    (false, Some(index)) => {
                        let _removed = rows.remove(index);
                    }
                    (true, Some(_)) | (false, None) => {}
                }
            }
            if flags & MORE_COMING != 0 {
                return;
            }
            let mut distinct = Vec::new();
            for (_, answer) in state.rows.drain(..) {
                if !distinct.contains(&answer) {
                    distinct.push(answer);
                }
            }
            distinct
        };
        self.finish(Ok(result));
    }
}

struct Reference {
    raw: NonNull<c_void>,
    _callback: CallbackContext,
}

#[expect(
    unsafe_code,
    reason = "the owning queue serializes all DNSServiceRef operations"
)]
// SAFETY: the handle is only operated on and retired by work running on its
// original serial queue. The other owner of Operation can only enqueue work.
unsafe impl Send for Reference {}

impl Reference {
    #[expect(
        unsafe_code,
        reason = "start DNS-SD and bind it to its original serial queue"
    )]
    fn start(operation: &Arc<Operation>, name: &CStr) -> io::Result<Self> {
        let callback = CallbackContext(Arc::into_raw(Arc::clone(operation)));
        let mut raw = ptr::null_mut();
        // SAFETY: the name and out pointer are live through this call. The
        // callback context stays alive through the original reference's drop.
        let code = unsafe {
            DNSServiceQueryRecord(
                &raw mut raw,
                RETURN_INTERMEDIATES | TIMEOUT,
                0,
                name.as_ptr(),
                operation.kind as u16,
                class::INTERNET,
                reply,
                callback.0.cast_mut().cast(),
            )
        };
        if code != 0 {
            return Err(dns_error(code));
        }
        let raw = NonNull::new(raw).ok_or(io::ErrorKind::InvalidData)?;
        let reference = Self {
            raw,
            _callback: callback,
        };
        // SAFETY: the reference was just acquired. This call is the only
        // registration, and is running on the same serial queue.
        let code = unsafe { DNSServiceSetDispatchQueue(raw.as_ptr(), operation.queue.0.as_ptr()) };
        if code != 0 {
            return Err(dns_error(code));
        }
        Ok(reference)
    }
}

impl Drop for Reference {
    #[expect(unsafe_code, reason = "cancel the original DNSServiceRef on its queue")]
    fn drop(&mut self) {
        // SAFETY: this runs on the reference's serial queue before releasing
        // its callback context. The class has no other native deallocator.
        unsafe { DNSServiceRefDeallocate(self.raw.as_ptr()) };
    }
}

// Own one raw Arc count from submission through registration failure or native
// deallocation. A callback can borrow it and temporarily retain another count.
struct CallbackContext(*const Operation);

impl Drop for CallbackContext {
    #[expect(unsafe_code, reason = "release the original raw Arc count")]
    fn drop(&mut self) {
        // SAFETY: Reference::start obtained the pointer with Arc::into_raw.
        // Native deallocation already completed if registration succeeded.
        drop(unsafe { Arc::from_raw(self.0) });
    }
}

#[expect(
    unsafe_code,
    reason = "borrow the live DNS-SD callback context and result bytes"
)]
extern "C" fn reply(
    _reference: *mut c_void,
    flags: u32,
    interface: u32,
    error: i32,
    _fullname: *const c_char,
    rrtype: u16,
    rrclass: u16,
    length: u16,
    data: *const c_void,
    _ttl: u32,
    context: *mut c_void,
) {
    let ptr = context.cast::<Operation>();
    // SAFETY: Reference holds the count behind the callback pointer. This
    // invocation takes its own count because completion can drop Reference.
    let operation = unsafe {
        Arc::increment_strong_count(ptr);
        Arc::from_raw(ptr)
    };
    if error == NO_SUCH_RECORD {
        // DNS-SD defines the other fields only when the status is successful.
        operation.receive(0, 0, Ok(None));
    } else if error != 0 {
        operation.finish(Err(dns_error(error)));
    } else if rrtype == operation.kind as u16 && rrclass == class::INTERNET {
        let length = usize::from(length);
        let answer = if data.is_null() || length == 0 || length > MAX_WIRE_NAME_LENGTH {
            Err(io::ErrorKind::InvalidData.into())
        } else {
            // SAFETY: on success DNS-SD lends length bytes for this callback.
            let bytes = unsafe { slice::from_raw_parts(data.cast::<u8>(), length) };
            decode(operation.kind, bytes)
        };
        operation.receive(flags, interface, answer);
    }
}

fn decode(kind: Kind, bytes: &[u8]) -> io::Result<Option<Answer>> {
    let answer = match kind {
        Kind::A => {
            let octets: [u8; 4] = bytes.try_into().map_err(|_| io::ErrorKind::InvalidData)?;
            Answer::V4(Ipv4Addr::from(octets))
        }
        Kind::Aaaa => {
            let octets: [u8; 16] = bytes.try_into().map_err(|_| io::ErrorKind::InvalidData)?;
            return Ok(Answer::unscoped_ipv6(octets));
        }
        Kind::Ptr => {
            let name = Name::from_wire(bytes).map_err(|_| io::ErrorKind::InvalidData)?;
            let mut dotted = [0; MAX_NAME_LENGTH];
            let count = name
                .write_dotted(&mut dotted)
                .map_err(|_| io::ErrorKind::InvalidData)?;
            if name
                .labels()
                .any(|label| label.contains(&0) || label.contains(&b'.'))
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let text = if count == 0 {
                "."
            } else {
                std::str::from_utf8(&dotted[..count]).map_err(|_| io::ErrorKind::InvalidData)?
            };
            Answer::Name(text.to_owned())
        }
    };
    Ok(Some(answer))
}

fn dns_error(code: i32) -> io::Error {
    io::Error::other(format!("macOS DNS-SD error {code}"))
}

type Reply = extern "C" fn(
    *mut c_void,
    u32,
    u32,
    i32,
    *const c_char,
    u16,
    u16,
    u16,
    *const c_void,
    u32,
    *mut c_void,
);

#[expect(
    unsafe_code,
    reason = "exact DNS-SD and libdispatch declarations from the Apple SDK"
)]
unsafe extern "C" {
    fn DNSServiceQueryRecord(
        reference: *mut *mut c_void,
        flags: u32,
        interface: u32,
        name: *const c_char,
        rrtype: u16,
        rrclass: u16,
        callback: Reply,
        context: *mut c_void,
    ) -> i32;
    fn DNSServiceSetDispatchQueue(reference: *mut c_void, queue: *mut c_void) -> i32;
    fn DNSServiceRefDeallocate(reference: *mut c_void);
    fn dispatch_queue_create(label: *const c_char, serial: *const c_void) -> *mut c_void;
    fn dispatch_async_f(queue: *mut c_void, context: *mut c_void, job: extern "C" fn(*mut c_void));
    fn dispatch_release(queue: *mut c_void);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert native PTR decoding and IPv6 scope exclusion"
    )]
    fn decodes_ptr_and_excludes_ipv6_scope() -> io::Result<()> {
        let ptr = decode(Kind::Ptr, b"\x04test\x07example\x00")?;
        assert!(matches!(ptr, Some(Answer::Name(name)) if name == "test.example"));
        assert!(decode(Kind::Ptr, b"\x04test").is_err());
        let scoped = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        assert!(decode(Kind::Aaaa, &scoped.octets())?.is_none());
        Ok(())
    }
}
