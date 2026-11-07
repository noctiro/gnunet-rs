//! Authoritative original IPC role/total before any crypto/dependency source.
use crate::run::{Control, KeyLease, Registry};
use crate::{Error, Limits, Profile, Role};
use gnunet_scalarproduct::Value;
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    framing::{Framed, ReadStep},
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::scalarproduct::{ClientRequest, ELEMENT_BYTES, Element};
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    mem::size_of,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::Poll,
};
use tokio::time::Instant;

/// Immutable original accepted intent and selected role/profile limits.
/// Captured before diagnostic/provider/allocator work, never when first polled.
pub(crate) struct Admission {
    pub id: u64,
    pub role: Role,
    pub limits: Limits,
    pub profile: Profile,
    pub started: Instant,
    pub now: u64,
}
pub(crate) struct Prepared {
    pub session: [u8; 64],
    pub peer: Option<[u8; 32]>,
    pub values: Vec<Value>,
    pub canonical_origin: u64,
    pub lease: KeyLease,
    pub canonical_until: u64,
    pub native_until: Instant,
}
struct Builder {
    session: [u8; 64],
    peer: Option<[u8; 32]>,
    total: usize,
    values: Vec<Value>,
    lease: KeyLease,
}
impl Builder {
    fn new(
        id: u64,
        role: Role,
        request: ClientRequest<'_>,
        limits: Limits,
        profile: Profile,
        registry: Rc<RefCell<Registry>>,
    ) -> Result<Self, Error> {
        let (session, peer, total, elements) = match (role, request) {
            (
                Role::Alice,
                ClientRequest::Alice {
                    session,
                    peer,
                    total,
                    elements,
                    ..
                },
            ) => (*session, Some(*peer), total, elements),
            (
                Role::Bob,
                ClientRequest::Bob {
                    session,
                    total,
                    elements,
                    ..
                },
            ) => (*session, None, total, elements),
            _ => return Err(Fault::Malformed.into()),
        };
        let total = usize::try_from(total).map_err(|_| Fault::TooLarge)?;
        if total == 0 || total > limits.max_rows {
            return Err(Fault::TooLarge.into());
        }
        let budget = profile.input_budget(limits)?;
        if total
            .checked_mul(size_of::<Value>())
            .ok_or(Fault::Overflow)?
            > budget
        {
            return Err(Fault::Capacity.into());
        }
        let lease = KeyLease::claim(registry, id, session)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(total)
            .map_err(|_| Fault::Capacity)?;
        if values
            .capacity()
            .checked_mul(size_of::<Value>())
            .ok_or(Fault::Overflow)?
            > budget
        {
            return Err(Fault::Capacity.into());
        }
        let mut this = Self {
            session,
            peer,
            total,
            values,
            lease,
        };
        this.append(elements)?;
        Ok(this)
    }
    fn append(&mut self, elements: &[[u8; ELEMENT_BYTES]]) -> Result<(), Error> {
        if elements.is_empty()
            || elements.len()
                > self
                    .total
                    .checked_sub(self.values.len())
                    .ok_or(Fault::Conflict)?
        {
            return Err(Fault::Malformed.into());
        }
        for bytes in elements {
            let item = Element::decode(bytes)?;
            self.values.push(Value::new(*item.key, item.value));
        }
        Ok(())
    }
    fn more(&mut self, role: Role, request: ClientRequest<'_>) -> Result<(), Error> {
        match (role, request) {
            (Role::Alice, ClientRequest::AlicePart { elements })
            | (Role::Bob, ClientRequest::BobPart { elements }) => self.append(elements),
            _ => Err(Fault::Malformed.into()),
        }
    }
    fn complete(&self) -> bool {
        self.values.len() == self.total
    }
}

pub(crate) async fn read(
    admission: Admission,
    io: &mut Framed<u64>,
    clock: Arc<dyn RuntimeClock>,
    registry: Rc<RefCell<Registry>>,
    control: &Control,
) -> Result<Prepared, Error> {
    let Admission {
        id,
        role,
        limits,
        profile,
        started,
        now,
    } = admission;
    let native_until = started
        .checked_add(limits.operation)
        .ok_or(Fault::Overflow)?;
    let mut first = Some(
        started
            .checked_add(limits.first_input)
            .ok_or(Fault::Overflow)?,
    );
    let mut partial = None;
    let canonical_until = now
        .checked_add(u64::try_from(limits.operation.as_micros()).map_err(|_| Fault::Overflow)?)
        .ok_or(Fault::Overflow)?;
    if Instant::now() >= native_until || first.is_some_and(|at| Instant::now() >= at) {
        return Err(Fault::Deadline.into());
    }
    let mut deadline = Deadline::at(
        clock.clone(),
        gnunet_types::AbsoluteTime::from_micros(canonical_until),
    )?;
    let mut timer = Box::pin(tokio::time::sleep_until(native_until));
    let mut builder: Option<Builder> = None;
    poll_fn(|cx| {
        if let Some(cause) = control.reason() {
            return Poll::Ready(Err(cause.into()));
        }
        let native = Instant::now();
        if native >= native_until
            || first.is_some_and(|at| native >= at)
            || partial.is_some_and(|at| native >= at)
        {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        if clock.sample()?.now.as_micros() >= canonical_until {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        if let Some(cause) = control.reason() {
            return Poll::Ready(Err(cause.into()));
        }
        if Instant::now() >= native_until
            || first.is_some_and(|at| Instant::now() >= at)
            || partial.is_some_and(|at| Instant::now() >= at)
        {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        if let Poll::Ready(result) = Pin::new(&mut deadline).poll(cx) {
            result?;
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        if let Some(cause) = control.reason() {
            return Poll::Ready(Err(cause.into()));
        }
        if Instant::now() >= native_until
            || first.is_some_and(|at| Instant::now() >= at)
            || partial.is_some_and(|at| Instant::now() >= at)
        {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        if let Some(bytes) = io.frame() {
            let request = ClientRequest::decode(bytes)?;
            if let Some(builder) = builder.as_mut() {
                builder.more(role, request)?;
            } else {
                builder = Some(Builder::new(
                    id,
                    role,
                    request,
                    limits,
                    profile,
                    registry.clone(),
                )?);
            }
            let _released = io.release_frame();
            first = None;
            partial = None;
            if builder.as_ref().is_some_and(Builder::complete) {
                let ready = builder.take().ok_or(Fault::Conflict)?;

                return Poll::Ready(Ok(Prepared {
                    session: ready.session,
                    peer: ready.peer,
                    values: ready.values,
                    canonical_origin: now,
                    lease: ready.lease,
                    canonical_until,
                    native_until,
                }));
            }
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if let Some(cause) = control.reason() {
            return Poll::Ready(Err(cause.into()));
        }
        if Instant::now() >= native_until
            || first.is_some_and(|at| Instant::now() >= at)
            || partial.is_some_and(|at| Instant::now() >= at)
        {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        match io.poll_read(cx) {
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(ReadStep::Eof)) => return Poll::Ready(Err(Fault::Closed.into())),
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
                if bytes > 0 && !complete && partial.is_none() {
                    partial = Some(
                        native
                            .checked_add(limits.partial_input)
                            .ok_or(Fault::Overflow)?,
                    );
                }
                if complete {
                    partial = None;
                }
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Pending => {}
        }
        let at = Some(native_until)
            .into_iter()
            .chain(first)
            .chain(partial)
            .min()
            .ok_or(Fault::Conflict)?;
        timer.as_mut().reset(at);
        if timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        Poll::Pending
    })
    .await
}
