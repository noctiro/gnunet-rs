//! One-shot sends and per-message reply custody for a captured UDP group.
use super::{
    callback::{Callback, thread_safe},
    completion::{self, Completion},
    connection::sdk::{self as network, CBool, Dispatch, Object},
    input::{Datagram, FlowId, ReplyEndpoint},
    lifetime::{self, Pending},
    provider::ProviderLease,
    sdk::{Endpoint, NativeFlow},
};
use block2::RcBlock;
use std::{
    ffi::c_void,
    fmt, io,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
use zeroize::Zeroizing;

mod path;
#[expect(
    unsafe_code,
    reason = "Network.framework group creation and borrowed callback metadata are private native SDK operations"
)]
mod sdk;
mod state;
use path::Path;
use state::{Watch, contain};

pub(super) fn is_multicast_destination(endpoint: &Endpoint) -> io::Result<bool> {
    path::is_multicast_destination(endpoint)
}

/// An original UDP datagram sent to a multicast group.
///
/// Its private destination cannot be used as a reply source.
pub struct MulticastRequest {
    pub(super) flow: FlowId,
    pub(super) group: Endpoint,
    pub(super) bytes: Zeroizing<Vec<u8>>,
    pub(super) reply_limit: usize,
    pub(super) received_at: Instant,
}
impl MulticastRequest {
    /// Exact captured UDP payload.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Identity of the flow that supplied this multicast destination.
    pub const fn flow_id(&self) -> FlowId {
        self.flow
    }

    /// The port of the original retained native multicast destination.
    /// # Errors
    /// Returns the native endpoint's address observation error.
    pub fn destination_port(&self) -> io::Result<u16> {
        Ok(self.group.socket_addr()?.port())
    }

    /// Monotonic observation taken in the original native read callback.
    pub const fn received_at(&self) -> Instant {
        self.received_at
    }
}
impl fmt::Debug for MulticastRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MulticastRequest")
            .field("flow", &self.flow)
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Observable work from an original native multicast exchange.
#[derive(Debug)]
pub enum MulticastEvent {
    /// The local SDK accepted the original group send.
    Sent,
    /// A distinct unicast reply from its actual native sender.
    Reply(Datagram),
    /// Native cancellation, handler disposal and send retirement are complete.
    Retired(MulticastRetirement),
}

/// Final native multicast send and cancellation observations.
#[derive(Debug)]
pub struct MulticastRetirement {
    send_accepted: bool,
    result: io::Result<()>,
}
impl MulticastRetirement {
    /// A successful original send callback was observed, including during cancellation.
    pub const fn send_accepted(&self) -> bool {
        self.send_accepted
    }

    /// Whether the group, its native send or its cancellation failed.
    pub const fn has_failure(&self) -> bool {
        self.result.is_err()
    }

    /// Return the original error if the group or its native send failed.
    pub fn into_result(self) -> io::Result<()> {
        self.result
    }
}

struct Handler {
    watch: Arc<Watch>,
    _disposed: completion::Publisher<()>,
    _provider: Option<ProviderLease>,
}

struct ReceiveHandler {
    path: Path,
    handler: Handler,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Admission {
    Open,
    CompletionsOnly,
}

pub(super) struct Relay {
    native: Option<Object>,
    queue: Dispatch,
    provider: Option<ProviderLease>,
    watch: Arc<Watch>,
    original: Option<MulticastRequest>,
    sending: Option<Pending<()>>,
    send_accepted: bool,
    failure: Option<io::Error>,
    state_disposal: Completion<()>,
    receive_disposal: Completion<()>,
}
impl Relay {
    pub(super) fn new(
        flow: &NativeFlow,
        local: &Endpoint,
        request: MulticastRequest,
        provider: Option<ProviderLease>,
    ) -> io::Result<Self> {
        let path = Path::new(local, &request.group)?;
        let maximum = u32::try_from(request.reply_limit).map_err(io::Error::other)?;
        let (native, queue) = sdk::create(flow, local, &request.group, &path)?;
        let watch = Arc::new(Watch::new(native.clone()));
        let (state_disposal, state) = completion::pair();
        let (receive_disposal, receive) = completion::pair();
        register_state(&native, Arc::clone(&watch), provider.clone(), state);
        register_receive(
            &native,
            Handler {
                watch: Arc::clone(&watch),
                _disposed: receive,
                _provider: provider.clone(),
            },
            path,
            request.flow,
            maximum,
        );
        sdk::start(&native);
        Ok(Self {
            native: Some(native),
            queue,
            provider,
            watch,
            original: Some(request),
            sending: None,
            send_accepted: false,
            failure: None,
            state_disposal,
            receive_disposal,
        })
    }

    fn submit(&mut self) -> io::Result<()> {
        let (Some(native), Some(request)) = (self.native.as_ref(), self.original.as_ref()) else {
            return Err(io::ErrorKind::NotConnected.into());
        };
        let data = network::copy_data(&request.bytes)?;
        let (pending, publish, disposed) = lifetime::reserve();
        let callback = Callback::new(
            publish,
            (native.clone(), self.queue.clone()),
            disposed,
            None,
            (data.clone(), request.group.clone()),
        )
        .keep_provider(self.provider.clone());
        let block = RcBlock::new(thread_safe(move |error| {
            callback
                .invoke(|| network::failure(error).map_or(Ok(()), |error| Err(error.into_error())))
        }));
        self.sending = Some(pending);
        self.watch.arm();
        sdk::send(native, &data, &request.group, &block);
        Ok(())
    }

    pub(super) fn query(&self) -> Option<&[u8]> {
        self.original.as_ref().map(MulticastRequest::bytes)
    }

    pub(super) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        admission: Admission,
    ) -> Poll<MulticastEvent> {
        if self.native.is_none() {
            return self.poll_retirement(cx);
        }
        match self.watch.poll_ready(cx) {
            Poll::Ready(Ok(()))
                if admission == Admission::Open
                    && !self.send_accepted
                    && self.sending.is_none() =>
            {
                if let Err(error) = self.submit() {
                    return self.fail(cx, error);
                }
            }
            Poll::Ready(Err(error)) => return self.fail(cx, error),
            _ => {}
        }
        if let Some(pending) = &mut self.sending {
            let Poll::Ready(result) = pending.poll(cx) else {
                return Poll::Pending;
            };
            self.sending = None;
            return match result {
                Some(Ok(())) => {
                    self.send_accepted = true;
                    Poll::Ready(MulticastEvent::Sent)
                }
                Some(Err(error)) => self.fail(cx, error),
                None => self.fail(cx, io::Error::other("native multicast send result missing")),
            };
        }
        if admission == Admission::Open {
            self.watch.poll_reply(cx).map(MulticastEvent::Reply)
        } else {
            Poll::Pending
        }
    }

    fn fail(&mut self, cx: &mut Context<'_>, error: io::Error) -> Poll<MulticastEvent> {
        self.failure = Some(error);
        self.cancel();
        self.poll_retirement(cx)
    }

    pub(super) fn cancel(&mut self) {
        if let Some(native) = self.native.take() {
            self.watch.disarm();
            self.original = None;
            sdk::cancel(&native);
        }
    }

    fn poll_retirement(&mut self, cx: &mut Context<'_>) -> Poll<MulticastEvent> {
        if let Some(send) = &mut self.sending
            && let Poll::Ready(result) = send.poll(cx)
        {
            match result {
                Some(Ok(())) => self.send_accepted = true,
                Some(Err(error)) => {
                    self.failure.get_or_insert(error);
                }
                None => {
                    self.failure.get_or_insert_with(|| {
                        io::Error::other("native multicast send result missing")
                    });
                }
            }
            self.sending = None;
        }
        let state_disposed = self.state_disposal.poll(cx).is_ready();
        let receive_disposed = self.receive_disposal.poll(cx).is_ready();
        let Poll::Ready(cancelled) = self.watch.poll_cancelled(cx) else {
            return Poll::Pending;
        };
        if !state_disposed || !receive_disposed || self.sending.is_some() {
            return Poll::Pending;
        }
        Poll::Ready(MulticastEvent::Retired(MulticastRetirement {
            send_accepted: self.send_accepted,
            result: self.failure.take().map_or(cancelled, Err),
        }))
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn register_state(
    native: &Object,
    watch: Arc<Watch>,
    provider: Option<ProviderLease>,
    disposed: completion::Publisher<()>,
) {
    let handler = Handler {
        watch,
        _disposed: disposed,
        _provider: provider,
    };
    let block = RcBlock::new(thread_safe(move |value, error| {
        // Use the whole context so its native block retains its disposal and provider keepers.
        let handler = &handler;
        contain(|| handler.watch.publish(value, network::failure(error)));
    }));
    sdk::set_state(native, &block);
}

fn register_receive(native: &Object, handler: Handler, path: Path, id: FlowId, maximum: u32) {
    // Keep the original local endpoint ahead of the disposal signal in field
    // drop order, even when the SDK releases the handlers asynchronously.
    let registration = ReceiveHandler { path, handler };
    let block = RcBlock::new(thread_safe(move |data, context, complete: CBool| {
        let registration = &registration;
        let watch = &registration.handler.watch;
        contain(|| {
            if complete.get()
                && let Some(native) = watch.receive_on()
                && let Ok(reply) = read_message(
                    &native,
                    &registration.path,
                    id,
                    maximum as usize,
                    data,
                    context,
                )
            {
                watch.reply(reply);
            }
        });
    }));
    sdk::set_receive(native, maximum, &block);
}

#[expect(
    unsafe_code,
    reason = "Only the original Network.group receive callback lends its invocation-borrowed message context"
)]
fn read_message(
    native: &Object,
    path: &Path,
    flow: FlowId,
    maximum: usize,
    data: *mut c_void,
    context: *mut c_void,
) -> io::Result<Datagram> {
    // SAFETY: These copies use the receive handler's original group and message
    // context while the SDK still lends that context.
    let (local, endpoint, _message_path) = unsafe {
        (
            sdk::message_local(native, context)?,
            sdk::message_sender(native, context)?,
            sdk::message_path(native, context)?,
        )
    };
    path.accept(&local, &endpoint)?;
    let bytes = network::content(data, maximum)?;
    Ok(Datagram::reply(bytes, ReplyEndpoint { flow, endpoint }))
}
