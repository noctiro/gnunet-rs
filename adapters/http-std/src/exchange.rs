use crate::{
    Error, Fault, HttpLimits, IoLease, Method, Proxy, ProxyKind, Request, State,
    gate::cooperate,
    transport::{Socket, authority, basic, copy, unescape},
};
use http_body_util::Full;
use hyper::{Request as HyperRequest, Version, body::Body};
use hyper_util::rt::TokioIo;
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    rc::Rc,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use url::Url;
use zeroize::Zeroizing;

/// Request-level plaintext boundary above TLS (and above the proxy tunnel).
/// TCP byte accounting stays below TLS and remains an independent observation.
struct Application {
    inner: Socket,
    lease: Rc<IoLease>,
    progress: Arc<State>,
}
impl AsyncRead for Application {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.lease.check()?;
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for Application {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.lease.check()?;
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.progress.attempted.store(true, Ordering::Release);
        let result = Pin::new(&mut this.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(n)) = result {
            this.progress.plaintext.fetch_add(n, Ordering::Release);
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.lease.check()?;
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            this.progress.flushed.store(true, Ordering::Release)
        }
        result
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
pub(crate) struct Reply {
    pub status: u16,
    pub head: crate::Head,
    pub body: Zeroizing<Vec<u8>>,
    pub post_guard: Option<Error>,
}
pub(crate) struct Exchange<'a> {
    pub url: &'a Url,
    pub absolute: bool,
    pub proxy: Option<&'a Proxy>,
    pub inherited_auth: Option<&'a [u8]>,
    pub request: &'a Request,
    pub lease: Rc<IoLease>,
    pub progress: Arc<State>,
    pub limits: HttpLimits,
}
pub(crate) async fn exchange(socket: Socket, input: Exchange<'_>) -> Result<Reply, Error> {
    let Exchange {
        url,
        absolute,
        proxy,
        inherited_auth,
        request,
        lease,
        progress,
        limits,
    } = input;
    let mut clean = url.clone();
    clean.set_username("").map_err(|_| Fault::InvalidInput)?;
    clean.set_password(None).map_err(|_| Fault::InvalidInput)?;
    clean.set_fragment(None);
    let target = if absolute {
        clean.as_str().to_owned()
    } else {
        let mut path = clean.path().to_owned();
        if path.is_empty() {
            path.push('/')
        }
        if let Some(query) = clean.query() {
            path.push('?');
            path.push_str(query)
        }
        path
    };
    let mut builder = HyperRequest::builder()
        .method(request.method().name())
        .uri(target)
        .header("Host", authority(url, false)?)
        .header("User-Agent", "GNUnet")
        .header("Accept", "application/octet-stream")
        .header("Connection", "close");
    if let Some(proxy) = proxy
        && absolute
    {
        if proxy.kind == ProxyKind::Http10 {
            builder = builder.version(Version::HTTP_10)
        }
        if !proxy.username.is_empty() || !proxy.password.is_empty() {
            let auth = basic(&proxy.username, &proxy.password)?;
            builder = builder.header(
                "Proxy-Authorization",
                hyper::header::HeaderValue::from_bytes(&auth).map_err(|_| Fault::InvalidInput)?,
            );
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        let user = unescape(url.username().as_bytes())?;
        let pass = unescape(url.password().unwrap_or("").as_bytes())?;
        let auth = basic(&user, &pass)?;
        builder = builder.header(
            "Authorization",
            hyper::header::HeaderValue::from_bytes(&auth).map_err(|_| Fault::InvalidInput)?,
        );
    } else if let Some(auth) = inherited_auth {
        builder = builder.header(
            "Authorization",
            hyper::header::HeaderValue::from_bytes(auth).map_err(|_| Fault::InvalidInput)?,
        );
    }
    if let Some(action) = &request.0.action {
        let mut quoted = copy(action)?;
        quoted.try_reserve(2).map_err(|_| Fault::Capacity)?;
        quoted.insert(0, b'"');
        quoted.push(b'"');
        builder = builder
            .header(
                "SOAPAction",
                hyper::header::HeaderValue::from_bytes(&quoted).map_err(|_| Fault::InvalidInput)?,
            )
            .header("Content-Type", "text/xml; charset=\"utf-8\"")
            .header("Content-Length", request.0.body.len());
    }
    let native = builder.body(Full::new(request.0.body.clone()))?;
    let mut bytes = native
        .method()
        .as_str()
        .len()
        .checked_add(native.uri().to_string().len())
        .and_then(|n| n.checked_add(16))
        .ok_or(Fault::Overflow)?;
    if native.headers().len() > limits.headers {
        return Err(Fault::Capacity.into());
    }
    for (name, value) in native.headers() {
        bytes = bytes
            .checked_add(name.as_str().len())
            .and_then(|n| n.checked_add(value.as_bytes().len()))
            .and_then(|n| n.checked_add(4))
            .ok_or(Fault::Overflow)?;
    }
    if bytes > limits.header_bytes {
        return Err(Fault::Capacity.into());
    }
    let io = Application {
        inner: socket,
        lease: lease.clone(),
        progress: progress.clone(),
    };
    let mut builder = hyper::client::conn::http1::Builder::new();
    builder
        .max_headers(limits.headers)
        .max_buf_size(limits.header_bytes);
    let (mut sender, connection) = builder.handshake(TokioIo::new(io)).await?;
    let mut connection = Box::pin(connection);
    let mut ended = false;
    // The initial sender need not be ready until its real connection receiver
    // has been polled. Keep that connection in this owner while waiting for the
    // actual readiness waker; never turn permanent Pending into a busy retry.
    poll_fn(|cx| {
        let result = connection.as_mut().poll(cx);
        if result.is_ready() {
            ended = true
        }
        if let Poll::Ready(Err(error)) = result {
            return Poll::Ready(Err(Error::Http(error)));
        }
        match sender.poll_ready(cx) {
            Poll::Ready(result) => Poll::Ready(result.map_err(Error::Http)),
            Poll::Pending if ended => Poll::Ready(Err(Fault::Closed.into())),
            Poll::Pending => Poll::Pending,
        }
    })
    .await?;
    // A factual dispatch API invocation is neither queue ACK nor whole write.
    // This owner is the sole foreground driver of this unshared connection.
    progress.dispatch.store(true, Ordering::Release);
    let mut response_future = Box::pin(sender.send_request(native));
    let mut response = poll_fn(|cx| {
        let c = if ended {
            Poll::Pending
        } else {
            connection.as_mut().poll(cx)
        };
        if c.is_ready() {
            ended = true
        }
        if let Poll::Ready(Err(error)) = c {
            return Poll::Ready(Err(Error::Http(error)));
        }
        let result = response_future.as_mut().poll(cx);
        if result.is_ready() {
            return result.map_err(Error::Http);
        }
        if ended {
            Poll::Ready(Err(Fault::Closed.into()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    lease.check()?;
    progress.headers.store(true, Ordering::Release);
    let status = response.status().as_u16();
    let location = response
        .headers()
        .get(hyper::header::LOCATION)
        .map(|h| {
            if h.as_bytes().len() > limits.uri_bytes {
                return Err(Fault::Capacity.into());
            }
            copy(h.as_bytes())
        })
        .transpose()?;
    let head = crate::Head {
        location,
        length: response
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|h| h.to_str().ok())
            .and_then(|n| n.parse::<u64>().ok()),
        kind: response
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .map(|h| copy(h.as_bytes()))
            .transpose()?,
    };
    if request.redirects() == crate::Redirects::Follow
        && matches!(status, 301 | 302 | 303 | 307 | 308)
    {
        // Explicit safe-method redirect does not falsely record entity EOF.
        return Ok(Reply {
            status,
            head,
            body: Zeroizing::new(Vec::new()),
            post_guard: None,
        });
    }
    if request.method() != Method::Head
        && response
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|h| h.to_str().ok())
            .and_then(|n| n.parse::<u64>().ok())
            .is_some_and(|n| n > limits.body_bytes as u64)
    {
        return Err(Fault::Capacity.into());
    }
    if request.method() != Method::Head
        && response
            .headers()
            .get(hyper::header::CONTENT_ENCODING)
            .is_some_and(|h| !h.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return Err(Fault::Unsupported.into());
    }
    let mut body = Zeroizing::new(Vec::new());
    if request.method() != Method::Head {
        body.try_reserve_exact(limits.body_bytes)
            .map_err(|_| Fault::Capacity)?;
    }
    let mut frames = 0usize;
    loop {
        let frame = poll_fn(|cx| {
            let c = if ended {
                Poll::Pending
            } else {
                connection.as_mut().poll(cx)
            };
            if c.is_ready() {
                ended = true
            }
            if let Poll::Ready(Err(error)) = c {
                return Poll::Ready(Err(Error::Http(error)));
            }
            match Pin::new(response.body_mut()).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => Poll::Ready(Ok(Some(frame))),
                Poll::Ready(Some(Err(error))) => Poll::Ready(Err(Error::Http(error))),
                Poll::Ready(None) => Poll::Ready(Ok(None)),
                Poll::Pending => {
                    if ended {
                        Poll::Ready(Err(Fault::Closed.into()))
                    } else {
                        Poll::Pending
                    }
                }
            }
        })
        .await?;
        let Some(frame) = frame else { break };
        frames = frames.checked_add(1).ok_or(Fault::Overflow)?;
        if frames > limits.frames {
            return Err(Fault::Capacity.into());
        }
        if let Ok(bytes) = frame.into_data() {
            if request.method() == Method::Head && !bytes.is_empty() {
                return Err(Fault::Malformed.into());
            }
            if bytes.len() > limits.body_bytes.saturating_sub(body.len()) {
                return Err(Fault::Capacity.into());
            }
            body.extend_from_slice(&bytes);
        }
        cooperate().await;
    }
    // Framing has actually completed. A failed post-response lease check must
    // deny subsequent progress without erasing these already received bytes.
    let post_guard = lease.check().err().map(Error::Io);
    progress.complete.store(true, Ordering::Release);
    Ok(Reply {
        status,
        head,
        body,
        post_guard,
    })
}
