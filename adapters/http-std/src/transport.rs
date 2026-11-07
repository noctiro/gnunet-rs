//! Mature HTTP/1 and verified TLS with explicit sockets, Resolver and no spawned
//! connection task. Proxy negotiation is bounded and tied to its original job.
use crate::bounded_io::{Counted, Counters, IoLease};
use crate::{Error, Fault, gate::cooperate};
use gnunet_client_host::resolution::{AddressLookup, SharedResolution};
use gnunet_service_runtime::connection::ConnectionLease;
use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    rc::Rc,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    time::Instant,
};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

/// Finite protocol and per-job native work budgets.
#[derive(Clone, Copy, Debug)]
pub struct HttpLimits {
    /// Maximum original/redirect URL bytes, at most8192.
    pub uri_bytes: usize,
    /// Complete decoded HTTP body cap; official default 500000.
    pub body_bytes: usize,
    /// Maximum immutable SOAP request-body bytes (also capped at 1 MiB).
    pub request_body_bytes: usize,
    /// Native bytes in each direction, including proxy/TLS overhead.
    pub wire_bytes: usize,
    /// Maximum distinct address socket attempts for the entire redirect/proxy job.
    pub probes: usize,
    /// HTTP request/response header count cap.
    pub headers: usize,
    /// Mature HTTP parser read-buffer cap, at least 8192.
    pub header_bytes: usize,
    /// Maximum nonempty HTTP body frames; empty/trailer frames share this budget.
    pub frames: usize,
    /// Maximum redirect count; official default four.
    pub redirects: usize,
}
impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            uri_bytes: 8192,
            body_bytes: 500_000,
            request_body_bytes: 65536,
            wire_bytes: 4 * 1024 * 1024,
            probes: 128,
            headers: 64,
            header_bytes: 32768,
            frames: 16384,
            redirects: 4,
        }
    }
}
impl HttpLimits {
    /// Validate explicit finite memory/work/native byte bounds.
    pub fn validate(self) -> Result<(), Error> {
        if self.uri_bytes == 0
            || self.uri_bytes > 8192
            || self.body_bytes == 0
            || self.body_bytes > 16 * 1024 * 1024
            || self.request_body_bytes > 1024 * 1024
            || self.wire_bytes < self.body_bytes
            || self.wire_bytes > 64 * 1024 * 1024
            || self.probes == 0
            || self.probes > 4096
            || self.headers == 0
            || self.headers > 256
            || self.header_bytes < 8192
            || self.header_bytes > 262140
            || self.frames == 0
            || self.frames > 16 * 1024 * 1024
            || self.redirects > 16
        {
            return Err(Fault::InvalidInput.into());
        }
        Ok(())
    }
}

/// Active configured proxy kinds, preserving distinct local/remote DNS modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyKind {
    /// HTTP proxy.
    Http,
    /// HTTP/1.0 proxy, including CONNECT.
    Http10,
    /// SOCKS4 with local IPv4-only shared Resolver lookup.
    Socks4,
    /// SOCKS5 with local shared Resolver lookup.
    Socks5,
    /// SOCKS4a with proxy-side destination DNS.
    Socks4a,
    /// SOCKS5 with proxy-side destination DNS.
    Socks5Hostname,
}
/// Explicit bounded proxy input. No environment/system proxy is consulted.
pub struct Proxy {
    pub(crate) kind: ProxyKind,
    endpoint: Zeroizing<Vec<u8>>,
    pub(crate) username: Zeroizing<Vec<u8>>,
    pub(crate) password: Zeroizing<Vec<u8>>,
}
impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proxy")
            .field("kind", &self.kind)
            .field("endpoint", &"[redacted]")
            .field("authentication", &"[redacted]")
            .finish()
    }
}
impl Proxy {
    /// Build from explicit caller proxy configuration, keeping all credentials
    /// opaque. A missing proxy port uses libcurl's default 1080.
    pub fn new(
        kind: ProxyKind,
        endpoint: &[u8],
        username: Option<&[u8]>,
        password: Option<&[u8]>,
    ) -> Result<Self, Error> {
        if endpoint.is_empty()
            || endpoint.len() > 1000
            || username.is_some_and(|v| v.len() > 1024)
            || password.is_some_and(|v| v.len() > 1024)
            || endpoint.iter().any(|b| *b <= 0x20 || *b == 0x7f)
            || username.is_some_and(|v| v.contains(&0))
            || password.is_some_and(|v| v.contains(&0))
        {
            return Err(Fault::InvalidInput.into());
        }
        let raw = std::str::from_utf8(endpoint).map_err(|_| Fault::InvalidInput)?;
        let mut url = if raw.contains("://") {
            Url::parse(raw)?
        } else {
            Url::parse(&format!("http://{raw}"))?
        };
        if url.host_str().is_none()
            || !matches!(
                url.scheme(),
                "http" | "https" | "socks4" | "socks4a" | "socks5" | "socks5h"
            )
        {
            return Err(Fault::InvalidInput.into());
        }
        if url.scheme() == "https" && !matches!(kind, ProxyKind::Http | ProxyKind::Http10) {
            return Err(Fault::Unsupported.into());
        }
        let user = match username {
            Some(value) => copy(value)?,
            None => unescape(url.username().as_bytes())?,
        };
        let pass = match password {
            Some(value) => copy(value)?,
            None => unescape(url.password().unwrap_or("").as_bytes())?,
        };
        url.set_username("").map_err(|_| Fault::InvalidInput)?;
        url.set_password(None).map_err(|_| Fault::InvalidInput)?;
        if url.port().is_none() {
            url.set_port(Some(1080)).map_err(|_| Fault::InvalidInput)?;
        }
        Ok(Self {
            kind,
            endpoint: copy(url.as_str().as_bytes())?,
            username: user,
            password: pass,
        })
    }
    /// The actual configured kind; endpoint/authentication remain redacted.
    pub const fn kind(&self) -> ProxyKind {
        self.kind
    }
}

/// Explicit owned mature TLS config. Uses public CA roots and the standard
/// Unix wall clock for X509 validity. Operation deadlines use RuntimeClock
/// separately. No global provider install, insecure verifier, key log or client key.
#[derive(Clone)]
pub struct Tls {
    config: Arc<rustls::ClientConfig>,
}
impl fmt::Debug for Tls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tls(verified, X509-system-wall-clock, redacted)")
    }
}
impl Tls {
    /// Public webpki CA snapshot with explicit AWS-LC non-FIPS provider ownership.
    pub fn new() -> Result<Self, Error> {
        Self::with_roots(rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ))
    }
    /// Explicit caller-supplied public roots; hostname and validity checks remain on.
    pub fn with_roots(roots: rustls::RootCertStore) -> Result<Self, Error> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.time_provider = Arc::new(rustls::time_provider::DefaultTimeProvider);
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.enable_early_data = false;
        config.resumption = rustls::client::Resumption::disabled();
        Ok(Self {
            config: Arc::new(config),
        })
    }
}

/// Original actual nonfatal socket configuration diagnostic, with its probe id.
#[derive(Debug)]
pub struct SocketDiagnostic {
    /// Original native connection attempt number.
    pub probe: usize,
    /// Actual native error, without URL or authentication bytes.
    pub diagnostic: gnunet_native::network::Diagnostic,
}
struct Leased {
    socket: TcpStream,
    _lookup: Box<dyn ConnectionLease>,
}
impl AsyncRead for Leased {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}
impl AsyncWrite for Leased {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.socket).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin {}
impl<T: AsyncRead + AsyncWrite + Unpin> Io for T {}
pub(crate) type Socket = Box<dyn Io>;
pub(crate) fn copy(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| Fault::Capacity)?;
    out.extend_from_slice(bytes);
    Ok(Zeroizing::new(out))
}
fn nibble(b: u8) -> Result<u8, Error> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(Fault::Malformed.into()),
    }
}
pub(crate) fn unescape(input: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut out = copy(input)?;
    let mut read = 0;
    let mut write = 0;
    while read < input.len() {
        let b = if input[read] == b'%' {
            let a = *input.get(read + 1).ok_or(Fault::Malformed)?;
            let b = *input.get(read + 2).ok_or(Fault::Malformed)?;
            read += 3;
            (nibble(a)? << 4) | nibble(b)?
        } else {
            read += 1;
            input[read - 1]
        };
        if b == 0 {
            return Err(Fault::InvalidInput.into());
        }
        out[write] = b;
        write += 1
    }
    out[write..].zeroize();
    out.truncate(write);
    Ok(out)
}
pub(crate) fn basic(user: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut raw = copy(user)?;
    raw.try_reserve(password.len() + 1)
        .map_err(|_| Fault::Capacity)?;
    raw.push(b':');
    raw.extend_from_slice(password);
    let n = raw
        .len()
        .checked_add(2)
        .and_then(|n| n.checked_div(3))
        .and_then(|n| n.checked_mul(4))
        .and_then(|n| n.checked_add(6))
        .ok_or(Fault::Overflow)?;
    let mut out = Vec::new();
    out.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    out.extend_from_slice(b"Basic ");
    for part in raw.chunks(3) {
        let a = part[0];
        let b = part.get(1).copied().unwrap_or(0);
        let c = part.get(2).copied().unwrap_or(0);
        out.push(TABLE[usize::from(a >> 2)]);
        out.push(TABLE[usize::from((a & 3) << 4 | b >> 4)]);
        out.push(if part.len() > 1 {
            TABLE[usize::from((b & 15) << 2 | c >> 6)]
        } else {
            b'='
        });
        out.push(if part.len() > 2 {
            TABLE[usize::from(c & 63)]
        } else {
            b'='
        });
    }
    Ok(Zeroizing::new(out))
}
/// Validate an actual configured/advertised HTTP(S) URL using the mature parser.
/// No username, password, query, or path is included in the returned diagnostics.
pub fn validate_uri(input: &[u8]) -> Result<Url, Error> {
    if input.len() > 8192 || input.iter().any(|b| *b <= 0x20 || *b == 0x7f) {
        return Err(Fault::Capacity.into());
    }
    let url = Url::parse(std::str::from_utf8(input).map_err(|_| Fault::InvalidInput)?)?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(Fault::Unsupported.into());
    }
    Ok(url)
}

async fn acknowledge<T, F: Future<Output = Result<T, Error>>>(
    lookup: &mut dyn AddressLookup,
    future: F,
) -> Result<T, Error> {
    let mut future = Box::pin(future);
    let mut acknowledged = false;
    poll_fn(|cx| {
        let result = future.as_mut().poll(cx);
        if !acknowledged {
            lookup.address_effect_done()?;
            acknowledged = true;
        }
        result
    })
    .await
}
async fn tcp(
    resolution: &SharedResolution,
    host: &str,
    port: u16,
    lease: Rc<IoLease>,
    counts: Arc<Counters>,
    limits: HttpLimits,
) -> Result<Socket, Error> {
    lease.check()?;
    let timeout = lease.hard.get().saturating_duration_since(Instant::now());
    let mut lookup = resolution
        .lookup(host.as_bytes(), timeout)?
        .ok_or(Fault::Unavailable)?;
    let mut last = None;
    loop {
        let address = poll_fn(|cx| lookup.poll_next(cx)).await?;
        let Some(address) = address else {
            return Err(last
                .unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "shared Resolver returned no address",
                    )
                })
                .into());
        };
        lease.check()?;
        counts
            .probes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                (used < limits.probes).then(|| used + 1)
            })
            .map_err(|_| Fault::Capacity)?;
        let attempt = async {
            TcpStream::connect(SocketAddr::new(address, port))
                .await
                .map_err(Error::Io)
        };
        match acknowledge(&mut *lookup, attempt).await {
            Ok(socket) => {
                use std::os::fd::AsFd;
                let diagnostics = match gnunet_native::network::initialize_reactor_stream(
                    socket.as_fd(),
                    gnunet_native::network::StreamKind::Tcp,
                ) {
                    Ok(diagnostics) => diagnostics,
                    Err(error) => {
                        drop(socket);
                        return Err(Error::Initialization(error));
                    }
                };
                if !diagnostics.is_empty() {
                    let mut retained = counts.diagnostics.lock().map_err(|_| Fault::Conflict)?;
                    for diagnostic in diagnostics {
                        retained.push(SocketDiagnostic {
                            probe: counts.probes.load(Ordering::Relaxed),
                            diagnostic,
                        });
                    }
                }
                let retained = lookup.connected()?;
                return Ok(Box::new(Counted {
                    inner: Leased {
                        socket,
                        _lookup: retained,
                    },
                    lease,
                    counts,
                    maximum: limits.wire_bytes,
                }));
            }
            Err(Error::Io(error)) => last = Some(error),
            Err(error) => return Err(error),
        }
        cooperate().await;
    }
}
async fn encrypted(socket: Socket, host: &str, tls: &Tls) -> Result<Socket, Error> {
    let name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|_| Fault::InvalidInput)?;
    let result = tokio_rustls::TlsConnector::from(tls.config.clone())
        .connect(name, socket)
        .await;
    result
        .map(|socket| Box::new(socket) as Socket)
        .map_err(Error::Io)
}
async fn proxy_socket(
    proxy: &Proxy,
    resolution: &SharedResolution,
    tls: &Tls,
    lease: Rc<IoLease>,
    counts: Arc<Counters>,
    limits: HttpLimits,
) -> Result<Socket, Error> {
    let endpoint =
        Url::parse(std::str::from_utf8(&proxy.endpoint).map_err(|_| Fault::InvalidInput)?)?;
    let host = hostname(&endpoint)?;
    let port = endpoint.port().unwrap_or(1080);
    let socket = tcp(resolution, &host, port, lease, counts, limits).await?;
    if endpoint.scheme() == "https" {
        encrypted(socket, &host, tls).await
    } else {
        Ok(socket)
    }
}

async fn socks5_auth(socket: &mut Socket, proxy: &Proxy) -> Result<(), Error> {
    if proxy.username.len() > 255 || proxy.password.len() > 255 {
        return Err(Fault::Capacity.into());
    }
    let authenticated = !proxy.username.is_empty() || !proxy.password.is_empty();
    let method = if authenticated { 2 } else { 0 };
    socket.write_all(&[5, 1, method]).await?;
    let mut selected = [0; 2];
    socket.read_exact(&mut selected).await?;
    if selected != [5, method] {
        return Err(Fault::Authentication.into());
    }
    if authenticated {
        let mut auth = Zeroizing::new(Vec::new());
        auth.try_reserve_exact(3 + proxy.username.len() + proxy.password.len())
            .map_err(|_| Fault::Capacity)?;
        auth.extend_from_slice(&[1, proxy.username.len() as u8]);
        auth.extend_from_slice(&proxy.username);
        auth.push(proxy.password.len() as u8);
        auth.extend_from_slice(&proxy.password);
        socket.write_all(&auth).await?;
        let mut result = [0; 2];
        socket.read_exact(&mut result).await?;
        if result != [1, 0] {
            return Err(Fault::Authentication.into());
        }
    }
    Ok(())
}
async fn socks(
    socket: &mut Socket,
    proxy: &Proxy,
    host: &str,
    port: u16,
    address: Option<IpAddr>,
) -> Result<(), Error> {
    let version4 = matches!(proxy.kind, ProxyKind::Socks4 | ProxyKind::Socks4a);
    if proxy.username.len() > 255 || proxy.password.len() > 255 || host.len() > 255 {
        return Err(Fault::Capacity.into());
    }
    if version4 {
        let mut packet = Zeroizing::new(Vec::new());
        packet
            .try_reserve_exact(9 + 255 + 256)
            .map_err(|_| Fault::Capacity)?;
        packet.extend_from_slice(&[4, 1]);
        packet.extend_from_slice(&port.to_be_bytes());
        match address {
            Some(IpAddr::V4(ip)) => packet.extend_from_slice(&ip.octets()),
            None => packet.extend_from_slice(&[0, 0, 0, 1]),
            _ => return Err(Fault::Unsupported.into()),
        }
        packet.extend_from_slice(&proxy.username);
        packet.push(0);
        if address.is_none() {
            packet.extend_from_slice(host.as_bytes());
            packet.push(0)
        }
        socket.write_all(&packet).await?;
        let mut reply = [0; 8];
        socket.read_exact(&mut reply).await?;
        if reply[0] != 0 {
            return Err(Fault::Malformed.into());
        }
        if reply[1] != 90 {
            return Err(Fault::Unavailable.into());
        }
        return Ok(());
    }
    let mut packet = Zeroizing::new(Vec::new());
    packet
        .try_reserve_exact(4 + 1 + 255 + 2)
        .map_err(|_| Fault::Capacity)?;
    packet.extend_from_slice(&[5, 1, 0]);
    match address {
        Some(IpAddr::V4(ip)) => {
            packet.push(1);
            packet.extend_from_slice(&ip.octets())
        }
        Some(IpAddr::V6(ip)) => {
            packet.push(4);
            packet.extend_from_slice(&ip.octets())
        }
        None => {
            packet.extend_from_slice(&[3, host.len() as u8]);
            packet.extend_from_slice(host.as_bytes())
        }
    }
    packet.extend_from_slice(&port.to_be_bytes());
    socket.write_all(&packet).await?;
    let mut head = [0; 4];
    socket.read_exact(&mut head).await?;
    if head[0] != 5 || head[2] != 0 {
        return Err(Fault::Malformed.into());
    }
    if head[1] != 0 {
        return Err(Fault::Unavailable.into());
    }
    let length = match head[3] {
        1 => 4,
        4 => 16,
        3 => usize::from(socket.read_u8().await?),
        _ => return Err(Fault::Malformed.into()),
    };
    let mut tail = [0; 257];
    socket.read_exact(&mut tail[..length + 2]).await?;
    Ok(())
}

async fn connect_tunnel(
    socket: &mut Socket,
    proxy: &Proxy,
    target: &Url,
    limit: usize,
) -> Result<(), Error> {
    let authority = authority(target, true)?;
    let version = if proxy.kind == ProxyKind::Http10 {
        "HTTP/1.0"
    } else {
        "HTTP/1.1"
    };
    let mut request = Zeroizing::new(
        format!("CONNECT {authority} {version}\r\nHost: {authority}\r\n").into_bytes(),
    );
    if !proxy.username.is_empty() || !proxy.password.is_empty() {
        let auth = basic(&proxy.username, &proxy.password)?;
        request.extend_from_slice(b"Proxy-Authorization: ");
        request.extend_from_slice(&auth);
        request.extend_from_slice(b"\r\n")
    }
    request.extend_from_slice(b"\r\n");
    socket.write_all(&request).await?;
    // Read exactly through the CONNECT headers, without swallowing TLS bytes
    // that may immediately follow them. Limits also bound malformed proxy work.
    let mut response = Zeroizing::new(Vec::new());
    response
        .try_reserve_exact(limit)
        .map_err(|_| Fault::Capacity)?;
    loop {
        if response.len() >= limit {
            return Err(Fault::Capacity.into());
        }
        response.push(socket.read_u8().await?);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
        if response.len().is_multiple_of(256) {
            cooperate().await
        }
    }
    let text = std::str::from_utf8(&response).map_err(|_| Fault::Malformed)?;
    let line = text.split("\r\n").next().ok_or(Fault::Malformed)?;
    let mut pieces = line.split(' ');
    if !matches!(pieces.next(), Some("HTTP/1.0" | "HTTP/1.1")) || pieces.next() != Some("200") {
        return Err(Fault::Unavailable.into());
    }
    for header in text.split("\r\n").skip(1).filter(|s| !s.is_empty()) {
        if !header.contains(':') || header.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
            return Err(Fault::Malformed.into());
        }
    }
    Ok(())
}
pub(crate) fn authority(url: &Url, always_port: bool) -> Result<String, Error> {
    let host = match url.host().ok_or(Fault::InvalidInput)? {
        url::Host::Ipv6(ip) => format!("[{ip}]"),
        host => host.to_string(),
    };
    let port = if always_port {
        Some(url.port_or_known_default().ok_or(Fault::InvalidInput)?)
    } else {
        url.port()
    };
    Ok(if let Some(port) = port {
        format!("{host}:{port}")
    } else {
        host
    })
}
fn hostname(url: &Url) -> Result<std::borrow::Cow<'_, str>, Error> {
    match url.host().ok_or(Fault::InvalidInput)? {
        url::Host::Domain(host) => Ok(std::borrow::Cow::Borrowed(host)),
        url::Host::Ipv4(ip) => Ok(std::borrow::Cow::Owned(ip.to_string())),
        url::Host::Ipv6(ip) => Ok(std::borrow::Cow::Owned(ip.to_string())),
    }
}

pub(crate) async fn socket(
    url: &Url,
    proxy: Option<&Proxy>,
    resolution: &SharedResolution,
    tls: &Tls,
    lease: Rc<IoLease>,
    counts: Arc<Counters>,
    limits: HttpLimits,
) -> Result<(Socket, bool), Error> {
    let host = hostname(url)?;
    let port = url.port_or_known_default().ok_or(Fault::InvalidInput)?;
    let mut socket = if let Some(proxy) = proxy {
        if matches!(proxy.kind, ProxyKind::Http | ProxyKind::Http10) {
            let mut io = proxy_socket(
                proxy,
                resolution,
                tls,
                lease.clone(),
                counts.clone(),
                limits,
            )
            .await?;
            if url.scheme() == "https" {
                connect_tunnel(&mut io, proxy, url, limits.header_bytes).await?;
            }
            io
        } else if matches!(proxy.kind, ProxyKind::Socks4a | ProxyKind::Socks5Hostname) {
            let mut io = proxy_socket(
                proxy,
                resolution,
                tls,
                lease.clone(),
                counts.clone(),
                limits,
            )
            .await?;
            if proxy.kind == ProxyKind::Socks5Hostname {
                socks5_auth(&mut io, proxy).await?
            }
            let address = match url.host() {
                Some(url::Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
                Some(url::Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
                _ => None,
            };
            socks(&mut io, proxy, &host, port, address).await?;
            io
        } else {
            // Proxy lookup/socket effects happen separately before taking each
            // target callback. Never hold an unused target callback while doing
            // another Resolver/native connection attempt.
            let first_io = proxy_socket(
                proxy,
                resolution,
                tls,
                lease.clone(),
                counts.clone(),
                limits,
            )
            .await?;
            let mut initial = Some(first_io);
            let timeout = lease.hard.get().saturating_duration_since(Instant::now());
            let mut lookup = if proxy.kind == ProxyKind::Socks4 {
                resolution.lookup_ipv4(host.as_bytes(), timeout)?
            } else {
                resolution.lookup(host.as_bytes(), timeout)?
            }
            .ok_or(Fault::Unavailable)?;
            loop {
                let mut io = match initial.take() {
                    Some(io) => io,
                    None => {
                        proxy_socket(
                            proxy,
                            resolution,
                            tls,
                            lease.clone(),
                            counts.clone(),
                            limits,
                        )
                        .await?
                    }
                };
                if proxy.kind == ProxyKind::Socks5 {
                    socks5_auth(&mut io, proxy).await?
                }
                let address = poll_fn(|cx| lookup.poll_next(cx))
                    .await?
                    .ok_or(Fault::Unavailable)?;
                let result = acknowledge(
                    &mut *lookup,
                    socks(&mut io, proxy, &host, port, Some(address)),
                )
                .await;
                match result {
                    Ok(()) => {
                        let drain = lookup.connected()?;
                        break Box::new(KeepLookup {
                            inner: io,
                            _lookup: drain,
                        }) as Socket;
                    }
                    Err(Error::Fault(Fault::Unavailable)) => {
                        drop(io);
                        cooperate().await;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    } else {
        tcp(resolution, &host, port, lease, counts, limits).await?
    };
    if url.scheme() == "https" {
        socket = encrypted(socket, &host, tls).await?
    }
    Ok((
        socket,
        proxy.is_some_and(|p| matches!(p.kind, ProxyKind::Http | ProxyKind::Http10))
            && url.scheme() == "http",
    ))
}
struct KeepLookup {
    inner: Socket,
    _lookup: Box<dyn ConnectionLease>,
}
impl AsyncRead for KeepLookup {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for KeepLookup {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
