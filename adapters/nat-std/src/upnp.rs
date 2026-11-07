//! Actual Rust IGD discovery/control. SSDP is unauthenticated LAN input, SOAP
//! success is a router claim of local mapping state, never remote reachability.
//! No miniupnpc/external-ip/C helper subprocess or private NAT protocol is used.
use crate::{
    Error as HostError,
    deadline::Gate,
    http::{self, Url, Written},
};
use gnunet_client_host::resolution::SharedResolution;
use gnunet_types::Error as Fault;
use quick_xml::{NsReader, events::Event, name::ResolveResult};
use std::{
    cell::Cell,
    fmt,
    net::{Ipv4Addr, SocketAddr},
    rc::Rc,
    time::Duration,
};
use tokio::{net::UdpSocket, time::Instant};
mod selection;
pub use selection::{
    ReadFailure, ReadObservations, ReadStage, ReadTarget, Selected, SelectionReport,
    select_from_locations,
};
/// Explicit finite discovery/HTTP/XML resources for one original job.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// HTTP wire/body/header/address caps.
    pub http: http::Limits,
    /// Maximum distinct actual SSDP locations.
    pub devices: usize,
    /// Maximum supported service entries parsed per description and maximum
    /// distinct WAN service/control candidates for the whole original discovery.
    pub services: usize,
    /// Maximum datagrams examined, including invalid/duplicates.
    pub datagrams: usize,
    /// Original fixed SSDP response window.
    pub discovery_window: Duration,
    /// Maximum XML element nesting.
    pub xml_depth: usize,
    /// Maximum total XML events/work.
    pub xml_events: usize,
    /// Maximum attributes on one element.
    pub xml_attributes: usize,
    /// Maximum live XML namespace bindings.
    pub xml_namespaces: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            http: http::Limits::default(),
            devices: 8,
            services: 32,
            datagrams: 64,
            discovery_window: Duration::from_secs(3),
            xml_depth: 64,
            xml_events: 32768,
            xml_attributes: 32,
            xml_namespaces: 256,
        }
    }
}
/// Actual original error. SOAP fault codes remain intact and are not fabricated
/// into a successful mapping or guessed from HTTP error status alone.
#[derive(Debug)]
pub enum Error {
    /// Original shared clock/native/protocol cause.
    Host(HostError),
    /// Original mature XML-parser error.
    Xml(quick_xml::Error),
    /// Original malformed XML attribute error.
    Attribute(quick_xml::events::attributes::AttrError),
    /// Actual HTTP status without a valid SOAP success/fault.
    Http(u16),
    /// Actual SOAP error code and bounded public description.
    Soap {
        /// Actual UPnP errorCode.
        code: u16,
        /// Actual public router description.
        description: String,
    },
    /// Fully received SOAP facts and an independent post-response guard failure.
    PostResponse {
        /// Pure bounded response classification, never overall job success.
        result: Result<(), Box<Error>>,
        /// First actual guard/observation failure after complete framing.
        cause: HostError,
    },
}
impl From<HostError> for Error {
    fn from(e: HostError) -> Self {
        Self::Host(e)
    }
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Host(e.into())
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Host(e.into())
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host(e) => e.fmt(f),
            Self::Xml(e) => write!(f, "IGD XML: {e}"),
            Self::Attribute(e) => write!(f, "IGD XML attribute: {e}"),
            Self::Http(n) => write!(f, "IGD HTTP status{n}"),
            Self::Soap { code, description } => write!(f, "IGD SOAP{code}: {description}"),
            Self::PostResponse { result, cause } => {
                write!(f, "IGD received {result:?}; post-response guard: {cause}")
            }
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Host(e) => Some(e),
            Self::Xml(e) => Some(e),
            Self::Attribute(e) => Some(e),
            Self::PostResponse { cause, .. } => Some(cause),
            _ => None,
        }
    }
}
fn string(s: &str, max: usize) -> Result<String, Error> {
    if s.len() > max {
        return Err(Fault::TooLarge.into());
    }
    let mut v = String::new();
    v.try_reserve_exact(s.len()).map_err(|_| Fault::Capacity)?;
    v.push_str(s);
    Ok(v)
}
fn append(out: &mut String, s: &str, max: usize) -> Result<(), Error> {
    if s.len() > max.saturating_sub(out.len()) {
        return Err(Fault::TooLarge.into());
    }
    out.try_reserve(s.len()).map_err(|_| Fault::Capacity)?;
    out.push_str(s);
    Ok(())
}
fn valid_text(s: &str) -> bool {
    s.chars()
        .all(|c| matches!(c, '\t' | '\n' | '\r') || c >= ' ' && c != '\u{fffe}' && c != '\u{ffff}')
}
trait Visitor {
    fn start(&mut self, path: &[String], namespace: Option<&str>) -> Result<(), Error>;
    fn text(&mut self, path: &[String], text: &str) -> Result<(), Error>;
    fn end(&mut self, path: &[String]) -> Result<(), Error>;
}
fn walk(bytes: &[u8], limits: Limits, visitor: &mut impl Visitor) -> Result<(), Error> {
    if bytes.len() > limits.http.body || limits.xml_depth == 0 || limits.xml_events == 0 {
        return Err(Fault::TooLarge.into());
    }
    let input = core::str::from_utf8(bytes).map_err(|_| Fault::Unsupported)?;
    let mut reader = NsReader::from_str(input);
    reader.config_mut().check_end_names = true;
    reader.config_mut().check_comments = true;
    reader.config_mut().expand_empty_elements = true;
    reader
        .resolver_mut()
        .set_max_namespace_bindings(limits.xml_namespaces);
    let mut path = Vec::new();
    path.try_reserve_exact(limits.xml_depth)
        .map_err(|_| Fault::Capacity)?;
    let mut roots = 0usize;
    let mut ended = false;
    for _ in 0..limits.xml_events {
        let (namespace, event) = reader.read_resolved_event().map_err(Error::Xml)?;
        let ns = match namespace {
            ResolveResult::Bound(n) => Some(n.into_inner()),
            ResolveResult::Unbound => None,
            ResolveResult::Unknown(_) => return Err(Fault::Malformed.into()),
        };
        match event {
            Event::Start(e) => {
                if path.len() >= limits.xml_depth {
                    return Err(Fault::TooLarge.into());
                }
                if path.is_empty() {
                    roots += 1;
                    if roots != 1 || ended {
                        return Err(Fault::Malformed.into());
                    }
                }
                let mut attrs = 0usize;
                for a in e.attributes() {
                    a.map_err(Error::Attribute)?;
                    attrs += 1;
                    if attrs > limits.xml_attributes {
                        return Err(Fault::TooLarge.into());
                    }
                }
                let name = e.local_name();
                path.push(string(name.as_ref(), 128)?);
                visitor.start(&path, ns)?;
            }
            Event::End(_) => {
                if path.is_empty() {
                    return Err(Fault::Malformed.into());
                }
                visitor.end(&path)?;
                path.pop();
                if path.is_empty() {
                    ended = true;
                }
            }
            Event::Text(text) => {
                let text = text.as_ref();
                if !valid_text(text) {
                    return Err(Fault::Malformed.into());
                }
                if path.is_empty() {
                    if !text.trim().is_empty() {
                        return Err(Fault::Malformed.into());
                    }
                } else {
                    visitor.text(&path, text)?;
                }
            }
            Event::CData(text) => {
                let text = text.as_ref();
                if path.is_empty() || !valid_text(text) {
                    return Err(Fault::Malformed.into());
                }
                visitor.text(&path, text)?;
            }
            Event::GeneralRef(reference) => {
                if path.is_empty() {
                    return Err(Fault::Malformed.into());
                }
                let c = match reference.resolve_char_ref().map_err(Error::Xml)? {
                    Some(c) => c,
                    None => match reference.as_ref() {
                        "amp" => '&',
                        "lt" => '<',
                        "gt" => '>',
                        "apos" => '\'',
                        "quot" => '"',
                        _ => return Err(Fault::Unsupported.into()),
                    },
                };
                let mut bytes = [0; 4];
                let value = c.encode_utf8(&mut bytes);
                if !valid_text(value) {
                    return Err(Fault::Malformed.into());
                }
                visitor.text(&path, value)?;
            }
            Event::Decl(d) => {
                if !path.is_empty() || roots != 0 {
                    return Err(Fault::Malformed.into());
                }
                if let Some(encoding) = d.encoding() {
                    let encoding = encoding.map_err(Error::Attribute)?;
                    if !encoding.eq_ignore_ascii_case("UTF-8")
                        && !encoding.eq_ignore_ascii_case("US-ASCII")
                    {
                        return Err(Fault::Unsupported.into());
                    }
                    if encoding.eq_ignore_ascii_case("US-ASCII") && !input.is_ascii() {
                        return Err(Fault::Malformed.into());
                    }
                }
            }
            Event::DocType(_) | Event::PI(_) => return Err(Fault::Unsupported.into()),
            Event::Eof => {
                if !path.is_empty() || roots != 1 {
                    return Err(Fault::Malformed.into());
                }
                return Ok(());
            }
            Event::Comment(_) => {}
            Event::Empty(_) => return Err(Fault::Malformed.into()),
        }
    }
    Err(Fault::Capacity.into())
}
/// One actual descriptor-derived IGD service/control candidate. Connection
/// selection is a separate read-only step; this grants no remote identity.
#[derive(Clone, Debug)]
pub struct Device {
    location: Url,
    control: Url,
    service: String,
}
impl Device {
    /// Actual descriptor endpoint.
    pub fn location(&self) -> &Url {
        &self.location
    }
    /// Actual control endpoint.
    pub fn control(&self) -> &Url {
        &self.control
    }
    /// Exact supported WAN service URN.
    pub fn service_type(&self) -> &str {
        &self.service
    }
}
struct Description {
    base: String,
    service_depth: Option<usize>,
    current_type: String,
    current_control: String,
    services: Vec<(String, String)>,
    limit: usize,
}
fn supported_service(s: &str) -> bool {
    matches!(
        s,
        "urn:schemas-upnp-org:service:WANIPConnection:1"
            | "urn:schemas-upnp-org:service:WANIPConnection:2"
            | "urn:schemas-upnp-org:service:WANPPPConnection:1"
            | "urn:schemas-upnp-org:service:WANPPPConnection:2"
    )
}
impl Visitor for Description {
    fn start(&mut self, path: &[String], _: Option<&str>) -> Result<(), Error> {
        if path.last().is_some_and(|s| s == "service") {
            if self.service_depth.is_some() {
                return Err(Fault::Malformed.into());
            }
            self.service_depth = Some(path.len());
            self.current_type.clear();
            self.current_control.clear();
        }
        Ok(())
    }
    fn text(&mut self, path: &[String], text: &str) -> Result<(), Error> {
        match path.last().map(String::as_str) {
            Some("URLBase") if path.len() == 2 => append(&mut self.base, text, 2048)?,
            Some("serviceType") if self.service_depth == Some(path.len() - 1) => {
                append(&mut self.current_type, text, 256)?
            }
            Some("controlURL") if self.service_depth == Some(path.len() - 1) => {
                append(&mut self.current_control, text, 2048)?
            }
            _ => {}
        }
        Ok(())
    }
    fn end(&mut self, path: &[String]) -> Result<(), Error> {
        if self.service_depth == Some(path.len()) && path.last().is_some_and(|s| s == "service") {
            if supported_service(self.current_type.trim())
                && !self.current_control.trim().is_empty()
                && !self.services.iter().any(|(service, control)| {
                    service == self.current_type.trim() && control == self.current_control.trim()
                })
            {
                if self.services.len() >= self.limit {
                    return Err(Fault::TooLarge.into());
                }
                self.services
                    .try_reserve_exact(1)
                    .map_err(|_| Fault::Capacity)?;
                self.services.push((
                    string(self.current_type.trim(), 256)?,
                    string(self.current_control.trim(), 2048)?,
                ));
            }
            self.service_depth = None;
        }
        Ok(())
    }
}
/// Parse all supported service/control candidates under the actual location,
/// retaining descriptor order rather than discarding WANPPP by a version rank.
/// No external entity, DTD, nonUTF8 declaration, unchecked end name or unbounded
/// namespace graph is accepted. An invalid control URL rejects its description.
pub fn descriptor(location: Url, body: &[u8], limits: Limits) -> Result<Vec<Device>, Error> {
    if limits.services == 0 {
        return Err(Fault::InvalidInput.into());
    }
    let mut d = Description {
        base: String::new(),
        service_depth: None,
        current_type: String::new(),
        current_control: String::new(),
        services: Vec::new(),
        limit: limits.services,
    };
    walk(body, limits, &mut d)?;
    if d.services.is_empty() {
        return Err(Fault::NotFound.into());
    }
    let base = if d.base.trim().is_empty() {
        location.clone()
    } else {
        Url::parse(d.base.trim())?
    };
    let mut devices = Vec::new();
    devices
        .try_reserve_exact(d.services.len())
        .map_err(|_| Fault::Capacity)?;
    for (service, relative) in d.services {
        let control = base.join(&relative)?;
        if !devices
            .iter()
            .any(|d: &Device| d.control == control && d.service == service)
        {
            devices.push(Device {
                location: location.clone(),
                control,
                service,
            });
        }
    }
    Ok(devices)
}
fn ssdp_location(packet: &[u8], limit: usize) -> Result<Option<Url>, Error> {
    if packet.len() > limit {
        return Err(Fault::TooLarge.into());
    }
    let text = core::str::from_utf8(packet).map_err(|_| Fault::Malformed)?;
    if !text.ends_with("\r\n\r\n") {
        return Ok(None);
    }
    let mut lines = text.split("\r\n");
    if lines
        .next()
        .is_none_or(|s| !s.starts_with("HTTP/1.1 200 ") && !s.starts_with("HTTP/1.0 200 "))
    {
        return Ok(None);
    }
    let mut location = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or(Fault::Malformed)?;
        if name.eq_ignore_ascii_case("location") {
            let candidate = Url::parse(value.trim())?;
            if location.as_ref().is_some_and(|old| old != &candidate) {
                return Err(Fault::Malformed.into());
            }
            location = Some(candidate);
        }
    }
    Ok(location)
}
/// Actual SSDP query on an explicitly selected interface (None means OS route),
/// then real bounded descriptor/status/address reads select one connected service.
/// Discovery timeout with no results is NotFound, not an UPnP mapping success.
pub async fn discover(
    resolver: &SharedResolution,
    gate: &mut Gate,
    local: Option<Ipv4Addr>,
    observations: ReadObservations,
) -> Result<SelectionReport, Error> {
    observations.begin()?;
    let limits = observations.limits();
    if limits.devices == 0
        || limits.services == 0
        || limits.datagrams == 0
        || limits.discovery_window.is_zero()
    {
        return Err(Fault::InvalidInput.into());
    }
    gate.check()?;
    let socket = gate
        .run(UdpSocket::bind(SocketAddr::new(
            local.unwrap_or(Ipv4Addr::UNSPECIFIED).into(),
            0,
        )))
        .await?;
    socket.set_multicast_ttl_v4(2)?;
    if let Some(local) = local {
        socket2::SockRef::from(&socket).set_multicast_if_v4(&local)?;
    }
    let query=b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
    let destination = SocketAddr::from(([239, 255, 255, 250], 1900));
    let n = gate.run(socket.send_to(query, destination)).await?;
    if n != query.len() {
        return Err(
            std::io::Error::new(std::io::ErrorKind::WriteZero, "short SSDP datagram").into(),
        );
    }
    let until = Instant::now()
        .checked_add(limits.discovery_window)
        .ok_or(Fault::Overflow)?
        .min(gate.bounds().hard);
    let mut locations = Vec::new();
    locations
        .try_reserve_exact(limits.devices)
        .map_err(|_| Fault::Capacity)?;
    let mut buffer = [0u8; 8192];
    for _ in 0..limits.datagrams {
        let received =
            tokio::time::timeout_at(until, gate.run(socket.recv_from(&mut buffer))).await;
        let n = match received {
            Err(_) => break,
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok((n, _))) => n,
        };
        let location = match ssdp_location(&buffer[..n], limits.http.headers) {
            Ok(Some(l)) => l,
            Ok(None) | Err(_) => continue,
        };
        if locations.contains(&location) {
            continue;
        }
        if locations.len() >= limits.devices {
            break;
        }
        locations.push(location);
    }
    gate.check()?;
    Ok(selection::select_locations(resolver, gate, locations, observations).await)
}
struct Soap {
    action: String,
    service: String,
    success_depth: Option<usize>,
    success: bool,
    fault: bool,
    fields: Vec<(String, String)>,
    error_code: String,
    error_description: String,
}
impl Visitor for Soap {
    fn start(&mut self, path: &[String], namespace: Option<&str>) -> Result<(), Error> {
        if path.last().is_some_and(|s| s == "Fault") {
            self.fault = true;
        }
        if path.len() == 3 && path[0] == "Envelope" && path[1] == "Body" && path[2] == self.action {
            if namespace != Some(self.service.as_str()) {
                return Err(Fault::Malformed.into());
            }
            self.success_depth = Some(3);
            self.success = true;
        }
        if self.success_depth == Some(path.len() - 1) {
            if self.fields.len() >= 64 {
                return Err(Fault::TooLarge.into());
            }
            self.fields.try_reserve(1).map_err(|_| Fault::Capacity)?;
            self.fields.push((
                string(path.last().ok_or(Fault::Malformed)?, 128)?,
                String::new(),
            ));
        }
        Ok(())
    }
    fn text(&mut self, path: &[String], text: &str) -> Result<(), Error> {
        if self.fault {
            match path.last().map(String::as_str) {
                Some("errorCode") => append(&mut self.error_code, text, 8)?,
                Some("errorDescription") => append(&mut self.error_description, text, 512)?,
                _ => {}
            }
        }
        if self.success_depth == Some(path.len() - 1)
            && let Some((name, value)) = self.fields.last_mut()
            && path.last() == Some(name)
        {
            append(value, text, 2048)?;
        }
        Ok(())
    }
    fn end(&mut self, path: &[String]) -> Result<(), Error> {
        if self.success_depth == Some(path.len()) {
            self.success_depth = None;
        }
        Ok(())
    }
}
/// Actual SOAP result fields after the original method response was received.
#[derive(Debug)]
pub struct ActionResult {
    fields: Vec<(String, String)>,
}
impl ActionResult {
    /// Borrow one returned parameter; duplicate parameters fail rather than silently choosing one.
    pub fn field(&self, name: &str) -> Result<Option<&str>, Error> {
        let mut matches = self.fields.iter().filter(|(n, _)| n == name);
        let first = matches.next().map(|(_, v)| v.trim());
        if matches.next().is_some() {
            return Err(Fault::Malformed.into());
        }
        Ok(first)
    }
}
fn soap_response(
    response: &http::Response,
    device: &Device,
    action: &str,
    limits: Limits,
) -> Result<ActionResult, Error> {
    let mut soap = Soap {
        action: format!("{action}Response"),
        service: device.service.clone(),
        success_depth: None,
        success: false,
        fault: false,
        fields: Vec::new(),
        error_code: String::new(),
        error_description: String::new(),
    };
    walk(&response.body, limits, &mut soap)?;
    if soap.fault {
        let code = soap
            .error_code
            .trim()
            .parse()
            .map_err(|_| Fault::Malformed)?;
        return Err(Error::Soap {
            code,
            description: soap.error_description,
        });
    }
    if response.status != 200 {
        return Err(Error::Http(response.status));
    }
    if !soap.success {
        return Err(Fault::Malformed.into());
    }
    Ok(ActionResult {
        fields: soap.fields,
    })
}
async fn action(
    resolver: &SharedResolution,
    gate: &mut Gate,
    device: &Device,
    name: &str,
    parameters: &[(&str, String)],
    written: &Written,
    limits: Limits,
) -> Result<ActionResult, Error> {
    action_observed(
        resolver,
        gate,
        device,
        SoapAction { name, parameters },
        written,
        limits,
        &mut |_| {},
    )
    .await?
    .finish()
}
struct SoapAction<'a> {
    name: &'a str,
    parameters: &'a [(&'a str, String)],
}
struct Observed<T> {
    result: Result<T, Error>,
    post_guard: Option<HostError>,
}
impl<T> Observed<T> {
    fn finish(self) -> Result<T, Error> {
        match self.post_guard {
            Some(cause) => Err(Error::PostResponse {
                result: self.result.map(|_| ()).map_err(Box::new),
                cause,
            }),
            None => self.result,
        }
    }
}
async fn action_observed(
    resolver: &SharedResolution,
    gate: &mut Gate,
    device: &Device,
    action: SoapAction<'_>,
    written: &Written,
    limits: Limits,
    observe: &mut impl FnMut(&Result<ActionResult, Error>),
) -> Result<Observed<ActionResult>, Error> {
    let SoapAction { name, parameters } = action;
    if name.len() > 64 || !name.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(Fault::InvalidInput.into());
    }
    let mut body = String::new();
    use std::fmt::Write;
    write!(body,"<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{name} xmlns:u=\"{}\">",device.service).map_err(|_|Fault::Capacity)?;
    for (key, value) in parameters {
        if key.len() > 64 || !key.bytes().all(|b| b.is_ascii_alphanumeric()) || value.len() > 2048 {
            return Err(Fault::InvalidInput.into());
        }
        write!(body, "<{key}>{}</{key}>", quick_xml::escape::escape(value))
            .map_err(|_| Fault::Capacity)?;
    }
    write!(body, "</u:{name}></s:Body></s:Envelope>").map_err(|_| Fault::Capacity)?;
    if body.len() > limits.http.body {
        return Err(Fault::TooLarge.into());
    }
    let soap_action = format!("{}#{name}", device.service);
    let mut parsed = None;
    let mut classify = |response: &http::Response| {
        let result = soap_response(response, device, name, limits);
        observe(&result);
        parsed = Some(result);
    };
    let response = http::exchange_observed(
        resolver,
        gate,
        &device.control,
        Some((&soap_action, body.as_bytes())),
        written,
        limits.http,
        &mut classify,
    )
    .await?;
    Ok(Observed {
        result: parsed.ok_or(Fault::NotReady)?,
        post_guard: response.post_guard,
    })
}
/// Actual TCP/UDP port-mapping protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    /// IPPROTO_TCP6.
    Tcp,
    /// IPPROTO_UDP17.
    Udp,
}
impl Protocol {
    /// Actual IP protocol number.
    pub const fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}
/// Original local mapping identity carried in the standard IGD description.
/// A matching internal endpoint alone does not establish which attempt owns it.
#[derive(Clone, Debug)]
pub struct Ownership([u8; 39]);
impl Ownership {
    fn description(&self) -> String {
        self.0.iter().copied().map(char::from).collect()
    }
}
/// Actual AddPortMapping disposition, separate from HTTP write exposure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddOutcome {
    /// No application request could have reached the router.
    Unexposed,
    /// The router returned an actual SOAP fault for this AddPortMapping.
    KnownRejected,
    /// The router returned actual AddPortMapping success.
    Committed,
    /// Actual request exposure without a valid success or rejection response.
    ExposedUnknown,
}
struct AttemptState {
    ownership: Ownership,
    written: Written,
    disposition: Cell<AddOutcome>,
}
/// One original Add attempt. Clones observe the same actual outcome even when
/// cancellation drops its future after a response but before local admission.
#[derive(Clone)]
pub struct AddAttempt(Rc<AttemptState>);
impl AddAttempt {
    /// Obtain a fresh, unguessable identity before any mapping mutation.
    pub fn new() -> Result<Self, Error> {
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(HostError::Entropy)?;
        let mut description = *b"GNUnet 00000000000000000000000000000000";
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (i, value) in random.into_iter().enumerate() {
            description[7 + 2 * i] = HEX[usize::from(value >> 4)];
            description[8 + 2 * i] = HEX[usize::from(value & 15)];
        }
        Ok(Self(Rc::new(AttemptState {
            ownership: Ownership(description),
            written: Written::default(),
            disposition: Cell::new(AddOutcome::Unexposed),
        })))
    }
    /// Actual response disposition, or conservative native exposure if no
    /// response established either outcome. Exposure is never delete authority.
    pub fn outcome(&self) -> AddOutcome {
        match self.0.disposition.get() {
            AddOutcome::Unexposed if self.0.written.may_have_exposed() => {
                AddOutcome::ExposedUnknown
            }
            outcome => outcome,
        }
    }
    /// Retain this attempt's identity for a separately bounded ownership probe.
    /// It does not assert that the router accepted the mapping.
    pub fn ownership(&self) -> Ownership {
        self.0.ownership.clone()
    }
}
/// Actual router-confirmed mapping inputs. No field asserts remote reachability.
#[derive(Clone, Debug)]
pub struct Mapping {
    device: Device,
    internal: Ipv4Addr,
    internal_port: u16,
    external_port: u16,
    protocol: Protocol,
    lease_seconds: u32,
    ownership: Ownership,
}
impl Mapping {
    /// Original actual control device.
    pub fn device(&self) -> &Device {
        &self.device
    }
    /// Original internal endpoint.
    pub const fn internal(&self) -> (Ipv4Addr, u16) {
        (self.internal, self.internal_port)
    }
    /// Router-confirmed external port.
    pub const fn external_port(&self) -> u16 {
        self.external_port
    }
    /// Original protocol.
    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }
    /// Actual requested lease seconds (0=permanent until removal).
    pub const fn lease_seconds(&self) -> u32 {
        self.lease_seconds
    }
    /// Original attempt identity, retained for ownership-checked cleanup.
    pub fn ownership(&self) -> Ownership {
        self.ownership.clone()
    }
}
/// Actual public external IPv4 claim returned by the selected router.
pub async fn external_ipv4(
    resolver: &SharedResolution,
    gate: &mut Gate,
    device: &Device,
    limits: Limits,
) -> Result<Ipv4Addr, Error> {
    let response = action(
        resolver,
        gate,
        device,
        "GetExternalIPAddress",
        &[],
        &Written::default(),
        limits,
    )
    .await?;
    let ip: Ipv4Addr = response
        .field("NewExternalIPAddress")?
        .ok_or(Fault::Malformed)?
        .parse()
        .map_err(|_| Fault::Malformed)?;
    if ip.is_unspecified() {
        return Err(Fault::Unavailable.into());
    }
    Ok(ip)
}
/// Original requested IGD mapping, distinct from a successful mapping receipt.
#[derive(Clone, Copy, Debug)]
pub struct MappingRequest {
    /// Original internal IPv4 address.
    pub internal: Ipv4Addr,
    /// Original internal port.
    pub internal_port: u16,
    /// Original requested external port.
    pub external_port: u16,
    /// Original transport protocol.
    pub protocol: Protocol,
    /// Requested lease duration in seconds; zero requests a permanent mapping.
    pub lease_seconds: u32,
}
/// Add a real IGD mapping and return a receipt only after actual SOAP success.
/// The caller retains this attempt across cancellation/error. An actual SOAP
/// fault establishes rejection; write exposure alone establishes only uncertainty.
pub async fn add_mapping(
    resolver: &SharedResolution,
    gate: &mut Gate,
    device: &Device,
    request: MappingRequest,
    attempt: &AddAttempt,
    limits: Limits,
) -> Result<Mapping, Error> {
    let MappingRequest {
        internal,
        internal_port,
        external_port,
        protocol,
        lease_seconds,
    } = request;
    if internal.is_unspecified() || internal_port == 0 || external_port == 0 {
        return Err(Fault::InvalidInput.into());
    }
    let parameters = [
        ("NewRemoteHost", String::new()),
        ("NewExternalPort", external_port.to_string()),
        ("NewProtocol", protocol.name().to_string()),
        ("NewInternalPort", internal_port.to_string()),
        ("NewInternalClient", internal.to_string()),
        ("NewEnabled", "1".to_string()),
        (
            "NewPortMappingDescription",
            attempt.0.ownership.description(),
        ),
        ("NewLeaseDuration", lease_seconds.to_string()),
    ];
    let mut classify = |result: &Result<ActionResult, Error>| match result {
        Ok(_) => attempt.0.disposition.set(AddOutcome::Committed),
        Err(Error::Soap { .. }) => attempt.0.disposition.set(AddOutcome::KnownRejected),
        Err(_) => {}
    };
    action_observed(
        resolver,
        gate,
        device,
        SoapAction {
            name: "AddPortMapping",
            parameters: &parameters,
        },
        &attempt.0.written,
        limits,
        &mut classify,
    )
    .await?
    .finish()?;
    gate.check()?;
    Ok(Mapping {
        device: device.clone(),
        internal,
        internal_port,
        external_port,
        protocol,
        lease_seconds,
        ownership: attempt.ownership(),
    })
}
/// Actual cleanup observation, distinct from the original Add outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Removal {
    /// An owned entry was probed and a subsequent DELETE succeeded.
    Removed,
    /// The ownership query reported no entry for the original port/protocol.
    Absent,
    /// The original marker was observed, then DELETE returned SOAP714 absence.
    /// The original Add has already applied; this is distinct from a query
    /// reporting absence before any original ownership could be established.
    OwnedThenAbsent,
    /// An entry exists but its tuple/description does not prove original ownership.
    Unproven,
}
#[derive(Default)]
struct DeleteState {
    written: Written,
    removal: Cell<Option<Removal>>,
}
/// Original cleanup observation shared across final-guard waits/cancellation.
/// Default has no response receipt; only actual bounded SOAP can fill it.
#[derive(Clone, Default)]
pub struct DeleteAttempt(Rc<DeleteState>);
impl DeleteAttempt {
    /// Actual observed removal/absence/unproven entry, independent of whether
    /// the cleanup job subsequently passed its original post-response guard.
    pub fn removal(&self) -> Option<Removal> {
        self.0.removal.get()
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Presence {
    Owned,
    Absent,
    Unproven,
}
/// Remove only a router-observed entry with the original internal tuple and
/// unguessable attempt identity. SOAP714 is observed absence. A foreign or
/// unverifiable entry is never deleted. IGD has no atomic compare-and-delete;
/// this probe does not claim protection from a subsequent router-side replacement.
pub async fn delete_mapping(
    resolver: &SharedResolution,
    gate: &mut Gate,
    device: &Device,
    request: MappingRequest,
    ownership: &Ownership,
    attempt: &DeleteAttempt,
    limits: Limits,
) -> Result<Removal, Error> {
    let mut queried = |presence| match presence {
        Presence::Owned => {}
        Presence::Absent => attempt.0.removal.set(Some(Removal::Absent)),
        Presence::Unproven => attempt.0.removal.set(Some(Removal::Unproven)),
    };
    match query_ownership_observed(
        resolver,
        gate,
        device,
        request,
        ownership,
        limits,
        &mut queried,
    )
    .await?
    .finish()?
    {
        Presence::Owned => {}
        Presence::Absent => return Ok(Removal::Absent),
        Presence::Unproven => return Ok(Removal::Unproven),
    }
    let parameters = [
        ("NewRemoteHost", String::new()),
        ("NewExternalPort", request.external_port.to_string()),
        ("NewProtocol", request.protocol.name().to_string()),
    ];
    let mut classify = |result: &Result<ActionResult, Error>| match result {
        Ok(_) => attempt.0.removal.set(Some(Removal::Removed)),
        Err(Error::Soap { code: 714, .. }) => attempt.0.removal.set(Some(Removal::OwnedThenAbsent)),
        Err(_) => {}
    };
    let observed = action_observed(
        resolver,
        gate,
        device,
        SoapAction {
            name: "DeletePortMapping",
            parameters: &parameters,
        },
        &attempt.0.written,
        limits,
        &mut classify,
    )
    .await?;
    Observed {
        result: match observed.result {
            Ok(_) => Ok(Removal::Removed),
            Err(Error::Soap { code: 714, .. }) => Ok(Removal::OwnedThenAbsent),
            Err(e) => Err(e),
        },
        post_guard: observed.post_guard,
    }
    .finish()
}
/// Query the actual original mapping before renewal/publication. No cache row
/// is treated as router evidence and source/session authority is not inferred.
pub async fn query_mapping(
    resolver: &SharedResolution,
    gate: &mut Gate,
    mapping: &Mapping,
    limits: Limits,
) -> Result<bool, Error> {
    Ok(query_ownership(
        resolver,
        gate,
        &mapping.device,
        MappingRequest {
            internal: mapping.internal,
            internal_port: mapping.internal_port,
            external_port: mapping.external_port,
            protocol: mapping.protocol,
            lease_seconds: mapping.lease_seconds,
        },
        &mapping.ownership,
        limits,
    )
    .await?
        == Presence::Owned)
}
async fn query_ownership(
    resolver: &SharedResolution,
    gate: &mut Gate,
    device: &Device,
    request: MappingRequest,
    ownership: &Ownership,
    limits: Limits,
) -> Result<Presence, Error> {
    query_ownership_observed(
        resolver,
        gate,
        device,
        request,
        ownership,
        limits,
        &mut |_| {},
    )
    .await?
    .finish()
}
fn presence(
    response: &ActionResult,
    request: MappingRequest,
    ownership: &Ownership,
) -> Result<Presence, Error> {
    let internal: Ipv4Addr = response
        .field("NewInternalClient")?
        .ok_or(Fault::Malformed)?
        .parse()
        .map_err(|_| Fault::Malformed)?;
    let port: u16 = response
        .field("NewInternalPort")?
        .ok_or(Fault::Malformed)?
        .parse()
        .map_err(|_| Fault::Malformed)?;
    let enabled = response.field("NewEnabled")?.ok_or(Fault::Malformed)?;
    let description = response.field("NewPortMappingDescription")?;
    Ok(
        if internal == request.internal
            && port == request.internal_port
            && matches!(enabled, "1" | "true" | "yes")
            && description.map(str::as_bytes) == Some(ownership.0.as_slice())
        {
            Presence::Owned
        } else {
            Presence::Unproven
        },
    )
}
async fn query_ownership_observed(
    resolver: &SharedResolution,
    gate: &mut Gate,
    device: &Device,
    request: MappingRequest,
    ownership: &Ownership,
    limits: Limits,
    observe: &mut impl FnMut(Presence),
) -> Result<Observed<Presence>, Error> {
    if request.internal.is_unspecified() || request.internal_port == 0 || request.external_port == 0
    {
        return Err(Fault::InvalidInput.into());
    }
    let parameters = [
        ("NewRemoteHost", String::new()),
        ("NewExternalPort", request.external_port.to_string()),
        ("NewProtocol", request.protocol.name().to_string()),
    ];
    let mut parsed = None;
    let mut classify = |result: &Result<ActionResult, Error>| {
        let result = match result {
            Ok(response) => Some(presence(response, request, ownership)),
            Err(Error::Soap { code: 714, .. }) => Some(Ok(Presence::Absent)),
            Err(_) => None,
        };
        if let Some(Ok(presence)) = &result {
            observe(*presence);
        }
        parsed = result;
    };
    let response = action_observed(
        resolver,
        gate,
        device,
        SoapAction {
            name: "GetSpecificPortMappingEntry",
            parameters: &parameters,
        },
        &Written::default(),
        limits,
        &mut classify,
    )
    .await?;
    let result = match response.result {
        Ok(_) | Err(Error::Soap { code: 714, .. }) => parsed.ok_or(Fault::NotReady)?,
        Err(error) => Err(error),
    };
    Ok(Observed {
        result,
        post_guard: response.post_guard,
    })
}
