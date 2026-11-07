//! Bounded ordinary HTTP metadata transformation; no private body is collected.
use super::{Limits, View};
use crate::Error;
use gnunet_types::Error as Fault;
use hyper::{
    HeaderMap, Method, Request, Uri,
    header::{self, HeaderName, HeaderValue},
    http::uri::Authority,
};
use std::{net::Ipv6Addr, str::FromStr};
const HOP: [&str; 10] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "http2-settings",
];

pub(super) fn validate(view: &View, limits: Limits) -> Result<(), Error> {
    authority(&view.browser_host, view.port, view.tls, limits)?;
    authority(&view.upstream_host, view.port, view.tls, limits)?;
    Ok(())
}
fn authority(host: &str, port: u16, tls: bool, limits: Limits) -> Result<Authority, Error> {
    if host.is_empty()
        || host.len() > limits.maximum_head_bytes
        || !host.is_ascii()
        || host
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b"/@?#\\\"".contains(&b))
    {
        return Err(Fault::Malformed.into());
    }
    let ipv6 = host.parse::<Ipv6Addr>().is_ok();
    if !ipv6 && (host.contains(':') || host.contains('[') || host.contains(']')) {
        return Err(Fault::Malformed.into());
    }
    let mut value = String::new();
    value
        .try_reserve(host.len().checked_add(8).ok_or(Fault::Overflow)?)
        .map_err(Error::Allocation)?;
    if ipv6 {
        value.push('[');
    }
    value.push_str(host);
    if ipv6 {
        value.push(']');
    }
    if port != if tls { 443 } else { 80 } {
        use std::fmt::Write;
        write!(&mut value, ":{port}").map_err(|_| Fault::Capacity)?;
    }
    Authority::from_str(&value).map_err(|_| Fault::Malformed.into())
}
fn bare_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}
fn origin(uri: &Uri, host: &str, view: &View) -> bool {
    let Some(scheme) = uri.scheme_str() else {
        return false;
    };
    let Some(authority) = uri.authority() else {
        return false;
    };
    !authority.as_str().contains('@')
        && scheme.eq_ignore_ascii_case(if view.tls { "https" } else { "http" })
        && bare_host(authority.host()).eq_ignore_ascii_case(host)
        && match authority.port_u16() {
            Some(port) => port == view.port,
            None => {
                authority.as_str() == authority.host()
                    && (if view.tls { 443 } else { 80 }) == view.port
            }
        }
}
pub(super) fn check_head(headers: &HeaderMap, limits: Limits) -> Result<(), Error> {
    if headers.len() > limits.maximum_headers {
        return Err(Fault::Capacity.into());
    }
    let mut bytes = 0usize;
    for (name, value) in headers {
        bytes = bytes
            .checked_add(name.as_str().len())
            .and_then(|n| n.checked_add(value.as_bytes().len()))
            .and_then(|n| n.checked_add(4))
            .ok_or(Fault::Overflow)?;
        if bytes > limits.maximum_head_bytes {
            return Err(Fault::Capacity.into());
        }
    }
    Ok(())
}
/// Remove hop-by-hop fields including each actual Connection-nominated name.
pub(super) fn strip(headers: &mut HeaderMap, limits: Limits) -> Result<Vec<HeaderName>, Error> {
    check_head(headers, limits)?;
    let mut names = Vec::new();
    for value in headers.get_all(header::CONNECTION) {
        for token in value.as_bytes().split(|b| *b == b',') {
            let token = trim(token);
            if token.is_empty() {
                continue;
            }
            if names.len() == limits.maximum_headers {
                return Err(Fault::Capacity.into());
            }
            let name = HeaderName::from_bytes(token).map_err(|_| Fault::Malformed)?;
            names.try_reserve(1).map_err(Error::Allocation)?;
            names.push(name);
        }
    }
    if headers.contains_key(header::TRANSFER_ENCODING) {
        headers.remove(header::CONTENT_LENGTH);
    }
    strip_named(headers, &names);
    Ok(names)
}
fn strip_named(headers: &mut HeaderMap, names: &[HeaderName]) {
    for name in HOP {
        headers.remove(name);
    }
    for name in names {
        headers.remove(name);
    }
}
pub(super) fn trailers(
    headers: &mut HeaderMap,
    names: &[HeaderName],
    limits: Limits,
) -> Result<(), Error> {
    let own = strip(headers, limits)?;
    strip_named(headers, names);
    strip_named(headers, &own);
    check_head(headers, limits)
}
pub(super) fn request<B>(
    request: &mut Request<B>,
    view: &View,
    limits: Limits,
) -> Result<Vec<HeaderName>, Error> {
    if request.method() == Method::CONNECT || request.headers().contains_key(header::UPGRADE) {
        return Err(Fault::Unsupported.into());
    }
    let uri = request.uri();
    if (uri.scheme().is_some() || uri.authority().is_some())
        && !origin(uri, &view.browser_host, view)
    {
        return Err(Fault::Malformed.into());
    }
    let mut parts = request.uri().clone().into_parts();
    parts.scheme = None;
    parts.authority = None;
    if parts.path_and_query.is_none() {
        parts.path_and_query = Some(hyper::http::uri::PathAndQuery::from_static("/"));
    }
    let path = parts
        .path_and_query
        .as_ref()
        .ok_or(Fault::Malformed)?
        .as_str();
    if !(path.starts_with('/') || (path == "*" && request.method() == Method::OPTIONS)) {
        return Err(Fault::Malformed.into());
    }
    if path.len() > limits.maximum_head_bytes {
        return Err(Fault::Capacity.into());
    }
    *request.uri_mut() = Uri::from_parts(parts).map_err(|_| Fault::Malformed)?;
    let names = strip(request.headers_mut(), limits)?;
    let host = authority(&view.upstream_host, view.port, view.tls, limits)?;
    request
        .headers_mut()
        .try_reserve(2)
        .map_err(|_| Fault::Capacity)?;
    request.headers_mut().insert(
        header::HOST,
        HeaderValue::from_str(host.as_str()).map_err(|_| Fault::Malformed)?,
    );
    // One fresh upstream per request. This hop-local policy is stripped again
    // from its response and never forces the browser's connection to close.
    request
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    check_head(request.headers(), limits)?;
    Ok(names)
}
fn mapped_origin(
    value: &HeaderValue,
    view: &View,
    limits: Limits,
    origin_only: bool,
) -> Result<Option<HeaderValue>, Error> {
    if view.browser_host.eq_ignore_ascii_case(&view.upstream_host) {
        return Ok(None);
    }
    let Ok(text) = value.to_str() else {
        return Ok(None);
    };
    // HTTP Uri is a request-target parser, not a URI-reference parser. Preserve
    // Location's fragment verbatim while parsing its actual absolute origin.
    let (base, fragment) = text
        .split_once('#')
        .map_or((text, None), |(base, fragment)| (base, Some(fragment)));
    let Ok(uri) = Uri::from_str(base) else {
        return Ok(None);
    };
    if !origin(&uri, &view.upstream_host, view) {
        return Ok(None);
    }
    let browser = authority(&view.browser_host, view.port, view.tls, limits)?;
    let result = if origin_only {
        let expected = uri
            .scheme_str()
            .ok_or(Fault::Malformed)?
            .len()
            .checked_add(3)
            .and_then(|n| n.checked_add(uri.authority()?.as_str().len()));
        if fragment.is_some() || expected != Some(text.len()) {
            return Ok(None);
        }
        let mut result = String::new();
        result
            .try_reserve(
                browser
                    .as_str()
                    .len()
                    .checked_add(8)
                    .ok_or(Fault::Overflow)?,
            )
            .map_err(Error::Allocation)?;
        result.push_str(if view.tls { "https://" } else { "http://" });
        result.push_str(browser.as_str());
        result
    } else {
        let mut parts = uri.into_parts();
        parts.authority = Some(browser);
        let mut result = Uri::from_parts(parts)
            .map_err(|_| Fault::Malformed)?
            .to_string();
        if let Some(fragment) = fragment {
            let extra = fragment.len().checked_add(1).ok_or(Fault::Overflow)?;
            if result
                .len()
                .checked_add(extra)
                .is_none_or(|n| n > limits.maximum_head_bytes)
            {
                return Err(Fault::Capacity.into());
            }
            result.try_reserve(extra).map_err(Error::Allocation)?;
            result.push('#');
            result.push_str(fragment);
        }
        result
    };
    if result.len() > limits.maximum_head_bytes {
        return Err(Fault::Capacity.into());
    }
    Ok(Some(
        HeaderValue::from_str(&result).map_err(|_| Fault::Malformed)?,
    ))
}
fn trim(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}
fn domain_match(host: &[u8], domain: &[u8]) -> bool {
    host.eq_ignore_ascii_case(domain)
        || (host.len() > domain.len()
            && host[host.len() - domain.len()..].eq_ignore_ascii_case(domain)
            && host[host.len() - domain.len() - 1] == b'.')
}
fn append(output: &mut Vec<u8>, data: &[u8], cap: usize) -> Result<(), Error> {
    if output.len().checked_add(data.len()).is_none_or(|n| n > cap) {
        return Err(Fault::Capacity.into());
    }
    output.try_reserve(data.len()).map_err(Error::Allocation)?;
    output.extend_from_slice(data);
    Ok(())
}
fn cookie(value: &HeaderValue, view: &View, limits: Limits) -> Result<Option<HeaderValue>, Error> {
    let raw = value.as_bytes();
    if view.browser_host.eq_ignore_ascii_case(&view.upstream_host) {
        return Ok(None);
    }
    if view.browser_host.contains(':') || view.upstream_host.contains(':') {
        return Ok(None);
    }
    let mut output = Vec::new();
    let mut copied = 0;
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    let mut first = true;
    for end in 0..=raw.len() {
        if end < raw.len() {
            let byte = raw[end];
            if escaped {
                escaped = false;
                continue;
            }
            if quoted && byte == b'\\' {
                escaped = true;
                continue;
            }
            if byte == b'"' {
                quoted = !quoted;
                continue;
            }
            if byte != b';' || quoted {
                continue;
            }
        } else if quoted || escaped {
            return Ok(None);
        }
        let attr = &raw[start..end];
        if !first
            && let Some(equal) = attr.iter().position(|b| *b == b'=')
            && trim(&attr[..equal]).eq_ignore_ascii_case(b"domain")
        {
            let actual = trim(&attr[equal + 1..]);
            let (domain, quote) =
                if actual.len() >= 2 && actual[0] == b'"' && actual[actual.len() - 1] == b'"' {
                    (&actual[1..actual.len() - 1], true)
                } else {
                    (actual, false)
                };
            let leading_dot = domain.first() == Some(&b'.');
            let domain = if leading_dot { &domain[1..] } else { domain };
            if !domain.is_empty()
                && domain
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'.')
                && domain_match(view.upstream_host.as_bytes(), domain)
            {
                let leading = attr[equal + 1..]
                    .iter()
                    .take_while(|byte| byte.is_ascii_whitespace())
                    .count();
                let offset = start + equal + 1 + leading;
                append(&mut output, &raw[copied..offset], limits.maximum_head_bytes)?;
                if quote {
                    append(&mut output, b"\"", limits.maximum_head_bytes)?;
                }
                if leading_dot {
                    append(&mut output, b".", limits.maximum_head_bytes)?;
                }
                append(
                    &mut output,
                    view.browser_host.as_bytes(),
                    limits.maximum_head_bytes,
                )?;
                if quote {
                    append(&mut output, b"\"", limits.maximum_head_bytes)?;
                }
                copied = offset + actual.len();
            }
        }
        first = false;
        start = end.saturating_add(1);
    }
    if copied == 0 {
        return Ok(None);
    }
    append(&mut output, &raw[copied..], limits.maximum_head_bytes)?;
    Ok(Some(
        HeaderValue::from_bytes(&output).map_err(|_| Fault::Malformed)?,
    ))
}
fn values(
    headers: &mut HeaderMap,
    name: HeaderName,
    view: &View,
    limits: Limits,
    cookies: bool,
) -> Result<(), Error> {
    let mut values = Vec::new();
    values
        .try_reserve(headers.get_all(&name).iter().count())
        .map_err(Error::Allocation)?;
    values.extend(headers.get_all(&name).iter().cloned());
    headers.remove(&name);
    for value in values {
        let rewritten = if cookies {
            cookie(&value, view, limits)?
        } else {
            mapped_origin(
                &value,
                view,
                limits,
                name == header::ACCESS_CONTROL_ALLOW_ORIGIN,
            )?
        };
        headers.try_reserve(1).map_err(|_| Fault::Capacity)?;
        headers.append(name.clone(), rewritten.unwrap_or(value));
        check_head(headers, limits)?;
    }
    Ok(())
}
pub(super) fn response(
    headers: &mut HeaderMap,
    view: &View,
    limits: Limits,
) -> Result<Vec<HeaderName>, Error> {
    let names = strip(headers, limits)?;
    values(headers, header::LOCATION, view, limits, false)?;
    values(
        headers,
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        view,
        limits,
        false,
    )?;
    values(headers, header::SET_COOKIE, view, limits, true)?;
    Ok(names)
}
