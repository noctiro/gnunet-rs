//! Synchronous system name-service lookup, run in the isolated worker.
use super::super::{Answer, Question};
use gnunet_dns::MAX_NAME_LENGTH;
use gnunet_native::addresses::{self, Hints};
use socket2::SockAddr;
use std::{
    ffi::{CStr, OsStr},
    io,
    net::{IpAddr, SocketAddr},
    ptr,
};

// Bound the native list copy separately from the deduplicated answer count.
const MAX_ADDRINFO_ROWS: usize = 128;

pub(super) fn resolve(question: Question<'_>, limit: usize) -> io::Result<Vec<Answer>> {
    if limit == 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    match question {
        Question::Any(name) => forward(name, libc::AF_UNSPEC, limit),
        Question::A(name) => forward(name, libc::AF_INET, limit),
        Question::Aaaa(name) => forward(name, libc::AF_INET6, limit),
        Question::Ptr(address) => reverse(address),
    }
}

fn forward(name: &str, family: libc::c_int, limit: usize) -> io::Result<Vec<Answer>> {
    let hints = Hints {
        family,
        socket_type: libc::SOCK_STREAM,
        protocol: libc::IPPROTO_TCP,
        flags: 0,
    };
    let results = match addresses::resolve(OsStr::new(name), hints, MAX_ADDRINFO_ROWS) {
        Ok(results) => results,
        Err(addresses::Error::Resolution { code, .. }) if no_name(code) => return Ok(Vec::new()),
        Err(addresses::Error::Io(error)) => return Err(error),
        Err(addresses::Error::Capacity) => return Err(io::ErrorKind::OutOfMemory.into()),
        Err(error) => return Err(io::Error::other(error)),
    };

    let mut answers = Vec::new();
    for result in results {
        let answer = match (family, result.address) {
            (libc::AF_UNSPEC | libc::AF_INET, SocketAddr::V4(address)) => {
                Some(Answer::V4(*address.ip()))
            }
            (libc::AF_UNSPEC | libc::AF_INET6, SocketAddr::V6(address))
                if address.scope_id() == 0 =>
            {
                Answer::unscoped_ipv6(address.ip().octets())
            }
            _ => None,
        };
        if let Some(answer) = answer
            && !answers.contains(&answer)
        {
            if answers.len() == limit {
                return Err(io::ErrorKind::OutOfMemory.into());
            }
            answers
                .try_reserve(1)
                .map_err(|_| io::ErrorKind::OutOfMemory)?;
            answers.push(answer);
        }
    }
    Ok(answers)
}

#[expect(
    unsafe_code,
    reason = "Native getnameinfo reads one live sockaddr and writes the bounded hostname buffer"
)]
fn reverse(address: IpAddr) -> io::Result<Vec<Answer>> {
    let socket = SockAddr::from(SocketAddr::new(address, 0));
    let mut hostname = [0u8; MAX_NAME_LENGTH + 2];
    // SAFETY: SockAddr owns the exact native layout for its family. The output
    // pointer and length cover the initialized hostname buffer, and no service
    // output is requested.
    let status = unsafe {
        libc::getnameinfo(
            socket.as_ptr().cast(),
            socket.len(),
            hostname.as_mut_ptr().cast(),
            hostname.len() as _,
            ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    match status {
        0 => {}
        code if no_name(code) => return Ok(Vec::new()),
        libc::EAI_SYSTEM => return Err(io::Error::last_os_error()),
        code => return Err(io::Error::other(format!("getnameinfo failed ({code})"))),
    }
    let hostname = CStr::from_bytes_until_nul(&hostname)
        .map_err(|_| io::ErrorKind::InvalidData)?
        .to_str()
        .map_err(|_| io::ErrorKind::InvalidData)?;
    if hostname.is_empty() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // A maximum-length absolute DNS name can use the extra byte for its
    // terminal root dot. Preserve the name within the common answer bound.
    let hostname = if hostname.len() > MAX_NAME_LENGTH {
        hostname
            .strip_suffix('.')
            .ok_or(io::ErrorKind::InvalidData)?
    } else {
        hostname
    };
    Ok(vec![Answer::Name(hostname.to_owned())])
}

fn no_name(code: libc::c_int) -> bool {
    if code == libc::EAI_NONAME {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        code == libc::EAI_NODATA
    }
    #[cfg(target_os = "freebsd")]
    {
        false
    }
}
