//! Numeric bootstrap endpoints for raw DNS exchanges.
use super::{DnsLimits, Error, push_server};
use gnunet_native::filesystem::open_regular;
use gnunet_types::Error as Fault;
use std::{
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

const MAX_CONFIG_BYTES: usize = 1024 * 1024;

pub(super) enum Source {
    Fixed(Vec<SocketAddr>),
    Dynamic(Dynamic),
}

pub(super) enum Dynamic {
    File {
        path: PathBuf,
        maximum_bytes: usize,
    },
    #[cfg(windows)]
    Windows,
}

impl Dynamic {
    pub(super) fn file(path: &Path, maximum_bytes: usize) -> Result<Source, Error> {
        if !(1..=MAX_CONFIG_BYTES).contains(&maximum_bytes) {
            return Err(Fault::InvalidInput.into());
        }
        Ok(Source::Dynamic(Self::File {
            path: path.to_path_buf(),
            maximum_bytes,
        }))
    }

    pub(super) fn snapshot(&self, limits: DnsLimits) -> Result<Vec<SocketAddr>, Error> {
        match self {
            Self::File {
                path,
                maximum_bytes,
            } => {
                let file = open_regular(path)?.ok_or(Fault::InvalidInput)?;
                let mut reader =
                    file.take(u64::try_from(*maximum_bytes).map_err(|_| Fault::Overflow)? + 1);
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact((*maximum_bytes).min(4096))
                    .map_err(Error::allocation)?;
                reader.read_to_end(&mut bytes)?;
                if bytes.len() > *maximum_bytes {
                    return Err(Fault::Capacity.into());
                }
                parse(&bytes, limits.port, limits.servers)
            }
            #[cfg(windows)]
            Self::Windows => {
                let mut servers = gnunet_native::dns::servers(gnunet_native::dns::Limits {
                    servers: limits.servers,
                    ..Default::default()
                })?;
                for server in &mut servers {
                    server.set_port(limits.port);
                    super::valid_server(*server)?;
                }
                if servers.is_empty() {
                    return Err(Fault::NotReady.into());
                }
                Ok(servers)
            }
        }
    }
}

pub(super) fn parse(
    input: &[u8],
    default_port: u16,
    maximum_servers: usize,
) -> Result<Vec<SocketAddr>, Error> {
    if default_port == 0 || maximum_servers == 0 || input.len() > MAX_CONFIG_BYTES {
        return Err(Fault::InvalidInput.into());
    }
    let text = std::str::from_utf8(input).map_err(|_| Fault::Malformed)?;
    let mut result = Vec::new();
    for line in text.lines() {
        let line = line.split(['#', ';']).next().unwrap_or("");
        let mut words = line.split_whitespace();
        if !words
            .next()
            .is_some_and(|key| key.eq_ignore_ascii_case("nameserver"))
        {
            continue;
        }
        let value = words.next().ok_or(Fault::Malformed)?;
        let address = if let Ok(ip) = value.parse::<IpAddr>() {
            SocketAddr::new(ip, default_port)
        } else {
            value
                .parse::<SocketAddr>()
                .or_else(|_| format!("[{value}]:{default_port}").parse::<SocketAddr>())
                .map_err(|_| Fault::InvalidInput)?
        };
        push_server(&mut result, address, maximum_servers)?;
    }
    if result.is_empty() {
        return Err(Fault::NotReady.into());
    }
    Ok(result)
}
