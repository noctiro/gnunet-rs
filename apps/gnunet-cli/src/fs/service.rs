//! Streaming service-backed file operations over caller-selected official MQs.
use gnunet::{
    datastore_host::{
        Client, Instance, Limits as NativeLimits, ProtocolClient, ProtocolLimits, ReservationSlot,
        Slot,
    },
    fs::{Limits as UriLimits, Uri},
    fs_host::{Buffers, Control, OutputDir, ipc::EndpointSource, network::DownloadOptions},
    types::AbsoluteTime,
};
use std::{
    error::Error,
    ffi::OsStr,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
};

pub(super) fn duration(value: Option<&impl AsRef<OsStr>>) -> Result<u64, Box<dyn Error>> {
    let seconds = match value {
        Some(value) => value
            .as_ref()
            .to_str()
            .ok_or("timeout must be UTF-8 digits")?
            .parse::<u64>()?,
        None => 300,
    };
    if seconds == 0 {
        return Err("timeout must be positive".into());
    }
    seconds
        .checked_mul(1_000_000)
        .ok_or_else(|| "timeout is too large".into())
}
pub(super) fn target(
    source: &EndpointSource,
    interval: u64,
) -> Result<AbsoluteTime, Box<dyn Error>> {
    let now = source.clock().sample()?.now.as_micros();
    let end = now.checked_add(interval).ok_or("deadline is too large")?;
    if end == u64::MAX {
        return Err("deadline must be finite".into());
    }
    Ok(AbsoluteTime::from_micros(end))
}
pub(super) fn datastore_client<'id, 'slots, 'buffers>(
    identity: &'id mut Instance,
    slots: &'slots mut [Slot<'buffers>],
    reservations: &'slots mut [ReservationSlot],
    source: EndpointSource,
) -> Result<Client<'id, 'slots, 'buffers>, gnunet::datastore_host::Error> {
    let core = ProtocolClient::new(
        identity,
        slots,
        reservations,
        ProtocolLimits {
            max_pending: 1,
            ..ProtocolLimits::default()
        },
    )?;
    Client::new(
        core,
        source,
        NativeLimits {
            reply_frames: 1,
            reply_bytes: 65535,
            ..NativeLimits::default()
        },
    )
}
pub(super) fn publish(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    super::publish::run(
        args,
        super::publish::Mode {
            indexed: false,
            tree: false,
        },
        out,
    )
}

struct FetchArguments<'a> {
    socket: &'a OsStr,
    uri: &'a OsStr,
    destination: &'a OsStr,
    interval: u64,
    anonymity: Option<u32>,
}
impl FetchArguments<'_> {
    fn options(&self, mut original: DownloadOptions) -> DownloadOptions {
        if let Some(level) = self.anonymity {
            original.anonymity = level;
        }
        original
    }
}
fn fetch_arguments(args: &[impl AsRef<OsStr>]) -> Result<FetchArguments<'_>, Box<dyn Error>> {
    if args.len() < 3 {
        return Err("fs fetch requires socket, CHK-or-LOC URI and new file".into());
    }
    let mut timeout = None;
    let mut anonymity = None;
    let mut literal = false;
    let mut index = 3;
    while index < args.len() {
        let value = args[index].as_ref();
        let raw = value.as_bytes();
        if !literal && raw == b"--" {
            literal = true;
            index += 1;
            continue;
        }
        let level = if !literal && matches!(raw, b"-a" | b"--anonymity") {
            index += 1;
            Some(
                args.get(index)
                    .ok_or("-a/--anonymity requires a level")?
                    .as_ref(),
            )
        } else if literal {
            None
        } else {
            raw.strip_prefix(b"--anonymity=")
                .or_else(|| raw.strip_prefix(b"-a"))
                .map(OsStr::from_bytes)
        };
        if let Some(level) = level {
            if anonymity.is_some() {
                return Err("fetch anonymity specified more than once".into());
            }
            anonymity = Some(
                level
                    .to_str()
                    .ok_or("fetch anonymity must be a UTF-8 unsigned integer")?
                    .parse::<u32>()?,
            );
        } else {
            if !literal && raw.starts_with(b"-") {
                return Err("unknown fs fetch option".into());
            }
            if timeout.replace(value).is_some() {
                return Err("fetch timeout specified more than once".into());
            }
        }
        index += 1;
    }
    Ok(FetchArguments {
        socket: args[0].as_ref(),
        uri: args[1].as_ref(),
        destination: args[2].as_ref(),
        interval: duration(timeout.as_ref())?,
        anonymity,
    })
}

pub(super) fn fetch(
    args: &[impl AsRef<OsStr>],
    out: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let arguments = fetch_arguments(args)?;
    let uri = Uri::parse(arguments.uri.as_bytes(), UriLimits::default())?;
    let source = EndpointSource::unix(Path::new(arguments.socket).to_path_buf());
    let deadline = target(&source, arguments.interval)?;
    let (content, options) = match uri {
        Uri::Content(content) => (content, DownloadOptions::new(deadline)),
        Uri::Location(location) => (
            location.content(),
            DownloadOptions::location(location, deadline),
        ),
        _ => return Err("fs fetch requires a resolved CHK or LOC URI".into()),
    };
    let options = arguments.options(options);
    let destination = Path::new(arguments.destination);
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = destination
        .file_name()
        .ok_or("fs fetch requires a new file name")?;
    let mut output = OutputDir::open(parent)?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let done=output.download_file(name,source,content,&mut Buffers::new(),None,options, |_|Control::Continue).await?;
        let row=serde_json::json!({"event":"fs_download_complete","bytes":done.progress.plaintext_bytes,"blocks":done.progress.blocks});
        serde_json::to_writer(&mut *out,&row).map_err(io::Error::other)?;writeln!(out)?;
        Ok::<_,Box<dyn Error>>(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The source regression checks the actual fetch argument-to-transfer policy boundary without I/O or crypto"
    )]
    fn fetch_anonymity_preserves_original_target_deadline_and_native_arguments()
    -> Result<(), Box<dyn Error>> {
        let ordinary = fetch_arguments(&["socket", "uri", "new-file"])?;
        let original = DownloadOptions::new(AbsoluteTime::from_micros(71));
        assert_eq!(ordinary.interval, 300_000_000);
        assert_eq!(ordinary.options(original).anonymity, 1);

        let selected = fetch_arguments(&["socket", "uri", "-a", "23", "-a0"])?;
        assert_eq!(selected.destination, OsStr::new("-a"));
        assert_eq!(selected.socket, OsStr::new("socket"));
        assert_eq!(selected.uri, OsStr::new("uri"));
        assert_eq!(selected.interval, 23_000_000);
        // The normal fetch path supplies this field from an already verified
        // LOC. Selecting0 must not replace its target or original hard bound.
        let original = DownloadOptions {
            target: [7; 32],
            ..original
        };
        let transfer = selected.options(original);
        assert_eq!(transfer.anonymity, 0);
        assert_eq!(transfer.target, [7; 32]);
        assert_eq!(transfer.deadline, AbsoluteTime::from_micros(71));
        assert_eq!(
            transfer.queries_per_connection,
            original.queries_per_connection
        );

        let long = fetch_arguments(&["s", "u", "o", "--anonymity", "0"])?;
        assert_eq!(long.options(original).anonymity, 0);
        let maximum = fetch_arguments(&["s", "u", "o", "--anonymity=4294967295"])?;
        assert_eq!(maximum.options(original).anonymity, u32::MAX);
        assert!(fetch_arguments(&["s", "u", "o", "-a", "4294967296"]).is_err());
        assert!(fetch_arguments(&["s", "u", "o", "-a", "-1"]).is_err());
        assert!(fetch_arguments(&["s", "u", "o", "-a"]).is_err());
        assert!(fetch_arguments(&["s", "u", "o", "-a0", "--anonymity", "1"]).is_err());
        assert!(fetch_arguments(&["s", "u", "o", "3", "4"]).is_err());
        assert!(fetch_arguments(&["s", "u", "o", "--", "-a0"]).is_err());
        assert_eq!(
            fetch_arguments(&["s", "u", "o", "--", "23"])?.interval,
            23_000_000
        );
        Ok(())
    }
}
