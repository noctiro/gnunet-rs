//! The installed `gnunet-search` front door over the shared search session.

use super::{Request, Style, canonical_uri, execute, format::Formats};
use gnunet::{
    fs::{Keywords, Limits, Uri},
    fs_host::search::Limits as SearchLimits,
};
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
    program,
};
use std::{error::Error, io::Write};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

struct Arguments {
    anonymity: Target<u32>,
    bookmark: Target<i32>,
    file_format: Target<Option<Vec<u8>>>,
    directory_format: Target<Option<Vec<u8>>>,
    metadata_format: Target<Option<Vec<u8>>>,
    results: Target<u32>,
    local_only: Target<i32>,
    output: Target<Option<Vec<u8>>>,
    silent: Target<i32>,
    timeout: Target<u64>,
    verbose: Target<u32>,
}

impl Arguments {
    fn new() -> Self {
        Self {
            anonymity: Target::new(1),
            bookmark: Target::new(0),
            file_format: Target::new(None),
            directory_format: Target::new(None),
            metadata_format: Target::new(None),
            results: Target::new(0),
            local_only: Target::new(0),
            output: Target::new(None),
            silent: Target::new(0),
            timeout: Target::new(0),
            verbose: Target::new(0),
        }
    }

    fn options(&self) -> Options<'static> {
        let mut options = Options::new();
        options.add(helpers::uint(
            b'a',
            b"anonymity",
            b"LEVEL",
            b"Set receiver anonymity (default 1)",
            self.anonymity.clone(),
        ));
        options.add(helpers::flag(
            b'b',
            b"bookmark-only",
            b"Print the canonical search URI",
            self.bookmark.clone(),
        ));
        options.add(helpers::string(
            b'f',
            b"printf",
            b"FORMAT",
            b"Format file results (%a, %f, %j, %l, %m, %n, %s, %u)",
            self.file_format.clone(),
        ));
        options.add(helpers::string(
            b'F',
            b"dir-printf",
            b"FORMAT",
            b"Format directory results",
            self.directory_format.clone(),
        ));
        options.add(helpers::string(
            b'i',
            b"iter-printf",
            b"FORMAT",
            b"Format each metadata item (%i, %l, %n, %p, %t, %w)",
            self.metadata_format.clone(),
        ));
        options.add(helpers::uint(
            b'N',
            b"results",
            b"VALUE",
            b"Stop after this many visible results",
            self.results.clone(),
        ));
        options.add(helpers::flag(
            b'n',
            b"no-network",
            b"Search only the local peer",
            self.local_only.clone(),
        ));
        options.add(helpers::string(
            b'o',
            b"output",
            b"FILENAME",
            b"Save results in a new GNUnet directory file",
            self.output.clone(),
        ));
        options.add(helpers::flag(
            b's',
            b"silent",
            b"Suppress result text (requires --output)",
            self.silent.clone(),
        ));
        options.add(helpers::relative_time(
            b't',
            b"timeout",
            b"DELAY",
            b"Stop after a GNUnet interval; 0 waits for a signal or result limit",
            self.timeout.clone(),
        ));
        options.add(helpers::increment(
            b'V',
            b"verbose",
            b"Append metadata to the default result formats",
            self.verbose.clone(),
        ));
        options
    }
}

fn terms(args: &[Vec<u8>]) -> Result<Vec<&[u8]>> {
    #[cfg(windows)]
    for argument in args {
        std::str::from_utf8(argument)?;
    }
    if args.is_empty() || args.len() > Limits::default().max_keywords {
        return Err(
            "search requires a bounded, nonempty list of keyword arguments or a URI".into(),
        );
    }
    let mut terms = Vec::new();
    terms.try_reserve_exact(args.len())?;
    terms.extend(args.iter().map(Vec::as_slice));
    Ok(terms)
}

fn query<'a>(terms: &'a [&'a [u8]]) -> Result<Uri<'a>> {
    let limits = Limits::default();
    if let [raw] = terms
        && raw.starts_with(b"gnunet://fs/")
        && let Ok(uri) = Uri::parse(raw, limits)
    {
        return match uri {
            Uri::Keywords(_) | Uri::Namespace(_) => Ok(uri),
            _ => Err("FS search accepts only KSK or SKS URIs".into()),
        };
    }
    Ok(Uri::Keywords(Keywords::from_user_args(terms, limits)?))
}

pub(crate) fn run() -> Result<()> {
    let arguments = Arguments::new();
    let Some((prepared, clock)) = crate::configured::prepare(
        b"gnunet-search",
        b"Search the configured FILESHARING service using keywords or a KSK/SKS URI. Use -b to print the search bookmark.",
        arguments.options(),
    )? else { return Ok(()); };
    let main = prepared.main();
    let terms = terms(main.arguments)?;
    let uri = query(&terms)?;
    let bookmark = arguments.bookmark.get()? != 0;
    let silent = arguments.silent.get()? != 0;
    let output = arguments.output.get()?;
    if bookmark {
        if silent || output.is_some() {
            return Err("--bookmark-only conflicts with --silent and --output".into());
        }
        let canonical = canonical_uri(&uri)?;
        return super::super::output::with_stdout("gnunet-search", true, |out| {
            out.write_all(&canonical)?;
            out.write_all(b"\n")?;
            out.flush()?;
            Ok(())
        });
    }
    if silent && output.is_none() {
        return Err("--silent requires --output".into());
    }
    let path = output.as_deref().map(program::native_path).transpose()?;
    let interval = match arguments.timeout.get()? {
        0 | u64::MAX => None,
        interval => Some(interval),
    };
    let limit = usize::try_from(arguments.results.get()?)?;
    if limit > SearchLimits::default().results {
        return Err("search result limit exceeds the configured retention capacity".into());
    }
    let formats = Formats::new(
        arguments.file_format.get()?,
        arguments.directory_format.get()?,
        arguments.metadata_format.get()?,
        arguments.verbose.get()? != 0,
    )?;
    let request = Request {
        query: uri,
        interval,
        limit: (limit != 0).then_some(limit),
        output: path.as_deref(),
        local_only: arguments.local_only.get()? != 0,
        anonymity: arguments.anonymity.get()?,
        style: if silent {
            Style::Silent
        } else {
            Style::Text(&formats)
        },
    };
    super::super::output::with_stdout("gnunet-search", true, |out| {
        crate::configured::run(main.config, clock, [b"fs"], move |[source]| {
            execute(request, source, out)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_search_preserves_required_quoted_keywords_and_canonical_input() -> Result<()> {
        let input = [b"+alpha".as_slice(), b"\"two words\"".as_slice()];
        let bookmark = canonical_uri(&query(&input)?)?;
        if bookmark.as_slice() != b"gnunet://fs/ksk/%2Balpha+two%20words" {
            return Err("search bookmark changed the selected keywords".into());
        }
        let input = [bookmark.as_slice()];
        if canonical_uri(&query(&input)?)? != bookmark {
            return Err("the emitted search bookmark did not round trip".into());
        }
        Ok(())
    }
}
