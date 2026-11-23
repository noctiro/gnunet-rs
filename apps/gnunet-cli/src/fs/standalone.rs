//! Installed PROGRAM entry points for file sharing operations.
use super::{index_list, metadata_options, output, service, unindex};
use crate::configured;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};
use std::{error::Error, path::Path};
use tokio::time::Instant;

type Result = std::result::Result<(), Box<dyn Error>>;
mod download;
pub(crate) use download::run as download;

pub(crate) fn index() -> Result {
    let list = Target::new(0);
    let verbose = Target::new(0);
    let mut options = Options::new();
    options.add(helpers::flag(
        b'i',
        b"list-indexed",
        b"Print a list of all indexed files",
        list.clone(),
    ));
    options.add(helpers::verbose(verbose.clone()));
    let Some((prepared, clock)) =
        configured::prepare(b"gnunet-fs", b"Special file-sharing operations", options)?
    else {
        return Ok(());
    };
    if list.get()? == 0 {
        return Ok(());
    }
    let format = index_list::Format::Names {
        include_hash: verbose.get()? != 0,
    };
    let interval = service::DEFAULT_INTERVAL_MICROS;
    output::with_stdout("gnunet-fs", true, |out| {
        configured::run(prepared.main().config, clock, [b"fs"], |[fs]| async move {
            index_list::list(fs, interval, index_list::DEFAULT_MAX_RECORDS, format, out).await
        })
    })
}

pub(crate) fn unindex() -> Result {
    let verbose = Target::new(0);
    let mut options = Options::new();
    options.add(helpers::verbose(verbose.clone()));
    let Some((prepared, clock)) = configured::prepare(
        b"gnunet-unindex",
        b"Unindex a file previously indexed with gnunet-publish. Supply one filename.",
        options,
    )?
    else {
        return Ok(());
    };
    let main = prepared.main();
    let [filename] = main.arguments else {
        return Err("specify exactly one filename for unindexing".into());
    };
    let filename = gnunet_native::os_bytes::decode(filename)?;
    let started = Instant::now();
    let job = unindex::Job {
        filename: Path::new(&filename),
        metadata: metadata_options::Arguments::default().select_configured(main.config)?,
        keywords: &[],
        started,
        interval: service::DEFAULT_INTERVAL_MICROS,
        format: unindex::Format::Text {
            verbose: verbose.get()? != 0,
        },
    };
    output::with_stdout("gnunet-unindex", false, |out| {
        configured::run(
            main.config,
            clock,
            [b"fs", b"datastore"],
            |sources| async move { unindex::execute(sources, job, out).await },
        )
    })
}
