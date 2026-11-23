//! Shared canonical included-HELLO import, before the storage worker starts.
use crate::{Failure, reporting::Reports};
use gnunet_hello::{AbsoluteTime, SignatureProfile};
use gnunet_peerstore_host::{
    backend::Wal,
    bootstrap::{Directory, Event, Import},
};

pub(crate) fn import_hellos(
    wal: &mut Wal,
    directory: Option<&Directory>,
    now: AbsoluteTime,
    reports: &Reports,
) -> Result<(), Failure> {
    for event in Import::open(directory, SignatureProfile::Gnunet029, now)? {
        match event? {
            Event::Included(included) => {
                wal.import_hello(&included)?;
            }
            Event::Skipped { path, reason } => {
                reports.warning(
                    "peerstore.hello.invalid",
                    format_args!("peerstore skip included HELLO {path:?}: {reason:?}"),
                );
                reports.startup_check()?;
            }
        }
    }
    Ok(())
}
