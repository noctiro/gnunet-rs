//! Native private parent preparation for service filesystem outputs.
use std::{io, path::Path};
/// Create missing parents with protected owner-only native ACLs. Existing parent
/// permissions remain unchanged; the caller controls namespace replacement.
pub fn private_parents(path: &Path) -> io::Result<()> {
    gnunet_native::local_path::prepare_parents(
        path,
        gnunet_native::local_path::EndpointAccess::Owner,
    )
}
