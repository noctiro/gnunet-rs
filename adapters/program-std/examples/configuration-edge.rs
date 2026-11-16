//! Safe owned reproduction for a missing-HOME default filename difference.
use std::io::{self, Write};
struct Empty;
impl gnunet_config::Environment for Empty {
    fn variable(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn current_dir(&self) -> io::Result<std::path::PathBuf> {
        std::env::current_dir()
    }
}
fn main() -> io::Result<()> {
    let Some(marker) = std::env::args_os().nth(1) else {
        return Err(io::Error::other("marker required"));
    };
    let marker_bytes = gnunet_native::os_bytes::encode(&marker);
    let project = gnunet_config::ProjectData {
        config_file: marker_bytes.as_ref().to_vec(),
        project_dirname: marker_bytes.as_ref().to_vec(),
        user_config_file: [b"~/.config/".as_slice(), marker_bytes.as_ref()].concat(),
        ..gnunet_config::ProjectData::default()
    };
    let mut stdout = io::stdout();
    match project.default_filename(&Empty) {
        Ok(None) => writeln!(stdout, "NONE"),
        Ok(Some(path)) => {
            stdout.write_all(b"SOME ")?;
            stdout.write_all(&gnunet_native::os_bytes::encode(path.as_os_str()))?;
            stdout.write_all(b"\n")
        }
        Err(error) => writeln!(stdout, "ERROR {error:?}"),
    }
}
