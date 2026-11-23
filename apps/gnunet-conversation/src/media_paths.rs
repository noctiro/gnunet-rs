//! The installed path and configuration shared by the Conversation commands.
use crate::Failure;
use gnunet_config::Configuration;
use std::path::PathBuf;

pub(super) const SECTION: &[u8] = b"conversation-command-rust";
pub(super) const RECORD: (&[u8], &str) = (b"HELPER_RECORD", "gnunet-helper-audio-record");
pub(super) const PLAYBACK: (&[u8], &str) = (b"HELPER_PLAYBACK", "gnunet-helper-audio-playback");

pub(super) struct Paths<'a> {
    config: &'a Configuration,
    defaults: PathBuf,
}

impl<'a> Paths<'a> {
    pub(super) fn installed(config: &'a Configuration) -> Result<Self, Failure> {
        let exe = std::env::current_exe()?;
        let dir = exe
            .parent()
            .ok_or("current Rust command has no installation directory")?;
        let defaults = if dir.file_name().is_some_and(|name| name == "bin") {
            dir.parent()
                .ok_or("Rust installation has no prefix")?
                .join("lib/gnunet/libexec")
        } else {
            dir.to_path_buf()
        };
        Ok(Self { config, defaults })
    }

    pub(super) fn program(&self, (key, name): (&[u8], &str)) -> Result<PathBuf, Failure> {
        let path = match self.config.get(SECTION, key) {
            Some(value) => {
                if value.is_empty() || value.len() > 4096 || value.contains(&0) {
                    return Err("invalid or over-bound native helper path".into());
                }
                PathBuf::from(gnunet_native::os_bytes::decode(value)?.into_owned())
            }
            None => {
                let mut path = self.defaults.join(name);
                if cfg!(windows) {
                    path.set_extension("exe");
                }
                path
            }
        };
        if !path.is_absolute() {
            return Err("explicit media/helper paths must be absolute".into());
        }
        Ok(path)
    }
}
