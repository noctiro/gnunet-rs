//! Render service manager assets for the final install location.
use super::{
    Platform, Result,
    catalog::Location,
    prefix::{DATA, write_new},
};
use std::{ffi::OsStr, fs, io, path::Path};

const DEFAULT_PREFIX: &str = "/usr/local";

pub(super) struct Assets {
    recipe: Option<(&'static str, String)>,
    documentation: &'static [u8],
}

impl Assets {
    pub(super) fn new(platform: Platform, install_prefix: Option<&OsStr>) -> Result<Self> {
        let (documentation, (name, template)) = match platform {
            Platform::Linux => (
                &include_bytes!("../../../../platform/linux/node/README.md")[..],
                (
                    "gnunet-node.service",
                    include_str!("../../../../platform/linux/node/gnunet-node.service.in"),
                ),
            ),
            Platform::Macos => (
                &include_bytes!("../../../../platform/macos/node/README.md")[..],
                (
                    "org.gnunet.node.plist",
                    include_str!("../../../../platform/macos/node/org.gnunet.node.plist.in"),
                ),
            ),
            Platform::FreeBsd => (
                &include_bytes!("../../../../platform/freebsd/node/README.md")[..],
                (
                    "gnunet_node",
                    include_str!("../../../../platform/freebsd/node/gnunet_node.in"),
                ),
            ),
            Platform::Windows => {
                if install_prefix.is_some() {
                    return Err(
                        "--install-prefix applies to Linux, macOS and FreeBSD service recipes"
                            .into(),
                    );
                }
                return Ok(Self {
                    recipe: None,
                    documentation: include_bytes!("../../../../platform/windows/node/README.md"),
                });
            }
        };
        let prefix = match install_prefix {
            Some(path) => path.to_str().ok_or("install prefix must be UTF-8")?,
            None => DEFAULT_PREFIX,
        };
        // Use the target's path syntax even when staging from a Windows host.
        // These characters are literal in systemd, XML and the rc.d shell.
        let tail = prefix
            .strip_prefix('/')
            .ok_or("install prefix must be an absolute Unix path")?;
        if !tail.is_empty()
            && !tail.split('/').all(|component| {
                !matches!(component, "" | "." | "..")
                    && component
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
            })
        {
            return Err("install prefix must use normalized components containing letters, digits, dots, underscores, plus or hyphens".into());
        }
        let base = prefix.trim_end_matches('/');
        let executable = format!("{base}/{}/gnunet-node", Location::Bin.directory());
        let data = format!("{base}/{DATA}");
        let recipe = template
            .replace("@GNUNET_EXECUTABLE@", &executable)
            .replace("@GNUNET_BOOTSTRAP_DATA@", &data);
        Ok(Self {
            recipe: Some((name, recipe)),
            documentation,
        })
    }

    pub(super) fn stage(&self, directory: &Path) -> io::Result<()> {
        fs::create_dir_all(directory)?;
        if let Some((name, recipe)) = &self.recipe {
            write_new(&directory.join(name), recipe.as_bytes())?;
        }
        write_new(&directory.join("README.md"), self.documentation)
    }
}
