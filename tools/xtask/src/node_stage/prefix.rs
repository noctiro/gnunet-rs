//! Stage fixed configuration and exact build artifacts into a fresh prefix.
use super::{
    Result, Target,
    build::{Artifacts, Plan},
    catalog::{Availability, Location},
    service,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

pub(super) const DATA: &str = "share/gnunet";
const DEFAULTS: &[(&str, &str)] = &[
    (
        "00-paths.conf",
        include_str!("../../node/config.d/00-paths.conf"),
    ),
    (
        "10-services.conf",
        include_str!("../../node/config.d/10-services.conf"),
    ),
    (
        "20-peer.conf",
        include_str!("../../node/config.d/20-peer.conf"),
    ),
    (
        "30-applications.conf",
        include_str!("../../node/config.d/30-applications.conf"),
    ),
];
struct Profile {
    name: &'static str,
    contents: &'static str,
    availability: Availability,
}
macro_rules! profiles {
    ($($name:literal $(on $platform:ident)?),+ $(,)?) => {
        &[$(Profile {
            name: $name,
            contents: include_str!(concat!("../../node/profiles/", $name)),
            availability: profiles!(@availability $($platform)?),
        }),+]
    };
    (@availability) => { Availability::All };
    (@availability $platform:ident) => { Availability::$platform };
}
const PROFILES: &[Profile] = profiles![
    "abd.conf",
    "bcd.conf",
    "consensus.conf",
    "conversation.conf",
    "dns.conf",
    "dns2gns.conf",
    "exit-dns.conf",
    "exit-ip.conf",
    "gns-proxy.conf",
    "hostlist.conf",
    "http3.conf",
    "messenger.conf",
    "nat-auto.conf",
    "pt.conf",
    "quic.conf",
    "reclaim.conf",
    "regex.conf",
    "rest.conf",
    "rps.conf",
    "scalarproduct-ecc.conf",
    "scalarproduct-paillier.conf",
    "secretsharing.conf",
    "sets.conf",
    "unix-communicator.conf" on Unix,
    "vpn.conf",
];
const MAX_HELLOS: usize = 1024;
const MAX_HELLO_BYTES: u64 = u16::MAX as u64;
const MAX_CATALOG_BYTES: u64 = 8 * 1024 * 1024;
const MAX_LOCALE_BYTES: usize = 32 * 1024 * 1024;

pub(super) struct Data {
    hellos: Vec<Vec<u8>>,
    catalogs: Vec<(String, Vec<u8>)>,
}

impl Data {
    pub(super) fn load(directory: Option<&Path>, locales: Option<&Path>) -> Result<Self> {
        let mut paths = Vec::new();
        if let Some(directory) = directory {
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                if !entry.file_type()?.is_file() || paths.len() == MAX_HELLOS {
                    return Err(
                        "HELLO input must contain at most 1024 regular contact files".into(),
                    );
                }
                paths.push(entry.path());
            }
            if paths.is_empty() {
                return Err("HELLO input directory is empty".into());
            }
        }
        paths.sort();
        let mut hellos = Vec::new();
        for path in paths {
            let mut bytes = Vec::new();
            File::open(&path)?
                .take(MAX_HELLO_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_HELLO_BYTES || !bytes.starts_with(b"gnunet://hello/") {
                return Err(
                    format!("expected a bounded GNUnet HELLO URI in {}", path.display()).into(),
                );
            }
            hellos.push(bytes);
        }
        let catalogs = locales.map(load_catalogs).transpose()?.unwrap_or_default();
        Ok(Self { hellos, catalogs })
    }

    pub(super) fn validate(&self, target: &Target, plan: &Plan) -> Result<()> {
        let profiles = profiles_for(target).map(|profile| (profile.name, profile.contents));
        for (file, text) in DEFAULTS.iter().copied().chain(profiles) {
            for (key, value) in text.lines().filter_map(|line| line.split_once('=')) {
                if key.trim().eq_ignore_ascii_case("BINARY") && !plan.contains_libexec(value.trim())
                {
                    return Err(format!(
                        "{file} selects an unstaged managed executable: {}",
                        value.trim()
                    )
                    .into());
                }
            }
        }
        for profile in profiles_for(target) {
            for include in profile
                .contents
                .lines()
                .filter_map(|line| line.trim().strip_prefix("@INLINE@"))
            {
                if !profiles_for(target).any(|candidate| candidate.name == include.trim()) {
                    return Err(format!(
                        "{} includes an unstaged profile: {}",
                        profile.name,
                        include.trim()
                    )
                    .into());
                }
            }
        }
        Ok(())
    }

    fn stage(self, output: &Path, target: &Target, service: &service::Assets) -> Result<()> {
        let data = output.join(DATA);
        let has_hellos = !self.hellos.is_empty();
        if has_hellos {
            let directory = data.join("hellos");
            fs::create_dir_all(&directory)?;
            for (index, bytes) in self.hellos.iter().enumerate() {
                write_new(&directory.join(format!("{index:04}.hello")), bytes)?;
            }
        }
        let defaults = data.join("config.d");
        fs::create_dir_all(&defaults)?;
        for (name, contents) in DEFAULTS {
            write_new(&defaults.join(name), contents.as_bytes())?;
        }
        let profiles = data.join("profiles");
        fs::create_dir_all(&profiles)?;
        for profile in profiles_for(target) {
            write_new(&profiles.join(profile.name), profile.contents.as_bytes())?;
        }
        if has_hellos {
            write_new(
                &defaults.join("90-local-hellos.conf"),
                b"[peerstore]\nUSE_INCLUDED_HELLOS = YES\n",
            )?;
        }
        write_new(
            &data.join("node.conf"),
            b"# Overrides for the staged GNUnet node.\n",
        )?;
        service.stage(&data.join("service"))?;
        for (locale, catalog) in self.catalogs {
            let messages = output.join("share/locale").join(locale).join("LC_MESSAGES");
            fs::create_dir_all(&messages)?;
            write_new(&messages.join("gnunet.mo"), &catalog)?;
        }
        Ok(())
    }
}

fn profiles_for(target: &Target) -> impl Iterator<Item = &'static Profile> {
    PROFILES
        .iter()
        .filter(|profile| profile.availability.supports(target))
}

fn load_catalogs(root: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let mut catalogs = Vec::new();
    let mut retained = 0;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let locale = entry
            .file_name()
            .into_string()
            .map_err(|_| "invalid catalog locale name")?;
        if locale.len() > 128
            || !locale
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !locale
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.@-".contains(&byte))
        {
            return Err("invalid catalog locale name".into());
        }
        let file = entry.path().join("LC_MESSAGES/gnunet.mo");
        match fs::symlink_metadata(&file) {
            Ok(meta) if meta.is_file() => {}
            Ok(_) => return Err("expected a regular gnunet.mo catalog".into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        }
        let mut bytes = Vec::new();
        File::open(file)?
            .take(MAX_CATALOG_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_CATALOG_BYTES
            || bytes.len() < 28
            || !matches!(
                &bytes[..4],
                [0xde, 0x12, 0x04, 0x95] | [0x95, 0x04, 0x12, 0xde]
            )
        {
            return Err("expected a bounded GNU gnunet.mo catalog".into());
        }
        retained += bytes.len();
        if retained > MAX_LOCALE_BYTES || catalogs.len() == 128 {
            return Err("staged gettext catalogs exceed their bounds".into());
        }
        catalogs.push((locale, bytes));
    }
    if catalogs.is_empty() {
        return Err("locale directory contains no gnunet.mo catalogs".into());
    }
    catalogs.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    Ok(catalogs)
}

pub(super) fn stage(
    output: &Path,
    target: &Target,
    built: Artifacts,
    data: Data,
    service: &service::Assets,
) -> Result<()> {
    for directory in [Location::Bin, Location::Libexec] {
        fs::create_dir_all(output.join(directory.directory()))?;
    }
    for artifact in built.iter() {
        let directory = output.join(artifact.location.directory());
        if artifact.location == Location::Nss {
            let module = directory.join("libnss_gns.so.2");
            copy_new(artifact.file(), &module)?;
            for name in ["libnss_gns4.so.2", "libnss_gns6.so.2"] {
                let alias = directory.join(name);
                if fs::hard_link(&module, &alias).is_err() {
                    copy_new(&File::open(&module)?, &alias)?;
                }
            }
        } else {
            copy_new(
                artifact.file(),
                &directory.join(target.executable(artifact.name)),
            )?;
        }
    }
    data.stage(output, target, service)
}

fn create(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

pub(super) fn write_new(path: &Path, contents: &[u8]) -> io::Result<()> {
    create(path)?.write_all(contents)
}

pub(super) fn copy_new(input: &File, destination: &Path) -> io::Result<()> {
    let metadata = input.metadata()?;
    if metadata.len() == 0 {
        return Err(io::Error::other(
            "Cargo artifact became empty before staging",
        ));
    }
    let mut output = create(destination)?;
    let copied = io::copy(
        &mut input.take(metadata.len().saturating_add(1)),
        &mut output,
    )?;
    if copied != metadata.len() {
        return Err(io::Error::other(
            "Cargo artifact size changed while staging",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        output.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{path::PathBuf, time::SystemTime};

    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _removed = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn unix_communicator_profile_follows_target_availability() -> Result<()> {
        for os in ["linux", "macos", "freebsd", "windows"] {
            let target = Target::from_cfg(os.to_owned(), &format!("target_os=\"{os}\""))?;
            let profile =
                profiles_for(&target).find(|profile| profile.name == "unix-communicator.conf");
            if profile.is_some() != (os != "windows") {
                return Err(format!("unexpected UNIX communicator profile on {os}").into());
            }
        }
        Ok(())
    }

    #[test]
    fn staged_service_recipe_matches_the_selected_target() -> Result<()> {
        let scratch = std::env::temp_dir().join(format!(
            "gnunet-node-service-{}-{}",
            std::process::id(),
            SystemTime::UNIX_EPOCH.elapsed()?.as_nanos()
        ));
        fs::create_dir(&scratch)?;
        let scratch = Scratch(scratch);
        for (os, expected) in [
            ("linux", &["README.md", "gnunet-node.service"][..]),
            ("macos", &["README.md", "org.gnunet.node.plist"]),
            ("freebsd", &["README.md", "gnunet_node"]),
            ("windows", &["README.md"]),
        ] {
            let target = Target::from_cfg(os.to_owned(), &format!("target_os=\"{os}\""))?;
            let output = scratch.0.join(os);
            let prefix = "/opt/gnunet-2.0+node";
            let install = (os != "windows").then_some(std::ffi::OsStr::new(prefix));
            let service = service::Assets::new(target.platform(), install)?;
            Data::load(None, None)?.stage(&output, &target, &service)?;
            let mut files = fs::read_dir(output.join(DATA).join("service"))?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<io::Result<Vec<_>>>()?;
            files.sort_unstable();
            if !files
                .iter()
                .map(|name| name.as_os_str())
                .eq(expected.iter().copied())
            {
                return Err(format!("unexpected service assets staged for {os}: {files:?}").into());
            }
            if let [_, recipe] = expected {
                let recipe = fs::read_to_string(output.join(DATA).join("service").join(recipe))?;
                for path in ["bin/gnunet-node", DATA] {
                    if !recipe.contains(&format!("{prefix}/{path}")) {
                        return Err(
                            format!("missing deployed path {prefix}/{path} for {os}").into()
                        );
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn stage_node_preserves_installed_gnunet_catalogs() -> Result<()> {
        let scratch = std::env::temp_dir().join(format!(
            "gnunet-node-locale-{}-{}",
            std::process::id(),
            SystemTime::UNIX_EPOCH.elapsed()?.as_nanos()
        ));
        fs::create_dir(&scratch)?;
        let scratch = Scratch(scratch);
        let input = scratch.0.join("input");
        let messages = input.join("fr/LC_MESSAGES");
        fs::create_dir_all(&messages)?;
        let mut catalog = [0_u8; 28];
        catalog[..4].copy_from_slice(&[0xde, 0x12, 0x04, 0x95]);
        fs::write(messages.join("gnunet.mo"), catalog)?;
        let output = scratch.0.join("output");
        let target = Target::resolve(None)?;
        let service = service::Assets::new(target.platform(), None)?;
        Data::load(None, Some(&input))?.stage(&output, &target, &service)?;
        if fs::read(output.join("share/locale/fr/LC_MESSAGES/gnunet.mo"))? != catalog {
            return Err("staged message catalog changed".into());
        }
        Ok(())
    }
}
