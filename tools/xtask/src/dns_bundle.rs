//! Assemble an unsigned DNS system-extension bundle without running its binary.
use std::{
    error::Error,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

mod app;
mod binary;
mod signed;

pub(crate) use app::bundle as bundle_app;
pub(crate) use signed::SignedApp;

const INFO: &str = include_str!("../../../apps/gnunet-service-dns/macos/Provider-Info.plist.in");
const ENTITLEMENTS: &str =
    include_str!("../../../apps/gnunet-service-dns/macos/Provider.entitlements.in");

pub(crate) fn bundle(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let mut binary = None;
    let mut output = None;
    let mut identifier = None;
    let mut group = None;
    let mut version = None;
    for pair in arguments.chunks(2) {
        if pair.len() != 2 {
            return Err("bundle-dns-proxy requires option/value pairs".into());
        }
        match pair[0].as_str() {
            "--binary" if binary.is_none() => binary = Some(PathBuf::from(&pair[1])),
            "--output" if output.is_none() => output = Some(PathBuf::from(&pair[1])),
            "--bundle-id" if identifier.is_none() => identifier = Some(pair[1].clone()),
            "--app-group" if group.is_none() => group = Some(pair[1].clone()),
            "--version" if version.is_none() => version = Some(pair[1].clone()),
            _ => return Err("unknown or duplicate bundle-dns-proxy option".into()),
        }
    }
    let binary = binary.ok_or("--binary is required")?;
    let output = output.ok_or("--output is required")?;
    let identifier = identifier.ok_or("--bundle-id is required")?;
    let group = group.ok_or("--app-group is required")?;
    let version = version.unwrap_or_else(|| "1.0.0".to_owned());
    let metadata = Metadata::new(&identifier, &group, &version)?;
    provider(&binary, &output, &metadata)?;
    let entitlements = output.with_extension("entitlements");
    write_new(&entitlements, metadata.entitlements().as_bytes())?;
    writeln!(
        std::io::stdout().lock(),
        "Unsigned DNS provider bundle: {}",
        output.display()
    )?;
    writeln!(
        std::io::stdout().lock(),
        "Signing entitlements: {}",
        entitlements.display()
    )?;
    Ok(())
}

struct Metadata<'a> {
    identifier: &'a str,
    group: &'a str,
    version: &'a str,
}
impl<'a> Metadata<'a> {
    fn new(identifier: &'a str, group: &'a str, version: &'a str) -> Result<Self, Box<dyn Error>> {
        validate_bundle_identity(identifier, version)?;
        if !qualified_name(group, 200)
        // Darwin bootstrap names include the terminating NUL in their 128-byte
        // limit (servers/bootstrap.h). Use the exact generated service name.
        || group.len() + ".dns-proxy.".len() + version.len() >= 128
        {
            return Err("invalid bundle application group for its versioned Mach service".into());
        }
        Ok(Self {
            identifier,
            group,
            version,
        })
    }
    fn entitlements(&self) -> String {
        ENTITLEMENTS.replace("@APP_GROUP@", self.group)
    }
}

fn qualified_name(name: &str, max_len: usize) -> bool {
    name.contains('.')
        && name.len() <= max_len
        && name.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn validate_bundle_identity(identifier: &str, version: &str) -> Result<(), Box<dyn Error>> {
    if !qualified_name(identifier, 255)
        || version.len() > 32
        || version.split('.').count() != 3
        || version.split('.').any(|part| {
            part.is_empty()
                || !part.bytes().all(|b| b.is_ascii_digit())
                || part.parse::<u32>().is_err()
        })
    {
        return Err("invalid bundle identifier or numeric bundle version".into());
    }
    Ok(())
}
fn provider(binary: &Path, output: &Path, metadata: &Metadata<'_>) -> Result<(), Box<dyn Error>> {
    if output.file_name().and_then(|p| p.to_str())
        != Some(&format!("{}.systemextension", metadata.identifier))
    {
        return Err("--output must end in <bundle-id>.systemextension".into());
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    // Refuse replacement of an existing bundle. Later errors leave the newly
    // created partial artifact for inspection; no recursive deletion is needed.
    fs::create_dir(output)?;
    let contents = output.join("Contents");
    fs::create_dir(&contents)?;
    let executable = contents.join("MacOS");
    fs::create_dir(&executable)?;
    let resources = contents.join("Resources");
    fs::create_dir_all(resources.join("share/gnunet/config.d"))?;
    binary::copy(binary, &executable.join("gnunet-dns-proxy"))?;
    write_new(
        &contents.join("Info.plist"),
        INFO.replace("@BUNDLE_ID@", metadata.identifier)
            .replace("@BUNDLE_VERSION@", metadata.version)
            .replace("@APP_GROUP@", metadata.group)
            .as_bytes(),
    )?;
    Ok(())
}
fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)
}
