//! Validate and stage a provisioned GNUnet DNS containing application.
use super::{Metadata, binary, validate_bundle_identity};
use serde_json::Value;
use std::{
    error::Error,
    ffi::OsString,
    fs,
    io::{Read, Write},
    mem::DropGuard,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const STAGED: &str = "share/gnunet/providers/macos";
const CONTROL: &str = "gnunet-dns-control";
const PROVIDER: &str = "gnunet-dns-proxy";
const NETWORK_EXTENSION: &str = "com.apple.developer.networking.networkextension";
const APP_GROUPS: &str = "com.apple.security.application-groups";
const INSTALL_EXTENSION: &str = "com.apple.developer.system-extension.install";
const MAX_PLIST: u64 = 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_DEPTH: usize = 24;
const MAX_BYTES: u64 = 1024 * 1024 * 1024;

#[cfg(all(test, target_os = "macos"))]
mod tests;

pub(crate) struct SignedApp {
    source: PathBuf,
    name: OsString,
    architecture: binary::Architecture,
    binding: Binding,
}

impl SignedApp {
    pub(crate) fn open(path: &Path, triple: &str) -> Result<Self> {
        let architecture = match triple {
            "x86_64-apple-darwin" => binary::Architecture::X86_64,
            "aarch64-apple-darwin" => binary::Architecture::Arm64,
            _ => {
                return Err("--macos-dns-app requires an x86_64 or arm64 macOS node target".into());
            }
        };
        if !cfg!(target_os = "macos") {
            return Err(
                "--macos-dns-app requires a macOS host for native signature verification".into(),
            );
        }
        let name = path
            .file_name()
            .filter(|_| path.extension().is_some_and(|ext| ext == "app"))
            .ok_or("--macos-dns-app requires a .app bundle")?
            .to_owned();
        if !fs::symlink_metadata(path)?.is_dir() {
            return Err("--macos-dns-app requires an ordinary .app directory".into());
        }
        let source = fs::canonicalize(path)?;
        let binding = Binding::read(&source, architecture)?;
        Ok(Self {
            source,
            name,
            architecture,
            binding,
        })
    }

    pub(crate) fn stage(self, prefix: &Path) -> Result<()> {
        let directory = fs::canonicalize(prefix)?.join(STAGED);
        fs::create_dir_all(&directory)?;
        let staging = directory.join(".staging");
        let destination = directory.join(&self.name);
        validate_tree(&self.source)?;
        // Publish only after checking the copied seal. Native ditto preserves
        // modes, ACLs, extended attributes and quarantine along with the tree.
        fs::create_dir(&staging)?;
        let staging = DropGuard::new(staging, |path| {
            let _cleanup = fs::remove_dir_all(path);
        });
        let pending = staging.join(&self.name);
        checked(
            Command::new("/usr/bin/ditto")
                .args(["--rsrc", "--extattr", "--qtn", "--acl"])
                .env_remove("DITTOKEEPBINARIESPATTERN")
                .arg(&self.source)
                .arg(&pending)
                .output()?,
            "copy signed DNS app",
        )?;
        if Binding::read(&pending, self.architecture)? != self.binding {
            return Err("the signed DNS app changed between admission and staging".into());
        }
        match fs::symlink_metadata(&destination) {
            Ok(_) => return Err("the signed DNS app staging destination already exists".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        fs::rename(pending, destination)?;
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Binding {
    identifier: String,
    provider: String,
    version: String,
    group: String,
    app: Signatures,
    extension: Signatures,
}

impl Binding {
    fn read(path: &Path, architecture: binary::Architecture) -> Result<Self> {
        validate_tree(path)?;
        let contents = path.join("Contents");
        let app = plist_file(&contents.join("Info.plist"))?;
        let identifier = field(&app, "CFBundleIdentifier")?;
        let provider = field(&app, "GNUnetDNSProviderIdentifier")?;
        let version = field(&app, "GNUnetDNSProviderVersion")?;
        // Use the unsigned assembler's identifier/version rules before the
        // provider ID enters a filename or the signature requirement grammar.
        validate_bundle_identity(identifier, version)?;
        validate_bundle_identity(provider, version)?;
        if !provider
            .strip_prefix(identifier)
            .is_some_and(|suffix| suffix.starts_with('.'))
            || field(&app, "CFBundleExecutable")? != CONTROL
            || field(&app, "CFBundlePackageType")? != "APPL"
            || field(&app, "CFBundleVersion")? != version
            || field(&app, "NSPrincipalClass")? != "NSApplication"
        {
            return Err("inconsistent GNUnet DNS containing application metadata".into());
        }
        let directory = contents.join("Library/SystemExtensions");
        let extension_path = directory.join(format!("{provider}.systemextension"));
        let mut entries = fs::read_dir(&directory)?;
        if entries
            .next()
            .transpose()?
            .as_ref()
            .map(fs::DirEntry::path)
            .as_ref()
            != Some(&extension_path)
            || entries.next().is_some()
        {
            return Err("the containing app must embed its declared DNS system extension".into());
        }
        let extension_info = plist_file(&extension_path.join("Contents/Info.plist"))?;
        let network = &extension_info["NetworkExtension"];
        if field(&extension_info, "CFBundleIdentifier")? != provider
            || field(&extension_info, "CFBundleExecutable")? != PROVIDER
            || field(&extension_info, "CFBundlePackageType")? != "SYSX"
            || field(&extension_info, "CFBundleVersion")? != version
            || field(
                &network["NEProviderClasses"],
                "com.apple.networkextension.dns-proxy",
            )? != "GNUnetDNSProxyProvider"
        {
            return Err("inconsistent GNUnet DNS system-extension metadata".into());
        }
        let service = field(network, "NEMachServiceName")?;
        let suffix = format!(".dns-proxy.{version}");
        let group = service
            .strip_suffix(&suffix)
            .ok_or("the provider Mach service must name its application group and version")?;
        let _metadata = Metadata::new(identifier, group, version)?;
        let app = signatures(path, Role::Application, identifier, group, architecture)?;
        let extension = signatures(
            &extension_path,
            Role::Provider,
            provider,
            group,
            architecture,
        )?;
        if app.team != extension.team {
            return Err(
                "DNS containing application and provider must share one signing team".into(),
            );
        }
        Ok(Self {
            identifier: identifier.to_owned(),
            provider: provider.to_owned(),
            version: version.to_owned(),
            group: group.to_owned(),
            app,
            extension,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Signatures {
    team: String,
    directories: Vec<(binary::Architecture, String)>,
}

#[derive(Clone, Copy)]
enum Role {
    Application,
    Provider,
}

impl Role {
    const fn executable(self) -> &'static str {
        match self {
            Self::Application => CONTROL,
            Self::Provider => PROVIDER,
        }
    }
}

fn signatures(
    bundle: &Path,
    role: Role,
    identifier: &str,
    group: &str,
    target: binary::Architecture,
) -> Result<Signatures> {
    let executable = role.executable();
    let path = bundle.join("Contents/MacOS").join(executable);
    let architectures = binary::architectures(&path)?;
    if !architectures.contains(&target) {
        return Err(format!(
            "{executable} lacks the {} node slice",
            target.codesign_name()
        )
        .into());
    }
    let mut directories = Vec::with_capacity(architectures.len());
    let mut signing_team: Option<String> = None;
    for (index, &architecture) in architectures.iter().enumerate() {
        if architectures[..index].contains(&architecture) {
            return Err(format!("{executable} has repeated Mach-O architecture").into());
        }
        let display = checked(
            Command::new("/usr/bin/codesign")
                .args([
                    "--display",
                    "--verbose=4",
                    "--architecture",
                    architecture.codesign_name(),
                    "--entitlements",
                    "-",
                    "--xml",
                    "--",
                ])
                .arg(bundle)
                .output()?,
            "read app code signature",
        )?;
        let metadata = std::str::from_utf8(&display.stderr)?;
        let team = signature_field(metadata, "TeamIdentifier=")?;
        if team.len() != 10
            || !team
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            return Err("DNS app requires an Apple signing team".into());
        }
        let code_directory = signature_field(metadata, "CDHash=")?;
        if code_directory.len() != 40
            || !code_directory.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("invalid DNS bundle code directory hash".into());
        }
        if signing_team
            .as_deref()
            .is_some_and(|original| original != team)
        {
            return Err(format!("{executable} slices must share one signing team").into());
        }
        let entitlements = plist(&display.stdout)?;
        if !contains(
            &entitlements[NETWORK_EXTENSION],
            "dns-proxy-systemextension",
        ) || !contains(&entitlements[APP_GROUPS], group)
            || (matches!(role, Role::Application)
                && entitlements[INSTALL_EXTENSION].as_bool() != Some(true))
        {
            return Err(
                format!("{executable} is missing its signed DNS extension entitlements").into(),
            );
        }
        signing_team.get_or_insert_with(|| team.to_owned());
        directories.push((architecture, code_directory.to_owned()));
    }
    let team = signing_team.ok_or("missing DNS bundle signature")?;
    // The independently constrained Apple requirement binds signed identity
    // and certificate team to the validated plist. Verify every available slice.
    let requirement = format!(
        "anchor apple generic and identifier \"{identifier}\" and certificate leaf[subject.OU] = \"{team}\""
    );
    checked(
        Command::new("/usr/bin/codesign")
            .args([
                "--verify",
                "--strict",
                "--all-architectures",
                "-R",
                &requirement,
                "--",
            ])
            .arg(bundle)
            .output()?,
        "verify signed DNS bundle",
    )?;
    Ok(Signatures { team, directories })
}

fn signature_field<'a>(display: &'a str, field: &str) -> Result<&'a str> {
    let mut matches = display.lines().filter_map(|line| line.strip_prefix(field));
    let value = matches.next().ok_or("missing signed DNS bundle identity")?;
    if matches.next().is_some() {
        return Err("ambiguous signed DNS bundle identity".into());
    }
    Ok(value)
}

fn checked(output: Output, operation: &str) -> Result<Output> {
    if !output.status.success() {
        return Err(format!(
            "{operation} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(output)
}

fn contains(value: &Value, needle: &str) -> bool {
    value
        .as_array()
        .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(needle)))
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("missing or invalid DNS bundle plist field {key}").into())
}

fn plist_file(path: &Path) -> Result<Value> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_PLIST + 1)
        .read_to_end(&mut bytes)?;
    plist(&bytes)
}

fn plist(bytes: &[u8]) -> Result<Value> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_PLIST {
        return Err("DNS bundle plist must be nonempty and at most 1 MiB".into());
    }
    let mut child = Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-", "--", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let write = child
        .stdin
        .take()
        .ok_or("plutil input pipe absent")
        .and_then(|mut input| {
            input
                .write_all(bytes)
                .map_err(|_| "could not write DNS bundle plist to plutil")
        });
    let output = checked(child.wait_with_output()?, "decode DNS bundle plist")?;
    write?;
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn validate_tree(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path)?.is_dir() {
        return Err("DNS app bundle root must be an ordinary directory".into());
    }
    let mut pending = vec![(path.to_path_buf(), 0)];
    let mut entries = 0;
    let mut bytes = 0_u64;
    while let Some((directory, depth)) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            entries += 1;
            bytes = bytes.saturating_add(metadata.len());
            if entries > MAX_ENTRIES || bytes > MAX_BYTES {
                return Err("DNS app exceeds staging limits of 4096 entries and 1 GiB".into());
            }
            if metadata.is_dir() && depth < MAX_DEPTH {
                pending.push((entry.path(), depth + 1));
            } else if !metadata.is_file() {
                return Err(
                    "DNS app requires ordinary files and directories up to 24 levels deep".into(),
                );
            }
        }
    }
    Ok(())
}
