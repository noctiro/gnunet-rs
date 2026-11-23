//! Preserve source notices and the licenses of a selected release graph.
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
type PackageKey = (String, String);
const BUNDLE: &str = "THIRD_PARTY_LICENSES.txt";

pub(crate) fn run_sdk(root: &Path, mut args: impl Iterator<Item = OsString>) -> Result<()> {
    let mut output = None;
    let mut targets = BTreeSet::new();
    while let Some(option) = args.next() {
        let value = args
            .next()
            .ok_or("missing stage-sdk-licenses option value")?;
        match option.to_str() {
            Some("--output") if output.is_none() => output = Some(PathBuf::from(value)),
            Some("--target") => {
                let target = value
                    .into_string()
                    .map_err(|_| "expected a UTF-8 Rust target")?;
                if target.is_empty()
                    || !target
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
                {
                    return Err("expected a Rust target triple".into());
                }
                targets.insert(target);
            }
            _ => {
                return Err(
                    "expected --output PATH and one or more --target TRIPLE options".into(),
                );
            }
        }
    }
    if targets.is_empty() {
        return Err("stage-sdk-licenses requires at least one Rust target".into());
    }
    let output = output.ok_or("stage-sdk-licenses requires --output")?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let selection = [
        OsString::from("--package"),
        OsString::from("gnunet-node-sdk"),
    ];
    stage(
        root,
        &cargo,
        targets.iter().map(String::as_str),
        &selection,
        &output,
    )
}

pub(crate) fn stage<'a>(
    root: &Path,
    cargo: &OsStr,
    targets: impl IntoIterator<Item = &'a str>,
    selection: &[OsString],
    output: &Path,
) -> Result<()> {
    let mut packages = BTreeMap::new();
    for target in targets {
        collect(root, cargo, target, selection, &mut packages)?;
    }
    let sources = source_notices(root)?;
    fs::create_dir_all(output)?;
    let mut bundle = create(&output.join(BUNDLE))?;
    writeln!(
        bundle,
        "Third-party notices. See NOTICE.md for source attribution."
    )?;
    for name in sources {
        let file = output.join(&name);
        fs::create_dir_all(file.parent().ok_or("notice parent missing")?)?;
        let source = root.join(&name);
        io::copy(&mut File::open(&source)?, &mut create(&file)?)?;
        if !matches!(name.as_str(), "LICENSE" | "NOTICE.md") {
            writeln!(bundle, "\n--- {name} ---")?;
            io::copy(&mut File::open(source)?, &mut bundle)?;
            writeln!(bundle)?;
        }
    }
    writeln!(bundle, "\nCargo runtime dependencies")?;
    for ((name, version), package) in packages {
        writeln!(
            bundle,
            "\n=== {name} {version} | {} | {} ===",
            package.expression,
            package.targets.into_iter().collect::<Vec<_>>().join(", ")
        )?;
        for file in package.files {
            writeln!(
                bundle,
                "\n--- {} ---",
                file.file_name()
                    .ok_or("license filename missing")?
                    .display()
            )?;
            io::copy(&mut File::open(file)?, &mut bundle)?;
            writeln!(bundle)?;
        }
    }
    Ok(())
}

fn create(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn source_notices(root: &Path) -> Result<BTreeSet<String>> {
    let notice = fs::read_to_string(root.join("NOTICE.md"))?;
    let mut files = BTreeSet::from(["LICENSE".to_owned(), "NOTICE.md".to_owned()]);
    for link in notice.split("](").skip(1) {
        let (name, _) = link.split_once(')').ok_or("unterminated NOTICE.md link")?;
        if !name.split('/').all(|part| {
            !matches!(part, "" | "." | "..")
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
        }) {
            return Err(format!("expected a local relative notice path: {name}").into());
        }
        files.insert(name.into());
    }
    Ok(files)
}

struct Package {
    expression: String,
    files: BTreeSet<PathBuf>,
    targets: BTreeSet<String>,
}

fn collect(
    root: &Path,
    cargo: &OsStr,
    target: &str,
    selection: &[OsString],
    packages: &mut BTreeMap<PackageKey, Package>,
) -> Result<()> {
    // Cargo tree applies package, feature, edge and target selection. Metadata
    // supplies the selected packages' original source paths and license fields.
    let tree = cargo_output(
        Command::new(cargo)
            .current_dir(root)
            .args([
                "tree",
                "--locked",
                "--color",
                "never",
                "--target",
                target,
                "--edges",
                "normal,no-proc-macro",
                "--prefix",
                "none",
                "--format",
                "{p}",
            ])
            .args(selection),
    )?;
    let keys = String::from_utf8(tree)?
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            let version = fields.next()?.strip_prefix('v')?;
            Some((name.to_owned(), version.to_owned()))
        })
        .collect::<BTreeSet<_>>();
    if keys.is_empty() {
        return Err(format!("Cargo reported no runtime dependencies for {target}").into());
    }
    let metadata = cargo_output(Command::new(cargo).current_dir(root).args([
        "metadata",
        "--locked",
        "--format-version",
        "1",
        "--filter-platform",
        target,
    ]))?;
    let metadata: Value = serde_json::from_slice(&metadata)?;
    let rows = metadata["packages"]
        .as_array()
        .ok_or("Cargo metadata packages missing")?;
    let workspace = metadata["workspace_members"]
        .as_array()
        .ok_or("Cargo metadata workspace members missing")?
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let mut selected = BTreeMap::new();
    for row in rows {
        let key = (
            field(row, "name")?.to_owned(),
            field(row, "version")?.to_owned(),
        );
        if keys.contains(&key) && selected.insert(key, row).is_some() {
            return Err("multiple Cargo sources match a selected dependency".into());
        }
    }
    for key in keys {
        let row = selected
            .get(&key)
            .ok_or_else(|| format!("missing Cargo metadata for {} {}", key.0, key.1))?;
        if workspace.contains(field(row, "id")?) {
            continue;
        }
        if let Some(package) = packages.get_mut(&key) {
            package.targets.insert(target.into());
            continue;
        }
        let directory = Path::new(field(row, "manifest_path")?)
            .parent()
            .ok_or("Cargo package directory missing")?;
        let mut files = BTreeSet::new();
        if let Some(file) = row["license_file"].as_str() {
            files.insert(directory.join(file));
        }
        for file in fs::read_dir(directory)? {
            let file = file?;
            if file.file_type()?.is_file() && is_notice_name(&file.file_name()) {
                files.insert(file.path());
            }
        }
        if files.is_empty() {
            files.insert(upstream_notice(root, &key, directory)?);
        }
        let expression = row["license"]
            .as_str()
            .unwrap_or("see the upstream license file");
        packages.insert(
            key,
            Package {
                expression: expression.into(),
                files,
                targets: BTreeSet::from([target.into()]),
            },
        );
    }
    Ok(())
}

fn is_notice_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    let stem = name.split(['-', '_', '.']).next().unwrap_or("");
    matches!(
        stem,
        "license" | "licence" | "copying" | "copyright" | "notice" | "unlicense"
    )
}

fn cargo_output(command: &mut Command) -> Result<Vec<u8>> {
    let output = command.stderr(Stdio::inherit()).output()?;
    if !output.status.success() {
        return Err(format!("Cargo license discovery failed with {}", output.status).into());
    }
    Ok(output.stdout)
}

fn field<'a>(row: &'a Value, key: &str) -> Result<&'a str> {
    Ok(row[key]
        .as_str()
        .ok_or_else(|| format!("Cargo metadata {key} is missing"))?)
}

fn upstream_notice(root: &Path, key: &PackageKey, directory: &Path) -> Result<PathBuf> {
    let vcs = fs::read(directory.join(".cargo_vcs_info.json"))
        .ok()
        .and_then(|data| serde_json::from_slice::<Value>(&data).ok());
    let revision = vcs.as_ref().and_then(|info| info["git"]["sha1"].as_str());
    let file = match (key.0.as_str(), revision) {
        (
            "jpxl-bitstream" | "jpxl-core" | "jpxl-decode" | "jpxl-entropy",
            Some("1e2004aa0672259279cc24a52d4b8e264f675b77"),
        ) => "JPXL-MIT.txt",
        ("block2", Some("b4167b582b2f75f9a1be75495c41b765344fd03c"))
        | ("objc2", Some("d7d2fa23ceaa5e6096c923b081040e5d81b3b9df"))
        | ("objc2-encode", Some("8d214f5477365ffcbcbb7de058c86ed9a518efb7"))
        | ("objc2-foundation", Some("7b1abfd750a2cacaea71d6a56ecfb83cb7de560b")) => "objc2-MIT.md",
        _ => return Err(format!("upstream license text missing for {} {}", key.0, key.1).into()),
    };
    Ok(root.join("tools/xtask/licenses").join(file))
}
