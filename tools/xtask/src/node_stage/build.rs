//! Match compiler artifacts to their workspace package and Cargo target.
use super::{
    Result, Target,
    catalog::{self, Location},
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs,
    io::{BufRead, BufReader},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

struct Package {
    name: String,
    feature: Option<&'static str>,
    targets: BTreeMap<&'static str, Location>,
}

struct Selection {
    directory: &'static str,
    feature: Option<&'static str>,
    artifacts: Vec<(&'static str, Location)>,
}

pub(super) const IMAGE_NAT_HELPERS: [(&str, &str); 2] = [
    ("apps/gnunet-helper-nat-client", "gnunet-helper-nat-client"),
    ("apps/gnunet-helper-nat-server", "gnunet-helper-nat-server"),
];

fn image_selections(include_nat_helpers: bool) -> impl Iterator<Item = Selection> {
    [("apps/gnunet-node", "gnunet-node")]
        .into_iter()
        .chain(
            include_nat_helpers
                .then_some(IMAGE_NAT_HELPERS)
                .into_iter()
                .flatten(),
        )
        .map(|(directory, name)| Selection {
            directory,
            feature: None,
            artifacts: vec![(name, Location::Bin)],
        })
}

pub(super) struct Plan {
    packages: BTreeMap<String, Package>,
}

pub(super) struct Artifact {
    pub location: Location,
    pub name: &'static str,
    source: PathBuf,
    file: fs::File,
}

impl Artifact {
    pub(super) fn file(&self) -> &fs::File {
        &self.file
    }
}

pub(super) struct Artifacts(Vec<Artifact>);

impl Artifacts {
    pub(super) fn iter(&self) -> impl Iterator<Item = &Artifact> {
        self.0.iter()
    }
}

impl Plan {
    pub(super) fn cargo_selection(&self) -> Vec<OsString> {
        let mut selection = Vec::new();
        for package in self.packages.values() {
            selection.extend([OsString::from("--package"), OsString::from(&package.name)]);
            if let Some(feature) = package.feature {
                selection.extend([
                    OsString::from("--features"),
                    OsString::from(format!("{}/{feature}", package.name)),
                ]);
            }
        }
        selection
    }

    pub(super) fn resolve(cargo: &OsStr, root: &Path, target: &Target) -> Result<Self> {
        Self::resolve_catalog(
            cargo,
            root,
            catalog::packages(target).map(|rule| Selection {
                directory: rule.directory,
                feature: rule.features,
                artifacts: rule.artifacts(target).collect(),
            }),
        )
    }

    pub(super) fn resolve_image(
        cargo: &OsStr,
        root: &Path,
        include_nat_helpers: bool,
    ) -> Result<Self> {
        Self::resolve_catalog(cargo, root, image_selections(include_nat_helpers))
    }

    fn resolve_catalog(
        cargo: &OsStr,
        root: &Path,
        selections: impl IntoIterator<Item = Selection>,
    ) -> Result<Self> {
        let output = Command::new(cargo)
            .current_dir(root)
            .args(["metadata", "--no-deps", "--locked", "--format-version", "1"])
            .stderr(Stdio::inherit())
            .output()?;
        if !output.status.success() {
            return Err("Cargo could not resolve the native node packages".into());
        }
        let metadata: Value = serde_json::from_slice(&output.stdout)?;
        Self::from_metadata(root, &metadata, selections)
    }

    fn from_metadata(
        root: &Path,
        metadata: &Value,
        selections: impl IntoIterator<Item = Selection>,
    ) -> Result<Self> {
        let reported = metadata["packages"]
            .as_array()
            .ok_or("Cargo metadata has no packages")?;
        let mut packages = BTreeMap::new();
        let mut names = BTreeSet::new();
        for rule in selections {
            let manifest = root.join(rule.directory).join("Cargo.toml");
            let package = reported
                .iter()
                .find(|entry| {
                    entry["manifest_path"].as_str().map(Path::new) == Some(manifest.as_path())
                })
                .ok_or_else(|| {
                    format!(
                        "node package absent from Cargo metadata: {}",
                        rule.directory
                    )
                })?;
            let id = text(package, "id")?;
            let name = text(package, "name")?;
            let declared = package["targets"]
                .as_array()
                .ok_or("Cargo package has no targets")?;
            let mut targets = BTreeMap::new();
            for (artifact, location) in rule.artifacts {
                if !declared
                    .iter()
                    .any(|entry| entry["name"] == artifact && matches_kind(entry, location))
                {
                    return Err(format!("{name} does not declare native target {artifact}").into());
                }
                if !names.insert(artifact) {
                    return Err(format!("more than one staged target is named {artifact}").into());
                }
                targets.insert(artifact, location);
            }
            if packages
                .insert(
                    id.to_owned(),
                    Package {
                        name: name.to_owned(),
                        feature: rule.feature,
                        targets,
                    },
                )
                .is_some()
            {
                return Err(format!("duplicate staged package {name}").into());
            }
        }
        Ok(Self { packages })
    }

    pub(super) fn build(
        &self,
        cargo: &OsStr,
        root: &Path,
        triple: &str,
        executable_suffix: &str,
        jobs: Option<NonZeroUsize>,
    ) -> Result<Artifacts> {
        let mut command = Command::new(cargo);
        command.current_dir(root).args([
            "build",
            "--locked",
            "--release",
            "--message-format=json-render-diagnostics",
            "--target",
            triple,
        ]);
        if let Some(jobs) = jobs {
            command.arg("--jobs").arg(jobs.to_string());
        }
        command.args(self.cargo_selection());
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let collected = (|| {
            let output = child.stdout.take().ok_or("missing Cargo artifact pipe")?;
            self.collect(BufReader::new(output), executable_suffix)
        })();
        let status = child.wait()?;
        if !status.success() {
            return Err(format!("Cargo node build failed with {status}").into());
        }
        collected
    }

    fn collect(&self, messages: impl BufRead, executable_suffix: &str) -> Result<Artifacts> {
        let mut artifacts = BTreeMap::<&'static str, Artifact>::new();
        let mut finished = false;
        for line in messages.lines() {
            let message: Value = serde_json::from_str(&line?)?;
            if message["reason"] == "build-finished" {
                finished = message["success"] == true;
            }
            if message["reason"] != "compiler-artifact" || message["profile"]["test"] != false {
                continue;
            }
            let id = text(&message, "package_id")?;
            let Some(package) = self.packages.get(id) else {
                continue;
            };
            let declaration = &message["target"];
            let name = text(declaration, "name")?;
            let Some((&name, &location)) = package.targets.get_key_value(name) else {
                continue;
            };
            if !matches_kind(declaration, location) {
                continue;
            }
            let source = artifact_path(&message, name, location, executable_suffix)?;
            if let Some(old) = artifacts.get(name) {
                if old.source != source {
                    return Err(format!("ambiguous Cargo artifact for {name}").into());
                }
            } else {
                let file = fs::File::open(&source)?;
                let metadata = file.metadata()?;
                if !metadata.is_file() || metadata.len() == 0 {
                    return Err(format!("invalid opened Cargo artifact for {name}").into());
                }
                artifacts.insert(
                    name,
                    Artifact {
                        location,
                        name,
                        source,
                        file,
                    },
                );
            }
        }
        if !finished {
            return Err("Cargo did not report a successful complete native build".into());
        }
        for package in self.packages.values() {
            for name in package.targets.keys() {
                if !artifacts.contains_key(name) {
                    return Err(format!(
                        "Cargo omitted native target {name} from {}",
                        package.name
                    )
                    .into());
                }
            }
        }
        Ok(Artifacts(artifacts.into_values().collect()))
    }
    pub(super) fn contains_libexec(&self, name: &str) -> bool {
        self.packages
            .values()
            .any(|package| package.targets.get(name) == Some(&Location::Libexec))
    }
}

fn matches_kind(target: &Value, location: Location) -> bool {
    let (key, expected) = match location {
        Location::Bin | Location::Libexec => ("kind", "bin"),
        Location::Nss => ("crate_types", "cdylib"),
    };
    target[key]
        .as_array()
        .is_some_and(|values| values.iter().any(|value| value == expected))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("Cargo metadata missing {key}").into())
}

fn artifact_path(
    message: &Value,
    name: &str,
    location: Location,
    executable_suffix: &str,
) -> Result<PathBuf> {
    let source = if location == Location::Nss {
        message["filenames"]
            .as_array()
            .and_then(|paths| {
                let mut paths = paths.iter().filter_map(Value::as_str).filter(|path| {
                    Path::new(path).file_name() == Some(OsStr::new("libnss_gns.so"))
                });
                let value = paths.next()?;
                paths.next().is_none().then_some(value)
            })
            .ok_or("missing unversioned GNU NSS artifact")?
    } else {
        let source = text(message, "executable")?;
        if Path::new(source).file_name() != Some(OsStr::new(&format!("{name}{executable_suffix}")))
        {
            return Err(format!("Cargo returned a different executable name for {name}").into());
        }
        source
    };
    let path = PathBuf::from(source);
    let metadata = fs::symlink_metadata(&path)?;
    if !path.is_absolute() || !metadata.is_file() || metadata.len() == 0 {
        return Err(format!("invalid Cargo artifact for {name}: {}", path.display()).into());
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_stage::{prefix, publication::Output};
    use serde_json::json;
    use std::{
        env,
        io::Cursor,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn image_plan_requires_both_nat_helper_packages_when_selected() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let package = |directory: &str, name: &str| {
            json!({
                "id": name,
                "name": name,
                "manifest_path": root.join(directory).join("Cargo.toml"),
                "targets": [{"name": name, "kind": ["bin"]}],
            })
        };
        let node = package("apps/gnunet-node", "gnunet-node");
        let [client, server] = IMAGE_NAT_HELPERS.map(|(directory, name)| package(directory, name));
        for incomplete in [
            json!({"packages": [&node, &client]}),
            json!({"packages": [&node, &server]}),
        ] {
            if Plan::from_metadata(&root, &incomplete, image_selections(true)).is_ok() {
                return Err("image plan accepted one missing NAT helper".into());
            }
        }
        let all = json!({"packages": [node, client, server]});
        let default_plan = Plan::from_metadata(&root, &all, image_selections(false))?;
        let helper_plan = Plan::from_metadata(&root, &all, image_selections(true))?;
        if default_plan.packages.len() != 1 || helper_plan.packages.len() != 3 {
            return Err("image plan selected unexpected packages".into());
        }
        Ok(())
    }

    #[test]
    fn stage_uses_the_original_cargo_target_and_a_fresh_prefix() -> Result<()> {
        struct Directory(PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _cleanup = fs::remove_dir_all(&self.0);
            }
        }
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = env::temp_dir().join(format!("gnunet-stage-{}-{nonce:x}", std::process::id()));
        fs::create_dir(&root)?;
        let directory = Directory(root);
        let binary = directory.0.join("gnunet-arm.exe");
        fs::write(&binary, b"fixture artifact")?;
        let target = Target::from_cfg("x86_64-pc-windows-msvc".into(), "target_os=\"windows\"")?;
        let plan = Plan {
            packages: BTreeMap::from([(
                "workspace-arm".to_owned(),
                Package {
                    name: "gnunet-arm-cli".to_owned(),
                    feature: None,
                    targets: BTreeMap::from([("gnunet-arm", Location::Bin)]),
                },
            )]),
        };
        let message = |package_id: &str, test: bool| {
            json!({
                "reason": "compiler-artifact", "package_id": package_id,
                "executable": binary, "target": {"name": "gnunet-arm", "kind": ["bin"]},
                "profile": {"test": test},
            })
        };
        let finished = json!({"reason": "build-finished", "success": true});
        let wrong = format!(
            "{}\n{}\n{finished}\n",
            message("foreign-arm", false),
            message("workspace-arm", true)
        );
        if plan
            .collect(Cursor::new(wrong.as_bytes()), target.executable_suffix())
            .is_ok()
        {
            return Err("foreign binary or test executable completed a release plan".into());
        }
        let messages = format!("{}\n{finished}\n", message("workspace-arm", false));
        let artifacts =
            plan.collect(Cursor::new(messages.as_bytes()), target.executable_suffix())?;
        fs::rename(&binary, directory.0.join("retired artifact.exe"))?;
        fs::write(&binary, b"replacement artifact")?;
        let output = directory.0.join("installed prefix");
        let stage = Output::resolve(&output)?.begin()?;
        prefix::stage(
            stage.path(),
            &target,
            artifacts,
            prefix::Data::load(None, None)?,
            &super::super::service::Assets::new(target.platform(), None)?,
        )?;
        stage.publish()?;
        if fs::read(output.join("bin/gnunet-arm.exe"))? != b"fixture artifact"
            || !output.join("share/gnunet/config.d/00-paths.conf").is_file()
            || !output.join("share/gnunet/node.conf").is_file()
            || Output::resolve(&output).is_ok()
        {
            return Err(
                "stage lost an artifact, default configuration or exclusive destination".into(),
            );
        }
        Ok(())
    }
}
