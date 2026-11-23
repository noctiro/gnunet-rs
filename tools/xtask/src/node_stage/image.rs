//! Stage the foreground executable and the selected system-image recipe.
mod small_linux;

use super::{
    OperatingSystem, Result, RustTarget,
    build::{IMAGE_NAT_HELPERS, Plan},
    compiler_target,
    prefix::copy_new,
    publication::Output,
};
use serde_json::{Map, Value};
use std::{
    env,
    ffi::OsString,
    fs::{self, File},
    io::{self, Read, Write},
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    num::{NonZeroU16, NonZeroUsize},
    path::{Path, PathBuf},
};

const HELPER_DIRECTORY_OPTION: &str = "--nat-helpers-directory";
const ANDROID_BIN: &str = "/vendor/bin";
const HARMONY_BIN: &str = "/system/bin";

struct Arguments {
    output: PathBuf,
    target: OsString,
    policy: Option<PathBuf>,
    small_linux: bool,
    jobs: NonZeroUsize,
    include_nat_helpers: bool,
}

impl Arguments {
    fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Self> {
        let mut output = None;
        let mut target = None;
        let mut policy = None;
        let mut small_linux = false;
        let mut jobs = None;
        let mut include_nat_helpers = false;
        while let Some(option) = args.next() {
            if option == "--include-nat-helpers" {
                if include_nat_helpers {
                    return Err("duplicate image option --include-nat-helpers".into());
                }
                include_nat_helpers = true;
                continue;
            }
            let value = args
                .next()
                .filter(|value| !value.is_empty() && !value.as_encoded_bytes().starts_with(b"--"))
                .ok_or("stage-node-image expects an option and its nonempty value")?;
            match option.to_str() {
                Some("--output") if output.is_none() => output = Some(value.into()),
                Some("--target") if target.is_none() => target = Some(value),
                Some("--policy") if policy.is_none() => policy = Some(value.into()),
                Some("--profile") if !small_linux && value == "openharmony-small-linux" => {
                    small_linux = true;
                }
                Some("--jobs") if jobs.is_none() => {
                    jobs = Some(
                        value
                            .to_str()
                            .ok_or("expected a positive job count")?
                            .parse()?,
                    );
                }
                _ => return Err(format!("unexpected or duplicate image option {option:?}").into()),
            }
        }
        Ok(Self {
            output: output.ok_or("stage-node-image requires --output")?,
            target: target.ok_or("stage-node-image requires --target")?,
            policy,
            small_linux,
            jobs: jobs.unwrap_or(NonZeroUsize::MIN),
            include_nat_helpers,
        })
    }
}

enum ImageProfile {
    Android,
    OpenHarmonySdk,
    OpenHarmonySmallLinux,
}

impl ImageProfile {
    fn select(target: RustTarget, triple: &str, small_linux: bool) -> Result<Self> {
        if small_linux {
            if target.os != OperatingSystem::Linux || triple != small_linux::TARGET {
                return Err(format!(
                    "OpenHarmony small-system Linux image requires Rust target {}",
                    small_linux::TARGET
                )
                .into());
            }
            return Ok(Self::OpenHarmonySmallLinux);
        }
        match target.os {
            OperatingSystem::Android => Ok(Self::Android),
            OperatingSystem::OpenHarmony => Ok(Self::OpenHarmonySdk),
            os => Err(format!("no system-image GNUnet recipe for {}", os.name()).into()),
        }
    }
}

struct Recipe(Vec<(&'static str, Vec<u8>)>);

impl Recipe {
    fn load(
        root: &Path,
        profile: &ImageProfile,
        policy: Option<&Path>,
        include_nat_helpers: bool,
    ) -> Result<Self> {
        let mut files = Vec::new();
        match profile {
            ImageProfile::Android => {
                if policy.is_some() {
                    return Err(
                        "Android service accounts and labels are assigned by the board build"
                            .into(),
                    );
                }
                let root = root.join("platform/android/system");
                let (build, init) = android_recipe(&root, include_nat_helpers)?;
                files.push(("Android.bp", build.into_bytes()));
                files.push(("gnunet-node.rc", init.into_bytes()));
                files.push(("README.md", fs::read(root.join("README.md"))?));
            }
            ImageProfile::OpenHarmonySdk => {
                let policy = policy.ok_or("OpenHarmony system images require --policy")?;
                let policy =
                    HarmonyPolicy::parse(read_json(policy, 16 * 1024)?, include_nat_helpers)?;
                let root = root.join("platform/openharmony/system");
                let build = harmony_build(&root, &policy, include_nat_helpers)?;
                let config = fs::read_to_string(root.join("gnunet-node.cfg.in"))?
                    .replace("@UID@", &policy.node.uid.to_string())
                    .replace("@GID@", &policy.node.gid.to_string())
                    .replace("@SELINUX_CONTEXT@", &policy.domain)
                    .replace("@STATE_DIRECTORY@", &policy.node.state)
                    .replace("@IPC_DIRECTORY@", &policy.node.ipc)
                    .replace(
                        "@ARGUMENTS@",
                        &serde_json::to_string(&policy.node.arguments)?,
                    );
                let rendered = format_json(&serde_json::from_str(&config)?)?;
                files.push(("BUILD.gn", build.into_bytes()));
                files.push(("gnunet-node.cfg", rendered));
                files.push(("README.md", fs::read(root.join("README.md"))?));
            }
            ImageProfile::OpenHarmonySmallLinux => {
                if include_nat_helpers {
                    return Err(
                        "OpenHarmony small-system Linux image does not install raw ICMP helpers"
                            .into(),
                    );
                }
                let policy = policy.ok_or("OpenHarmony system images require --policy")?;
                let mut policy = read_json(policy, 16 * 1024)?;
                let policy =
                    NodePolicy::parse(policy_fields(&mut policy)?, small_linux::PATHS, false)?;
                let assets = root.join("platform/openharmony/system/small-linux");
                files.push(("BUILD.gn", fs::read(assets.join("BUILD.gn"))?));
                files.push(("gnunet-node.cfg", small_linux::init(&policy)?));
                files.push(("README.md", fs::read(assets.join("README.md"))?));
            }
        }
        Ok(Self(files))
    }
}

fn read_json(path: &Path, limit: u64) -> Result<Value> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(format!("{} exceeds the {limit}-byte JSON limit", path.display()).into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn format_json(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn android_recipe(root: &Path, include_nat_helpers: bool) -> Result<(String, String)> {
    let required = if include_nat_helpers {
        let names = IMAGE_NAT_HELPERS
            .map(|(_, name)| format!("\"{name}\""))
            .join(", ");
        format!("    required: [{names}],\n")
    } else {
        String::new()
    };
    let mut build =
        fs::read_to_string(root.join("Android.bp.in"))?.replace("@NAT_HELPER_REQUIRED@", &required);
    let arguments = if include_nat_helpers {
        let helper = fs::read_to_string(root.join("nat-helper.bp.in"))?;
        for (_, name) in IMAGE_NAT_HELPERS {
            build.push('\n');
            build.push_str(&helper.replace("@NAME@", name));
        }
        format!(" {HELPER_DIRECTORY_OPTION} {ANDROID_BIN}")
    } else {
        String::new()
    };
    let init = fs::read_to_string(root.join("gnunet-node.rc.in"))?
        .replace("@NAT_HELPER_ARGUMENTS@", &arguments);
    Ok((build, init))
}

fn harmony_build(root: &Path, policy: &HarmonyPolicy, include_nat_helpers: bool) -> Result<String> {
    let mut dependencies = String::new();
    let mut targets = String::new();
    if include_nat_helpers {
        let helper = fs::read_to_string(root.join("nat-helper.gn.in"))?;
        for (_, name) in IMAGE_NAT_HELPERS {
            dependencies.push_str(&format!("    \":{name}\",\n"));
            targets.push_str("\n\n");
            targets.push_str(helper.replace("@NAME@", name).trim_end());
        }
    }
    Ok(fs::read_to_string(root.join("BUILD.gn.in"))?
        .replace("@NAT_HELPER_DEPS@", &dependencies)
        .replace("@NAT_HELPER_TARGETS@", &targets)
        .replace("@PART@", &policy.part)
        .replace("@SUBSYSTEM@", &policy.subsystem))
}

struct HarmonyPolicy {
    domain: String,
    part: String,
    subsystem: String,
    node: NodePolicy,
}

impl HarmonyPolicy {
    fn parse(mut input: Value, include_nat_helpers: bool) -> Result<Self> {
        let fields = policy_fields(&mut input)?;
        let part = policy_text(fields, "part")?;
        let subsystem = policy_text(fields, "subsystem")?;
        if !safe_label(&part) || !safe_label(&subsystem) {
            return Err("OpenHarmony part and subsystem must be safe GN identifiers".into());
        }
        let domain = policy_text(fields, "selinux_context")?;
        if !domain
            .strip_prefix("u:r:")
            .and_then(|name| name.strip_suffix(":s0"))
            .is_some_and(safe_label)
        {
            return Err("expected an explicit OpenHarmony SELinux context u:r:TYPE:s0".into());
        }
        let node = NodePolicy::parse(
            fields,
            ImagePaths {
                executable: "/system/bin/gnunet-node",
                runtime_root: "/data/",
                config_root: "/system/",
                required_mount: None,
            },
            include_nat_helpers,
        )?;
        Ok(Self {
            domain,
            part,
            subsystem,
            node,
        })
    }
}

struct ImagePaths {
    executable: &'static str,
    runtime_root: &'static str,
    config_root: &'static str,
    required_mount: Option<&'static str>,
}

struct NodePolicy {
    uid: u32,
    gid: u32,
    state: String,
    ipc: String,
    arguments: Vec<String>,
}

impl NodePolicy {
    fn parse(
        fields: &mut Map<String, Value>,
        paths: ImagePaths,
        include_nat_helpers: bool,
    ) -> Result<Self> {
        let uid = policy_number(fields, "uid")?;
        let gid = policy_number(fields, "gid")?;
        let state = image_path(policy_text(fields, "state_directory")?, paths.runtime_root)?;
        let ipc = image_path(policy_text(fields, "ipc_directory")?, paths.runtime_root)?;
        if state == ipc
            || Path::new(&state).starts_with(&ipc)
            || Path::new(&ipc).starts_with(&state)
        {
            return Err("OpenHarmony state and IPC directories must be separate".into());
        }
        let mode = policy_text(fields, "peer_mode")?;
        let mut arguments = vec![
            paths.executable.into(),
            "--state-directory".into(),
            state.clone(),
            "--ipc-directory".into(),
            ipc.clone(),
        ];
        if let Some(mount) = paths.required_mount {
            arguments.extend(["--require-storage-mount".into(), mount.into()]);
        }
        match mode.as_str() {
            "outbound-tcp" => arguments.push("--outbound-tcp".into()),
            "listening" => {
                let (tcp_flag, address) = if let Some(port) = fields.remove("tcp_dual_stack") {
                    let port = port
                        .as_u64()
                        .and_then(|port| u16::try_from(port).ok())
                        .and_then(NonZeroU16::new)
                        .ok_or("tcp_dual_stack must be a nonzero TCP port")?;
                    ("--tcp-dual-stack", port.to_string())
                } else {
                    let address = fields
                        .remove("tcp_bind")
                        .and_then(|value| value.as_str()?.parse::<SocketAddr>().ok())
                        .ok_or("listening requires a numeric tcp_bind or tcp_dual_stack")?;
                    ("--tcp-bind", address.to_string())
                };
                let udp4 = fields
                    .remove("udp4_bind")
                    .and_then(|value| value.as_str()?.parse::<SocketAddrV4>().ok())
                    .ok_or("listening requires a numeric IPv4 udp4_bind")?;
                arguments.extend([
                    tcp_flag.into(),
                    address,
                    "--udp4-bind".into(),
                    udp4.to_string(),
                ]);
                if let Some(udp6) = fields.remove("udp6_bind") {
                    let udp6 = udp6
                        .as_str()
                        .and_then(|value| value.parse::<SocketAddrV6>().ok())
                        .filter(|address| address.ip().to_ipv4_mapped().is_none())
                        .ok_or("udp6_bind must be a native numeric IPv6 address")?;
                    arguments.extend(["--udp6-bind".into(), udp6.to_string()]);
                }
            }
            _ => return Err("OpenHarmony peer_mode must be outbound-tcp or listening".into()),
        }
        for (key, flag) in [
            ("config_file", "--config"),
            ("bootstrap_data_directory", "--bootstrap-data-directory"),
        ] {
            if let Some(value) = fields.remove(key) {
                let Value::String(path) = value else {
                    return Err(format!("OpenHarmony {key} must be a path").into());
                };
                arguments.extend([flag.into(), image_path(path, paths.config_root)?]);
            }
        }
        if let Some(dns) = fields.remove("dns_servers") {
            let Value::Array(dns) = dns else {
                return Err("dns_servers must be an array of numeric endpoints".into());
            };
            for address in dns {
                let address = address
                    .as_str()
                    .and_then(|value| value.parse::<SocketAddr>().ok())
                    .filter(|address| address.port() != 0 && !address.ip().is_unspecified())
                    .ok_or("dns_servers must contain numeric endpoints with nonzero ports")?;
                arguments.extend(["--dns-server".into(), address.to_string()]);
            }
        }
        if let Some(key) = fields.keys().next() {
            return Err(format!("unknown or conflicting OpenHarmony policy field {key}").into());
        }
        if include_nat_helpers {
            arguments.extend([HELPER_DIRECTORY_OPTION.into(), HARMONY_BIN.into()]);
        }
        if arguments.len() > 20 || arguments.iter().any(|arg| arg.len() > 64) {
            return Err("OpenHarmony init permits at most 20 arguments of at most 64 bytes".into());
        }
        Ok(Self {
            uid,
            gid,
            state,
            ipc,
            arguments,
        })
    }
}

fn policy_fields(input: &mut Value) -> Result<&mut Map<String, Value>> {
    input
        .as_object_mut()
        .ok_or_else(|| "expected an OpenHarmony policy object".into())
}

fn policy_text(fields: &mut Map<String, Value>, key: &str) -> Result<String> {
    match fields.remove(key) {
        Some(Value::String(text)) => Ok(text),
        _ => Err(format!("OpenHarmony policy requires {key}").into()),
    }
}

fn policy_number(fields: &mut Map<String, Value>, key: &str) -> Result<u32> {
    fields
        .remove(key)
        .and_then(|value| value.as_u64())
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| (1..=i32::MAX as u32).contains(value))
        .ok_or_else(|| format!("{key} must be a positive non-root image ID").into())
}

fn safe_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn image_path(path: String, prefix: &str) -> Result<String> {
    if path.len() <= 64
        && path.strip_prefix(prefix).is_some_and(|relative| {
            relative.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
            })
        })
    {
        Ok(path)
    } else {
        Err(format!("expected a literal image path under {prefix}").into())
    }
}

pub(crate) fn run(root: &Path, args: impl Iterator<Item = OsString>) -> Result<()> {
    let options = Arguments::parse(args)?;
    let (triple, cfg) = compiler_target(Some(options.target))?;
    let target = RustTarget::from_cfg(&cfg).ok_or("unsupported system-image Rust target")?;
    let profile = ImageProfile::select(target, &triple, options.small_linux)?;
    let Recipe(files) = Recipe::load(
        root,
        &profile,
        options.policy.as_deref(),
        options.include_nat_helpers,
    )?;
    let output = Output::resolve(&options.output)?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let plan = Plan::resolve_image(&cargo, root, options.include_nat_helpers)?;
    let artifacts = plan.build(&cargo, root, &triple, "", Some(options.jobs))?;
    let image = output.begin()?;
    for artifact in artifacts.iter() {
        let staged = image.path().join(artifact.name);
        copy_new(artifact.file(), &staged)?;
        if matches!(profile, ImageProfile::OpenHarmonySmallLinux) {
            small_linux::validate_executable(&staged)?;
        }
    }
    for (name, contents) in files {
        fs::write(image.path().join(name), contents)?;
    }
    crate::licenses::stage(
        root,
        &cargo,
        [triple.as_str()],
        &plan.cargo_selection(),
        image.path(),
    )?;
    image.publish()?;
    writeln!(
        io::stdout().lock(),
        "Staged {} node image input at {}",
        triple,
        options.output.display()
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy() -> Value {
        json!({
            "uid": 3401, "gid": 3401, "selinux_context": "u:r:gnunet_node:s0",
            "part": "gnunet_node", "subsystem": "custom",
            "state_directory": "/data/gnunet/state", "ipc_directory": "/data/gnunet/ipc",
            "peer_mode": "outbound-tcp"
        })
    }

    #[test]
    fn taurus_image_requires_the_static_arm_target_and_lite_init_paths() -> Result<()> {
        let args = [
            "--output",
            "image",
            "--target",
            small_linux::TARGET,
            "--profile",
            "openharmony-small-linux",
        ]
        .map(OsString::from);
        let options = Arguments::parse(args.into_iter())?;
        let linux = RustTarget::from_cfg("target_os=\"linux\"\ntarget_env=\"musl\"")
            .ok_or("invalid Linux test configuration")?;
        if !matches!(
            ImageProfile::select(linux, small_linux::TARGET, options.small_linux)?,
            ImageProfile::OpenHarmonySmallLinux
        ) || ImageProfile::select(linux, "armv7-unknown-linux-musleabihf", true).is_ok()
            || ImageProfile::select(linux, small_linux::TARGET, false).is_ok()
        {
            return Err("image profile did not select the exact ARM soft-float target".into());
        }

        let mut input = json!({
            "uid": 3401, "gid": 3402, "peer_mode": "outbound-tcp",
            "state_directory": "/storage/data/gnunet-state",
            "ipc_directory": "/storage/data/gnunet-ipc",
        });
        let config = NodePolicy::parse(policy_fields(&mut input)?, small_linux::PATHS, false)?;
        let init: Value = serde_json::from_slice(&small_linux::init(&config)?)?;
        if init["jobs"]
            != json!([{
                "name": "post-init",
                "cmds": [
                    "mkdir /storage/data/gnunet-state 0700 3401 3402",
                    "mkdir /storage/data/gnunet-ipc 0700 3401 3402",
                    "start gnunet-node",
                ],
            }])
            || init["services"][0]["path"][0] != "/bin/gnunet-node"
            || init["services"][0]["path"][5] != "--require-storage-mount"
            || init["services"][0]["path"][6] != "/storage"
            || init["services"][0]["uid"] != 3401
            || init["services"][0]["gid"] != 3402
            || init["services"][0]["caps"] != json!([])
        {
            return Err("Taurus Lite init lost the executable or non-root ownership".into());
        }
        Ok(())
    }

    #[test]
    fn image_policy_supplies_one_privilege_and_argument_profile() -> Result<()> {
        let base = HarmonyPolicy::parse(policy(), false)?;
        if base.node.arguments
            != [
                "/system/bin/gnunet-node",
                "--state-directory",
                "/data/gnunet/state",
                "--ipc-directory",
                "/data/gnunet/ipc",
                "--outbound-tcp",
            ]
        {
            return Err("image did not preserve the exact foreground arguments".into());
        }
        for (field, invalid) in [
            ("uid", json!(0)),
            ("ipc_directory", json!("/data/gnunet/state/ipc")),
            ("ipc_directory", json!("/data/gnunet/../ipc")),
            ("part", json!("image\"\nimport")),
            ("tcp_bind", json!("127.0.0.1:0")),
            ("dns_servers", json!(vec!["127.0.0.1:53"; 8])),
        ] {
            let mut input = policy();
            input[field] = invalid;
            if HarmonyPolicy::parse(input, false).is_ok() {
                return Err(format!("system image accepted invalid field {field}").into());
            }
        }
        Ok(())
    }

    #[test]
    fn optional_nat_helpers_match_the_image_commands() -> Result<()> {
        let args = [
            "--output",
            "image",
            "--target",
            "aarch64-linux-android",
            "--include-nat-helpers",
        ]
        .map(OsString::from);
        let options = Arguments::parse(args.clone().into_iter())?;
        if !options.include_nat_helpers
            || Arguments::parse(
                args.into_iter()
                    .chain([OsString::from("--include-nat-helpers")]),
            )
            .is_ok()
        {
            return Err("image option did not preserve explicit helper selection".into());
        }

        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let android = root.join("platform/android/system");
        let (default_build, default_init) = android_recipe(&android, false)?;
        if default_build.contains("gnunet-helper-nat")
            || default_build.contains("@NAT_")
            || default_init.contains(HELPER_DIRECTORY_OPTION)
            || default_init.contains("@NAT_")
            || !default_init
                .lines()
                .next()
                .is_some_and(|line| line.ends_with(" --outbound-tcp"))
        {
            return Err("default Android recipe selected optional NAT helpers".into());
        }
        let (build, init) = android_recipe(&android, options.include_nat_helpers)?;
        if !init
            .lines()
            .next()
            .is_some_and(|line| line.ends_with(" --nat-helpers-directory /vendor/bin"))
            || !build
                .contains("required: [\"gnunet-helper-nat-client\", \"gnunet-helper-nat-server\"]")
        {
            return Err("Android recipe does not install and select the helper pair".into());
        }

        let harmony = root.join("platform/openharmony/system");
        let home = HarmonyPolicy::parse(policy(), true)?;
        let harmony_build = harmony_build(&harmony, &home, true)?;
        if !home
            .node
            .arguments
            .ends_with(&[HELPER_DIRECTORY_OPTION.into(), "/system/bin".into()])
            || harmony_build
                .matches("module_install_dir = \"bin\"")
                .count()
                != 3
        {
            return Err("OpenHarmony helper targets do not match their command path".into());
        }
        for (_, name) in IMAGE_NAT_HELPERS {
            if !build.contains(&format!("name: \"{name}\""))
                || !build.contains(&format!("srcs: [\"{name}\"]"))
                || !harmony_build.contains(&format!("\":{name}\""))
                || !harmony_build.contains(&format!("ohos_prebuilt_executable(\"{name}\")"))
            {
                return Err(format!("image recipes omitted native helper {name}").into());
            }
        }
        let mut at_limit = policy();
        at_limit["dns_servers"] = json!(vec!["127.0.0.1:53"; 7]);
        if HarmonyPolicy::parse(at_limit.clone(), false).is_err()
            || HarmonyPolicy::parse(at_limit, true).is_ok()
        {
            return Err("helper arguments do not count against the init limit".into());
        }
        Ok(())
    }
}
