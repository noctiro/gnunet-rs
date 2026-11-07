//! Historical capability ledger and C API audit evidence checks.
//! The canonical external release gate is in `external_contracts`.

use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    fs,
    io::{self, Write},
    path::{Component, Path, PathBuf},
    process::Command,
};

type CheckResult<T> = Result<T, Box<dyn Error>>;

const COMMIT: &str = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165";
const PROFILE: &str = "gnunet-0.29.1";
const API_INPUTS: &[&str] = &[
    "spec/gnunet/api/catalog.json",
    "spec/gnunet/api/declarations.json",
    "spec/gnunet/api/operations.json",
    "spec/gnunet/api/statistics.json",
];
struct ApiInventory {
    criteria: BTreeMap<String, BTreeSet<String>>,
    ready: bool,
    reference_checked: bool,
    build_checked: bool,
}
const SUBSYSTEMS: &[&str] = &[
    "util",
    "statistics",
    "testbed",
    "arm",
    "peerstore",
    "nat",
    "nat-auto",
    "pils",
    "transport",
    "core",
    "nse",
    "hostlist",
    "topology",
    "dns",
    "identity",
    "namecache",
    "namestore",
    "datacache",
    "datastore",
    "dht",
    "cadet",
    "seti",
    "setu",
    "regex",
    "revocation",
    "vpn",
    "gns",
    "zonemaster",
    "fs",
    "exit",
    "pt",
    "reclaim",
    "messenger",
    "rest",
];
const FOUNDATIONS: &[&str] = &[
    "wire",
    "crypto",
    "hello",
    "block",
    "gnsrecord",
    "service-runtime",
    "storage-contracts",
    "reference-harness",
];
const P2P: &[&str] = &[
    "transport",
    "core",
    "nse",
    "hostlist",
    "dht",
    "cadet",
    "seti",
    "setu",
    "regex",
    "revocation",
    "vpn",
    "gns",
    "fs",
    "pt",
    "exit",
    "messenger",
];
const IPC: &[&str] = &[
    "util",
    "statistics",
    "arm",
    "peerstore",
    "nat",
    "nat-auto",
    "pils",
    "transport",
    "core",
    "nse",
    "dns",
    "identity",
    "namecache",
    "namestore",
    "datastore",
    "dht",
    "cadet",
    "seti",
    "setu",
    "regex",
    "revocation",
    "vpn",
    "gns",
    "fs",
    "reclaim",
    "messenger",
];

struct Coverage {
    subsystems: usize,
    foundations: usize,
    pending: Vec<String>,
}

/// Emit noncircular current-source/requirement digests for evidence producers.
/// These are input identities only and grant no conformance credit.
pub(crate) fn evidence_inputs() -> CheckResult<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("workspace root absent")?;
    let before = crate::inputs::fingerprint()?;
    let ledger: Value =
        serde_json::from_slice(&fs::read(root.join("spec/gnunet/conformance.json"))?)?;
    let normative = crate::inputs::normative_fingerprint(root)?;
    let mut requirements = BTreeMap::new();
    for (field, owners) in [
        ("required_subsystems", SUBSYSTEMS),
        ("foundations", FOUNDATIONS),
    ] {
        for entry in array(&ledger, field)? {
            let id = text(entry, "id")?;
            if !owners.contains(&id)
                || requirements
                    .insert(id, requirements_digest(&ledger, entry, &normative)?)
                    .is_some()
            {
                return Err("unknown or duplicate requirement owner".into());
            }
        }
    }
    if requirements.len() != SUBSYSTEMS.len() + FOUNDATIONS.len()
        || crate::inputs::fingerprint()? != before
    {
        return Err("missing owner or changed inputs during evidence input capture".into());
    }
    writeln!(
        io::stdout().lock(),
        "{}",
        serde_json::json!({"schema":1,"full_gnunet_conformance_claim":false,
        "source_sha256":before.0,"spec_sha256":before.1,"normative_spec_sha256":normative,
        "requirements_algorithm":"gnunet-requirements-v1","requirements_sha256":requirements})
    )?;
    Ok(())
}

/// Audit historical ledger integrity and supplied official-C evidence.
/// Its optional strict mode preserves legacy catalog completeness semantics;
/// it is not the canonical external compatibility release gate.
/// `GNUNET_REFERENCE_SOURCE`, when set, also checks the pinned C checkout and source hashes.
pub(crate) fn check_legacy_conformance(strict: bool) -> CheckResult<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("workspace root absent")?;
    let before = crate::inputs::fingerprint()?;
    let ledger: Value =
        serde_json::from_slice(&fs::read(root.join("spec/gnunet/conformance.json"))?)?;
    let inventory = load_api_inventory(root)?;
    let coverage = validate_inventory(&ledger, root, &before.0, Some(&inventory))?;
    let reference = env::var_os("GNUNET_REFERENCE_SOURCE");
    if let Some(reference) = &reference {
        validate_reference(&ledger, Path::new(reference))?;
    }
    if crate::inputs::fingerprint()? != before {
        return Err("implementation or specification changed during the conformance check".into());
    }
    writeln!(
        io::stdout().lock(),
        "official GNUnet v0.29.1: {}/{} subsystems and {}/{} foundations verified; {} pending",
        coverage.subsystems,
        SUBSYSTEMS.len(),
        coverage.foundations,
        FOUNDATIONS.len(),
        coverage.pending.len(),
    )?;
    if strict {
        require_api_complete(&inventory)?;
        require_complete(&coverage, reference.is_some())?;
    }
    Ok(())
}

/// Validate the compiler-derived public API/operation catalog and its provenance.
/// Pending coverage is permitted only outside strict release checks.
pub(crate) fn check_api_inventory(strict: bool) -> CheckResult<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("workspace root absent")?;
    let before = crate::inputs::fingerprint()?;
    let inventory = load_api_inventory(root)?;
    if crate::inputs::fingerprint()? != before {
        return Err(
            "implementation or specification changed during API inventory validation".into(),
        );
    }
    if strict {
        require_api_complete(&inventory)?;
    }
    Ok(())
}

fn load_api_inventory(root: &Path) -> CheckResult<ApiInventory> {
    // Execute the fixed repository checker, never commands supplied by catalog data.
    let mut command = Command::new("python3");
    command.current_dir(root).args([
        "-B",
        "tools/api_inventory/check.py",
        "--json",
        "--requirements",
    ]);
    if let Some(source) = env::var_os("GNUNET_REFERENCE_SOURCE") {
        command.arg("--source").arg(source);
    }
    if let Some(build) = env::var_os("GNUNET_API_REFERENCE_BUILD") {
        command.arg("--build").arg(build);
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!(
            "official API inventory invalid: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    if output.stdout.len() > 8 * 1024 * 1024 {
        return Err("API inventory checker output exceeds 8 MiB".into());
    }
    let mut document: Value = serde_json::from_slice(&output.stdout)?;
    let inventory = parse_api_inventory(&document)?;
    if let Some(object) = document.as_object_mut() {
        object.remove("required_criteria");
    }
    writeln!(io::stdout().lock(), "official API inventory: {document}")?;
    Ok(inventory)
}

fn parse_api_inventory(document: &Value) -> CheckResult<ApiInventory> {
    if !["valid", "valid-incomplete"].contains(&text(document, "status")?)
        || document["full_gnunet_conformance_claim"] != false
        || document["evidence_validation_required_externally"] != true
    {
        return Err(
            "API catalog cannot substitute its status for official conformance evidence".into(),
        );
    }
    let rows = document["required_criteria"]
        .as_object()
        .ok_or("API inventory criteria absent")?;
    let expected: BTreeSet<_> = SUBSYSTEMS.iter().chain(FOUNDATIONS).copied().collect();
    if rows.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err("API criteria must cover every required subsystem and foundation".into());
    }
    let mut criteria = BTreeMap::new();
    for (owner, values) in rows {
        let values = values
            .as_array()
            .ok_or("API owner criteria must be an array")?;
        let mut unique = BTreeSet::new();
        for value in values {
            let id = value
                .as_str()
                .filter(|id| !id.is_empty() && !id.contains('\0'))
                .ok_or("invalid API criterion ID")?;
            if !unique.insert(id.to_owned()) {
                return Err("duplicate API criterion ID for owner".into());
            }
        }
        // These owners have no dedicated public API declarations in the pinned
        // catalog. Their required service/runtime behavior remains in the main
        // ledger and the catalog's still-mandatory operation review.
        if unique.is_empty()
            && ![
                "exit",
                "hostlist",
                "pt",
                "reference-harness",
                "topology",
                "zonemaster",
            ]
            .contains(&owner.as_str())
        {
            return Err(format!("API/operation obligations cannot disappear for {owner}").into());
        }
        criteria.insert(owner.clone(), unique);
    }
    let boolean = |name: &str| {
        document[name]
            .as_bool()
            .ok_or_else(|| format!("API inventory boolean absent: {name}"))
    };
    let ready = boolean("inventory_ready")?;
    if ready != (document["status"] == "valid") {
        return Err("API readiness/status mismatch".into());
    }
    Ok(ApiInventory {
        criteria,
        ready,
        reference_checked: boolean("source_verified")?,
        build_checked: boolean("build_profile_verified")?,
    })
}

fn require_api_complete(inventory: &ApiInventory) -> CheckResult<()> {
    if !inventory.ready || !inventory.reference_checked || !inventory.build_checked {
        return Err("official API/operation inventory incomplete or unvalidated profile; strict checks require all catalog obligations and pinned GNUNET_REFERENCE_SOURCE plus GNUNET_API_REFERENCE_BUILD".into());
    }
    Ok(())
}

fn require_complete(coverage: &Coverage, reference_checked: bool) -> CheckResult<()> {
    if coverage.subsystems != SUBSYSTEMS.len()
        || coverage.foundations != FOUNDATIONS.len()
        || !coverage.pending.is_empty()
    {
        return Err(format!(
            "official GNUnet conformance incomplete; pending: {}",
            coverage.pending.join(", ")
        )
        .into());
    }
    if !reference_checked {
        return Err(
            "strict conformance requires a clean pinned GNUNET_REFERENCE_SOURCE checkout".into(),
        );
    }
    Ok(())
}

fn text<'a>(value: &'a Value, field: &str) -> CheckResult<&'a str> {
    value[field]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("missing/nonempty string required: {field}").into())
}

fn array<'a>(value: &'a Value, field: &str) -> CheckResult<&'a [Value]> {
    value[field]
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("array required: {field}").into())
}

fn canonical_hash(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn relative(path: &str) -> CheckResult<&Path> {
    let path = Path::new(path);
    if path.as_os_str().is_empty()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err("path must be a nonempty repository-relative path without traversal".into());
    }
    Ok(path)
}

fn local_file(root: &Path, path: &str) -> CheckResult<PathBuf> {
    let actual = root.join(relative(path)?).canonicalize()?;
    if !actual.starts_with(root.canonicalize()?) || !actual.is_file() {
        return Err(format!("file escapes the repository or is not a file: {path}").into());
    }
    Ok(actual)
}

fn digest(bytes: &[u8]) -> String {
    gnunet_crypto::hash256(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn source_entry(entry: &Value) -> CheckResult<&str> {
    let path = text(entry, "path")?;
    relative(path)?;
    if !path.starts_with("src/") || !canonical_hash(text(entry, "sha256")?, 64) {
        return Err("upstream source requires a src/ path and canonical SHA256".into());
    }
    Ok(path)
}

#[cfg(test)]
fn validate(ledger: &Value, root: &Path, current_source: &str) -> CheckResult<Coverage> {
    validate_inventory(ledger, root, current_source, None)
}

fn validate_inventory(
    ledger: &Value,
    root: &Path,
    current_source: &str,
    inventory: Option<&ApiInventory>,
) -> CheckResult<Coverage> {
    if ledger["schema"] != 1
        || ledger["baseline"]["repository"] != "https://git.gnunet.org/gnunet.git"
        || ledger["baseline"]["tag"] != "v0.29.1"
        || ledger["baseline"]["commit"] != COMMIT
        || ledger["baseline"]["profile"] != PROFILE
        || !canonical_hash(current_source, 64)
    {
        return Err("unsupported or malformed official GNUnet baseline".into());
    }
    let policy = &ledger["policy"];
    if policy["production_language"] != "Rust"
        || policy["production_libgnunet_ffi"] != false
        || policy["official_wire_required"] != true
        || policy["breaking_rewrite"] != true
        || policy["legacy_compatibility"] != false
        || policy["private_wire_fallback"] != false
        || policy["forbidden_historical_profile"] != "gnrs-native-v1"
        || policy["historical_private_evidence_counts_as_compatible"] != false
    {
        return Err(
            "ledger must require an official Rust rewrite without private compatibility or evidence credit"
                .into(),
        );
    }
    let mut sources = BTreeSet::new();
    for entry in array(&ledger["baseline"], "source_files")? {
        if !sources.insert(source_entry(entry)?) {
            return Err("duplicate upstream source path".into());
        }
    }
    for required in [
        "src/service/meson.build",
        "src/include/gnunet_common.h",
        "src/include/gnunet_protocols.h",
    ] {
        if !sources.contains(required) {
            return Err(format!("missing baseline source: {required}").into());
        }
    }
    let mut coverage = Coverage {
        subsystems: 0,
        foundations: 0,
        pending: Vec::new(),
    };
    let normative = inventory
        .map(|_| crate::inputs::normative_fingerprint(root))
        .transpose()?;
    for (field, required) in [
        ("required_subsystems", SUBSYSTEMS),
        ("foundations", FOUNDATIONS),
    ] {
        let entries = array(ledger, field)?;
        let mut ids = BTreeSet::new();
        for entry in entries {
            let id = text(entry, "id")?;
            if !required.contains(&id) || !ids.insert(id) || entry["required"] != true {
                return Err(
                    format!("unknown, duplicate, or disabled required {field}: {id}").into(),
                );
            }
            if field == "required_subsystems" {
                let expected = format!("src/service/{id}/meson.build");
                if source_entry(&entry["upstream_source"])? != expected {
                    return Err(format!("wrong official subsystem build source: {id}").into());
                }
            }
            text(entry, "scope")?;
            text(entry, "phase")?;
            let mut dependencies = BTreeSet::new();
            for dependency in array(entry, "depends_on")? {
                let name = dependency
                    .as_str()
                    .ok_or("dependency ID must be a string")?;
                if name == id
                    || (!SUBSYSTEMS.contains(&name) && !FOUNDATIONS.contains(&name))
                    || !dependencies.insert(name)
                {
                    return Err(
                        format!("unknown, self, or duplicate dependency for {id}: {name}").into(),
                    );
                }
            }
            let mut criteria = validate_interfaces(entry, id)?;
            if let Some(inventory) = inventory {
                criteria.extend(
                    inventory
                        .criteria
                        .get(id)
                        .ok_or("missing API owner")?
                        .iter()
                        .map(String::as_str),
                );
            }
            let status = text(entry, "status")?;
            if ![
                "missing",
                "planned",
                "in_progress",
                "implemented",
                "verified",
            ]
            .contains(&status)
            {
                return Err(format!("unsupported implementation status for {id}: {status}").into());
            }
            let implementation = array(entry, "implementation_files")?;
            let commands = array(entry, "test_commands")?;
            if ["implemented", "verified"].contains(&status)
                && (implementation.is_empty() || commands.is_empty())
            {
                return Err(format!("implemented capability has no code/tests: {id}").into());
            }
            for file in implementation {
                let path = file
                    .as_str()
                    .ok_or("implementation path must be a string")?;
                if !implementation_source_path(id, path)
                    || fs::metadata(local_file(root, path)?)?.len() == 0
                {
                    return Err(format!(
                        "implementation must identify nonempty allowed source code: {id}"
                    )
                    .into());
                }
            }
            for command in commands {
                command_argv(command)?;
            }
            if status == "verified" && entry["verification"].is_null() {
                return Err(format!("verified capability has no official-C evidence: {id}").into());
            }
            if !entry["verification"].is_null() {
                let requirements = normative
                    .as_ref()
                    .map(|spec| requirements_digest(ledger, entry, spec))
                    .transpose()?;
                validate_evidence(
                    entry,
                    &criteria,
                    root,
                    current_source,
                    requirements.as_deref(),
                )?;
            }
            if status == "verified" {
                if field == "required_subsystems" {
                    coverage.subsystems += 1;
                } else {
                    coverage.foundations += 1;
                }
            } else {
                coverage.pending.push(format!("{id}({status})"));
            }
        }
        if ids.len() != required.len() {
            return Err(format!(
                "{field} must contain every one of its {} required entries",
                required.len()
            )
            .into());
        }
    }
    Ok(coverage)
}

fn requirements_digest(ledger: &Value, entry: &Value, normative_spec: &str) -> CheckResult<String> {
    // Status, implementation mappings, test descriptions and report references
    // are mutable proof metadata. The normative contract stays fixed while
    // evidence is produced and attached afterward.
    Ok(digest(&serde_json::to_vec(&serde_json::json!({
        "schema":"gnunet-requirements-v1", "normative_spec_sha256":normative_spec,
        "baseline":ledger["baseline"], "policy":ledger["policy"],
        "owner":{"id":entry["id"],"required":entry["required"],"scope":entry["scope"],
            "depends_on":entry["depends_on"],"upstream_source":entry["upstream_source"],
            "interfaces":entry["interfaces"]}
    }))?))
}

fn implementation_source_path(id: &str, path: &str) -> bool {
    let extension = Path::new(path).extension().and_then(|value| value.to_str());
    if id == "reference-harness" {
        // Test orchestration is not product protocol code. This exception is
        // scoped to the harness foundation and its actual test/tool directories;
        // it cannot turn a Python wrapper into a Rust service implementation.
        ["tools/", "tests/"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
            && matches!(extension, Some("rs" | "py"))
    } else {
        ["crates/", "adapters/", "apps/"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
            && extension == Some("rs")
    }
}

fn validate_interfaces<'a>(entry: &'a Value, id: &str) -> CheckResult<BTreeSet<&'a str>> {
    let mut ids = BTreeSet::new();
    let interfaces = &entry["interfaces"];
    for (kind, required) in [
        ("p2p", P2P.contains(&id)),
        ("ipc", IPC.contains(&id)),
        ("api", true),
        ("behavior", true),
    ] {
        let interface = &interfaces[kind];
        if interface["required"] != required {
            return Err(format!(
                "required {kind} interface cannot be disabled or invented for {id}"
            )
            .into());
        }
        let criteria = array(interface, "criteria")?;
        if required == criteria.is_empty() {
            return Err(format!("incorrect acceptance criteria for {id}/{kind}").into());
        }
        if !required {
            text(interface, "not_applicable_reason")?;
        }
        for criterion in criteria {
            let criterion_id = text(criterion, "id")?;
            text(criterion, "description")?;
            if !criterion_id.starts_with(&format!("{id}-{kind}")) || !ids.insert(criterion_id) {
                return Err(format!("ambiguous or duplicate criterion: {criterion_id}").into());
            }
        }
    }
    Ok(ids)
}

fn command_argv(value: &Value) -> CheckResult<()> {
    let args = value
        .as_array()
        .ok_or("command must be an argv array, never shell text")?;
    if args.is_empty()
        || args
            .iter()
            .any(|arg| arg.as_str().is_none_or(|s| s.trim().is_empty()))
    {
        return Err("empty command or command argument cannot count as verification".into());
    }
    Ok(())
}

fn validate_evidence(
    entry: &Value,
    expected: &BTreeSet<&str>,
    root: &Path,
    current_source: &str,
    requirements: Option<&str>,
) -> CheckResult<()> {
    let id = text(entry, "id")?;
    let reference = &entry["verification"];
    let report_path = local_file(root, text(reference, "path")?)?;
    if fs::metadata(&report_path)?.len() > 4 * 1024 * 1024 {
        return Err("verification report exceeds the bounded 4 MiB allowance".into());
    }
    let bytes = fs::read(report_path)?;
    if !canonical_hash(text(reference, "sha256")?, 64)
        || digest(&bytes) != text(reference, "sha256")?
    {
        return Err(format!("verification report hash mismatch for {id}").into());
    }
    let report: Value = serde_json::from_slice(&bytes)?;
    if report["schema"] != 1
        || report["subsystem"] != id
        || report["profile"] != PROFILE
        || report["upstream_commit"] != COMMIT
        || report["source_sha256"] != current_source
        || report["source_unchanged"] != true
        || report["passed"] != true
    {
        return Err(format!(
            "foreign, stale, changed-source, or failed official evidence for {id}"
        )
        .into());
    }
    if requirements.is_some_and(|expected| report["requirements_sha256"].as_str() != Some(expected))
    {
        return Err("stale normative specification or owner requirement projection".into());
    }
    let participant_values = array(&report, "implementations")?;
    let participants: BTreeSet<_> = participant_values
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or("implementation identifier must be a string")
        })
        .collect::<Result<_, _>>()?;
    if participants != BTreeSet::from(["gnunet-c", "gnunet-rs"]) {
        return Err("native-only software interoperation is not official-C evidence".into());
    }
    if participant_values.len() != participants.len() {
        return Err("duplicate evidence participant".into());
    }
    for participant in ["gnunet-c", "gnunet-rs"] {
        let expected = text(&report["binary_sha256"], participant)?;
        let binary = local_file(root, text(&report["binary_paths"], participant)?)?;
        if fs::metadata(&binary)?.len() > 256 * 1024 * 1024 {
            return Err(
                "interop evidence binary exceeds 256 MiB; use the isolated test/release artifact"
                    .into(),
            );
        }
        if !canonical_hash(expected, 64) || digest(&fs::read(binary)?) != expected {
            return Err("both participating binaries require SHA256 provenance".into());
        }
    }
    if report["binary_sha256"]["gnunet-c"] == report["binary_sha256"]["gnunet-rs"] {
        return Err(
            "the same binary cannot stand in for both the C and Rust implementation".into(),
        );
    }
    text(&report, "timestamp_utc")?;
    let kind_values = array(&report, "kinds")?;
    let kinds: BTreeSet<_> = kind_values
        .iter()
        .map(|value| value.as_str().ok_or("evidence kind must be a string"))
        .collect::<Result<_, _>>()?;
    if kind_values.len() != kinds.len() {
        return Err("duplicate evidence kind".into());
    }
    let p2p = entry["interfaces"]["p2p"]["required"] == true;
    let ipc = entry["interfaces"]["ipc"]["required"] == true;
    for kind in &kinds {
        if ![
            "official-c-peer",
            "official-c-ipc",
            "official-c-differential",
        ]
        .contains(kind)
        {
            return Err("unsupported evidence kind, including native-only evidence".into());
        }
    }
    if (p2p && !kinds.contains("official-c-peer"))
        || (ipc && !kinds.contains("official-c-ipc"))
        || (!p2p && !ipc && !kinds.contains("official-c-differential"))
    {
        return Err(
            format!("official-C evidence does not cover required interfaces for {id}").into(),
        );
    }
    let inputs = array(&report, "spec_inputs")?;
    if inputs.is_empty() {
        return Err("evidence requires hashed normative/vector inputs".into());
    }
    let mut input_paths = BTreeSet::new();
    for input in inputs {
        let path = text(input, "path")?;
        if path == "spec/gnunet/conformance.json"
            || !path.starts_with("spec/")
            || !input_paths.insert(path)
            || !canonical_hash(text(input, "sha256")?, 64)
            || digest(&fs::read(local_file(root, path)?)?) != text(input, "sha256")?
        {
            return Err("stale, duplicate, or self-referential normative/vector input".into());
        }
    }
    if requirements.is_some() && API_INPUTS.iter().any(|path| !input_paths.contains(path)) {
        return Err(
            "official evidence must bind every compiler/API/operation catalog input".into(),
        );
    }
    let commands = array(&report, "commands")?;
    if commands.is_empty() {
        return Err("evidence has no executed commands".into());
    }
    for command in commands {
        command_argv(&command["argv"])?;
        if command["exit_code"] != 0
            || command["executed_checks"]
                .as_u64()
                .is_none_or(|count| count == 0)
            || !canonical_hash(text(command, "output_sha256")?, 64)
            || digest(&fs::read(local_file(root, text(command, "output_path")?)?)?)
                != text(command, "output_sha256")?
        {
            return Err("failed or zero-execution command cannot count as passing evidence".into());
        }
    }
    let mut actual = BTreeSet::new();
    for check in array(&report, "checks")? {
        let name = text(check, "id")?;
        if check["passed"] != true || !actual.insert(name) {
            return Err("failed or duplicate acceptance result".into());
        }
    }
    if &actual != expected {
        return Err(format!("incomplete acceptance coverage for {id}").into());
    }
    Ok(())
}

fn validate_reference(ledger: &Value, reference: &Path) -> CheckResult<()> {
    let revision = Command::new("git")
        .arg("-C")
        .arg(reference)
        .args(["rev-parse", "HEAD"])
        .output()?;
    if !revision.status.success() || String::from_utf8_lossy(&revision.stdout).trim() != COMMIT {
        return Err("GNUNET_REFERENCE_SOURCE is not the pinned official commit".into());
    }
    let clean = Command::new("git")
        .arg("-C")
        .arg(reference)
        .args(["diff", "--quiet", COMMIT, "--"])
        .status()?;
    if !clean.success() {
        return Err("the official reference checkout has modified tracked inputs".into());
    }
    let entries = array(&ledger["baseline"], "source_files")?.iter().chain(
        array(ledger, "required_subsystems")?
            .iter()
            .map(|entry| &entry["upstream_source"]),
    );
    for entry in entries {
        let path = source_entry(entry)?;
        if digest(&fs::read(local_file(reference, path)?)?) != text(entry, "sha256")? {
            return Err(format!("official source changed from pinned catalog: {path}").into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    const SOURCE: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn ledger() -> CheckResult<Value> {
        let mut document: Value =
            serde_json::from_str(include_str!("../../../spec/gnunet/conformance.json"))?;
        // Progress in the real ledger must not change the test's pending fixture.
        for field in ["foundations", "required_subsystems"] {
            for entry in document[field]
                .as_array_mut()
                .ok_or("fixture entries absent")?
            {
                entry["status"] = "planned".into();
                entry["implementation_files"] = serde_json::json!([]);
                entry["test_commands"] = serde_json::json!([]);
                entry["verification"] = Value::Null;
            }
        }
        Ok(document)
    }

    fn rejected(result: CheckResult<Coverage>) -> CheckResult<()> {
        if result.is_ok() {
            return Err("invalid conformance claim was accepted".into());
        }
        Ok(())
    }

    fn write_report(root: &Path, document: &mut Value, report: &Value) -> CheckResult<()> {
        let bytes = serde_json::to_vec(report)?;
        fs::write(root.join("evidence.json"), &bytes)?;
        document["foundations"][0]["verification"] =
            serde_json::json!({"path":"evidence.json","sha256":digest(&bytes)});
        Ok(())
    }

    fn verified_fixture() -> CheckResult<(PathBuf, Value, Value)> {
        let root = env::temp_dir().join(format!(
            "gnunet-conformance-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        fs::create_dir_all(root.join("crates/example/src"))?;
        fs::create_dir_all(root.join("spec/gnunet"))?;
        fs::write(
            root.join("crates/example/src/lib.rs"),
            b"pub fn checked_frame() {}\n",
        )?;
        fs::write(root.join("spec/gnunet/vector.bin"), [0, 4, 0, 1])?;
        fs::write(root.join("rust.bin"), b"isolated Rust test artifact")?;
        fs::write(root.join("c.bin"), b"isolated C test artifact")?;
        fs::write(
            root.join("output.txt"),
            b"1 official differential check passed\n",
        )?;
        let mut document = ledger()?;
        let foundation = &mut document["foundations"][0];
        foundation["status"] = "verified".into();
        foundation["implementation_files"] = serde_json::json!(["crates/example/src/lib.rs"]);
        foundation["test_commands"] = serde_json::json!([["cargo", "test", "official_frames"]]);
        let checks: Vec<_> = ["api", "behavior"]
            .iter()
            .map(|kind| serde_json::json!({"id":format!("wire-{kind}"),"passed":true}))
            .collect();
        let report = serde_json::json!({
            "schema":1,"subsystem":"wire","profile":PROFILE,"upstream_commit":COMMIT,
            "source_sha256":SOURCE,"source_unchanged":true,"passed":true,
            "implementations":["gnunet-c","gnunet-rs"],"timestamp_utc":"2026-10-26T00:00:00Z",
            "binary_paths":{"gnunet-rs":"rust.bin","gnunet-c":"c.bin"},
            "binary_sha256":{"gnunet-rs":digest(b"isolated Rust test artifact"),"gnunet-c":digest(b"isolated C test artifact")},
            "kinds":["official-c-differential"],
            "spec_inputs":[{"path":"spec/gnunet/vector.bin","sha256":digest(&[0,4,0,1])}],
            "commands":[{"argv":["cargo","test","official_frames"],"exit_code":0,"executed_checks":1,"output_path":"output.txt","output_sha256":digest(b"1 official differential check passed\n")}],
            "checks":checks,
        });
        write_report(&root, &mut document, &report)?;
        Ok((root, document, report))
    }

    #[test]
    fn pending_work_is_valid_inventory_but_never_complete() -> CheckResult<()> {
        let coverage = validate(&ledger()?, Path::new("."), SOURCE)?;
        if coverage.pending.len() != 42 || coverage.subsystems != 0 || coverage.foundations != 0 {
            return Err("the initial inventory incorrectly claims a verified capability".into());
        }
        Ok(())
    }

    #[test]
    fn active_testbed_and_pt_profiles_cannot_invent_or_drop_protocol_interfaces() -> CheckResult<()>
    {
        let document = ledger()?;
        for (id, kind, required) in [("testbed", "ipc", false), ("pt", "p2p", true)] {
            let entry = document["required_subsystems"]
                .as_array()
                .ok_or("subsystems absent")?
                .iter()
                .find(|entry| entry["id"] == id)
                .ok_or("profile absent")?;
            validate_interfaces(entry, id)?;
            if entry["interfaces"][kind]["required"] != required {
                return Err(format!("active profile differs: {id}/{kind}").into());
            }
            let mut altered = entry.clone();
            altered["interfaces"][kind]["required"] = (!required).into();
            if validate_interfaces(&altered, id).is_ok() {
                return Err(format!("invented or dropped interface accepted: {id}/{kind}").into());
            }
        }
        Ok(())
    }

    fn api_fixture() -> Value {
        let criteria: BTreeMap<_, _> = SUBSYSTEMS
            .iter()
            .chain(FOUNDATIONS)
            .map(|owner| {
                (
                    (*owner).to_owned(),
                    serde_json::json!([format!("api.{owner}.required")]),
                )
            })
            .collect();
        serde_json::json!({"status":"valid-incomplete","inventory_ready":false,
            "full_gnunet_conformance_claim":false,"evidence_validation_required_externally":true,
            "source_verified":false,"build_profile_verified":false,"required_criteria":criteria})
    }

    #[test]
    fn api_inventory_requires_all_owners_unique_obligations_and_explicit_readiness()
    -> CheckResult<()> {
        let document = api_fixture();
        if require_api_complete(&parse_api_inventory(&document)?).is_ok() {
            return Err("pending API inventory gained completeness credit".into());
        }
        for malformed in [
            {
                let mut d = document.clone();
                d["required_criteria"]
                    .as_object_mut()
                    .ok_or("criteria absent")?
                    .remove("crypto");
                d
            },
            {
                let mut d = document.clone();
                d["required_criteria"]["wire"] = serde_json::json!([]);
                d
            },
            {
                let mut d = document.clone();
                d["required_criteria"]["wire"] =
                    serde_json::json!(["api.required", "api.required"]);
                d
            },
            {
                let mut d = document.clone();
                d["inventory_ready"] = true.into();
                d
            },
            {
                let mut d = document.clone();
                d["full_gnunet_conformance_claim"] = true.into();
                d
            },
        ] {
            if parse_api_inventory(&malformed).is_ok() {
                return Err("malformed API inventory passed".into());
            }
        }
        let mut reviewed = document;
        reviewed["status"] = "valid".into();
        reviewed["inventory_ready"] = true.into();
        if require_api_complete(&parse_api_inventory(&reviewed)?).is_ok() {
            return Err("API profile without C source/build provenance passed".into());
        }
        reviewed["source_verified"] = true.into();
        reviewed["build_profile_verified"] = true.into();
        require_api_complete(&parse_api_inventory(&reviewed)?)?;
        Ok(())
    }

    #[test]
    fn verified_evidence_requires_every_api_obligation_and_current_catalog_inputs()
    -> CheckResult<()> {
        let (root, mut ledger, mut report) = verified_fixture()?;
        let inventory = parse_api_inventory(&api_fixture())?;
        if validate_inventory(&ledger, &root, SOURCE, Some(&inventory)).is_ok() {
            return Err("interface-only report substituted for full API evidence".into());
        }
        report["checks"]
            .as_array_mut()
            .ok_or("checks absent")?
            .push(serde_json::json!({"id":"api.wire.required","passed":true}));
        write_report(&root, &mut ledger, &report)?;
        if validate_inventory(&ledger, &root, SOURCE, Some(&inventory)).is_ok() {
            return Err("API report omitted its catalog source binding".into());
        }
        fs::create_dir_all(root.join("spec/gnunet/api"))?;
        for path in API_INPUTS {
            fs::write(root.join(path), b"synthetic catalog input")?;
            report["spec_inputs"]
                .as_array_mut()
                .ok_or("inputs absent")?
                .push(serde_json::json!({"path":path,"sha256":digest(b"synthetic catalog input")}));
        }
        report["requirements_sha256"] = requirements_digest(
            &ledger,
            &ledger["foundations"][0],
            &crate::inputs::normative_fingerprint(&root)?,
        )?
        .into();
        write_report(&root, &mut ledger, &report)?;
        validate_inventory(&ledger, &root, SOURCE, Some(&inventory))?;
        let mut stronger = ledger.clone();
        stronger["foundations"][0]["interfaces"]["api"]["criteria"][0]["description"] =
            "A stronger normative requirement with the same stable criterion ID".into();
        if validate_inventory(&stronger, &root, SOURCE, Some(&inventory)).is_ok() {
            return Err("changed criterion meaning retained old evidence".into());
        }
        let extra = root.join("spec/new-required-vector.bin");
        fs::write(
            &extra,
            b"new normative vector absent from report spec_inputs",
        )?;
        if validate_inventory(&ledger, &root, SOURCE, Some(&inventory)).is_ok() {
            return Err("unlisted normative changes retained old evidence".into());
        }
        fs::remove_file(extra)?;
        // Attaching the proof and updating nonnormative completion metadata do
        // not change the contract hash or create a report/ledger hash cycle.
        let mut implementation_metadata = ledger.clone();
        implementation_metadata["foundations"][0]["phase"] = "verified checkpoint".into();
        validate_inventory(&implementation_metadata, &root, SOURCE, Some(&inventory))?;
        fs::write(root.join(API_INPUTS[0]), b"changed catalog scope")?;
        if validate_inventory(&ledger, &root, SOURCE, Some(&inventory)).is_ok() {
            return Err("changed catalog retained evidence credit".into());
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn reference_tools_cannot_substitute_for_production_rust_services() -> CheckResult<()> {
        if !implementation_source_path("reference-harness", "tools/reference/statistics_daemons.py")
            || !implementation_source_path("statistics", "adapters/ipc-unix/src/server.rs")
            || implementation_source_path("statistics", "tools/reference/statistics_daemons.py")
            || implementation_source_path("statistics", "adapters/statistics.c")
            || implementation_source_path("reference-harness", "tools/reference/library.c")
        {
            return Err(
                "reference tooling exception crossed a production language boundary".into(),
            );
        }
        Ok(())
    }

    #[test]
    fn strict_gate_requires_complete_coverage_and_a_checked_official_checkout() -> CheckResult<()> {
        let pending = Coverage {
            subsystems: 0,
            foundations: 0,
            pending: vec!["core(missing)".into()],
        };
        if require_complete(&pending, true).is_ok() {
            return Err("strict gate accepted pending work".into());
        }
        let complete = Coverage {
            subsystems: SUBSYSTEMS.len(),
            foundations: FOUNDATIONS.len(),
            pending: Vec::new(),
        };
        if require_complete(&complete, false).is_ok() {
            return Err("strict gate accepted an unchecked reference tree".into());
        }
        require_complete(&complete, true)
    }

    #[test]
    fn required_services_and_interfaces_cannot_be_deleted_duplicated_or_disabled() -> CheckResult<()>
    {
        let original = ledger()?;
        let mut missing = original.clone();
        missing["required_subsystems"]
            .as_array_mut()
            .ok_or("fixture array absent")?
            .remove(0);
        rejected(validate(&missing, Path::new("."), SOURCE))?;
        let mut duplicate = original.clone();
        duplicate["required_subsystems"][1] = duplicate["required_subsystems"][0].clone();
        rejected(validate(&duplicate, Path::new("."), SOURCE))?;
        let mut disabled = original.clone();
        disabled["required_subsystems"][0]["required"] = false.into();
        rejected(validate(&disabled, Path::new("."), SOURCE))?;
        let mut no_ipc = original.clone();
        no_ipc["required_subsystems"][0]["interfaces"]["ipc"]["required"] = false.into();
        rejected(validate(&no_ipc, Path::new("."), SOURCE))?;
        let mut fake_baseline = original.clone();
        fake_baseline["baseline"]["commit"] = "a".repeat(40).into();
        rejected(validate(&fake_baseline, Path::new("."), SOURCE))?;
        let mut unsupported = original;
        unsupported["required_subsystems"][0]["status"] = "native-only".into();
        rejected(validate(&unsupported, Path::new("."), SOURCE))
    }

    #[test]
    fn rewrite_policy_cannot_reintroduce_private_compatibility_or_evidence_credit()
    -> CheckResult<()> {
        let original = ledger()?;
        for (field, value) in [
            ("breaking_rewrite", false),
            ("legacy_compatibility", true),
            ("private_wire_fallback", true),
            ("historical_private_evidence_counts_as_compatible", true),
        ] {
            let mut document = original.clone();
            document["policy"][field] = value.into();
            rejected(validate(&document, Path::new("."), SOURCE))?;
        }
        let mut document = original;
        document["policy"]["forbidden_historical_profile"] = PROFILE.into();
        rejected(validate(&document, Path::new("."), SOURCE))
    }

    #[test]
    fn verified_status_requires_code_tests_and_official_evidence() -> CheckResult<()> {
        let mut document = ledger()?;
        document["foundations"][0]["status"] = "verified".into();
        rejected(validate(&document, Path::new("."), SOURCE))?;
        let (root, mut document, _) = verified_fixture()?;
        let coverage = validate(&document, &root, SOURCE)?;
        if coverage.foundations != 1 || coverage.pending.len() != 41 {
            return Err("a single foundation incorrectly satisfied the full implementation".into());
        }
        document["foundations"][0]["test_commands"] = serde_json::json!([]);
        rejected(validate(&document, &root, SOURCE))?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn native_only_failed_stale_and_empty_filter_reports_cannot_earn_credit() -> CheckResult<()> {
        let (root, document, report) = verified_fixture()?;
        for invalid in [
            ("profile", serde_json::json!("gnrs-native-v1")),
            (
                "implementations",
                serde_json::json!(["gnunet-rs", "gnunet-rs"]),
            ),
            ("kinds", serde_json::json!(["native-only"])),
            ("source_unchanged", serde_json::json!(false)),
            ("passed", serde_json::json!(false)),
            ("source_sha256", serde_json::json!("2".repeat(64))),
            ("checks", serde_json::json!([])),
        ] {
            let mut modified = report.clone();
            modified[invalid.0] = invalid.1;
            let mut claim = document.clone();
            write_report(&root, &mut claim, &modified)?;
            rejected(validate(&claim, &root, SOURCE))?;
        }
        for (field, value) in [("executed_checks", 0), ("exit_code", 1)] {
            let mut modified = report.clone();
            modified["commands"][0][field] = value.into();
            let mut claim = document.clone();
            write_report(&root, &mut claim, &modified)?;
            rejected(validate(&claim, &root, SOURCE))?;
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn evidence_inputs_and_artifacts_are_bound_to_actual_files() -> CheckResult<()> {
        let (root, document, report) = verified_fixture()?;
        for path in ["spec/gnunet/vector.bin", "output.txt", "c.bin"] {
            let original = fs::read(root.join(path))?;
            fs::write(root.join(path), b"changed after proof")?;
            rejected(validate(&document, &root, SOURCE))?;
            fs::write(root.join(path), original)?;
        }
        let mut self_referential = report;
        self_referential["spec_inputs"][0]["path"] = "spec/gnunet/conformance.json".into();
        let mut claim = document.clone();
        write_report(&root, &mut claim, &self_referential)?;
        rejected(validate(&claim, &root, SOURCE))?;
        let mut traversal = document;
        traversal["foundations"][0]["verification"]["path"] = "../outside-evidence.json".into();
        rejected(validate(&traversal, &root, SOURCE))?;
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
