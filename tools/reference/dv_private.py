#!/usr/bin/env python3
"""Bounded normal three-node DV/CORE private interoperability driver.

This source draft is inert unless main is explicitly invoked with --execute.
It builds/downloads nothing. All services and utilities are real compiler-bound
normal programs. The two payload callers are separately identified official-C
public-API components, not normal C CORE services or a substitute transport.

The script requires a current manifest and complete expanded official defaults;
missing old /tmp prerequisites are errors, never reconstructed pass evidence.
"""
import argparse
import configparser
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import sys
import tempfile
import time
from urllib.parse import parse_qsl, urlsplit

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools/reference"))
from conversation_owned import (Blocked, Controller, Deadline, ObservationError,
                                Owner, described, file_hash)

PROFILE = "three-normal-nodes-private-unix-dv-core"
REVISION = "14698f19848af867f48a04521e274abd55972075"
SERVICES = ("statistics", "peerstore", "pils", "nat", "transport", "core")
STOP_ORDER = ("communicator", "core", "transport", "nat", "pils", "peerstore", "statistics")
BASE32 = r"[0123456789ABCDEFGHJKMNPQRSTVWXYZ]"
PUBLIC = re.compile(BASE32 + r"{52}")
MAX_METADATA = 16 << 20
REQUIRED_RUST = {"rust.service." + name for name in SERVICES} | {
    "rust.communicator.unix", "rust.cli.pils", "rust.cli.hello"}
REQUIRED_C = {"c.cli.transport"}
REQUIRED_COMPONENT = {"component.core_dv"}
VALIDATION_DIAGNOSTIC = "reference-single-neighbour-validation"


class DiagnosticComplete(ObservationError):
    """The fixed observation window ended; this supplies no interop pass."""


def absolute(value):
    path = Path(value)
    if not path.is_absolute() or "\0" in str(path):
        raise Blocked("all supplied paths must be absolute")
    return path


def within(path, root):
    return Path(path).resolve().is_relative_to(Path(root).resolve())


def load_json(path):
    path = absolute(path)
    try:
        if path.stat().st_size > MAX_METADATA:
            raise Blocked("metadata exceeds its finite input bound")
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise Blocked("required metadata is unavailable/invalid: " + str(path)) from error


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def checked(row):
    path = absolute(row["path"])
    if not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
        raise Blocked("invalid named input hash")
    try:
        digest, size = file_hash(path)
    except OSError as error:
        raise Blocked("required named input is unavailable: " + str(path)) from error
    if digest != row["sha256"]:
        raise Blocked("named input changed: " + str(path))
    return {"path": str(path), "sha256": digest, "bytes": size}


class Inputs:
    """Public compiler/source/default/artifact bindings, never node keys/DBs."""
    def __init__(self, manifest, middle):
        if manifest.get("schema") != 1 or manifest.get("profile") != PROFILE:
            raise Blocked("manifest is not the reviewed three-node DV profile")
        if manifest.get("official_revision") != REVISION:
            raise Blocked("C must use the exact unmodified pinned official revision")
        self.middle = middle
        self.diagnostic = manifest.get("diagnostic_mode")
        if self.diagnostic is not None and (self.diagnostic != VALIDATION_DIAGNOSTIC or middle != "c"):
            raise Blocked("unknown diagnostic mode or missing unchanged C relay")
        self.bindings = []
        self.manifest = manifest
        self.source_ref = checked(manifest["source_inputs"])
        self.bindings.append(self.source_ref)
        source = load_json(self.source_ref["path"])
        if not isinstance(source, dict) or not 1 <= len(source) <= 10000:
            raise Blocked("current source input map is absent/unbounded")
        if manifest["source_inputs"].get("files", len(source)) != len(source):
            raise Blocked("source input count differs from the actual named map")
        self.sources = []
        for name, digest in source.items():
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise Blocked("source input path escapes its workspace")
            self.sources.append(checked({"path": str(REPO / relative), "sha256": digest}))
        self.bindings.append(checked({"path": str(Path(__file__).resolve()),
                                      "sha256": file_hash(Path(__file__))[0]}))
        self.bindings.append(checked({"path": str(REPO / "tools/reference/conversation_owned.py"),
                                      "sha256": manifest["owner_module_sha256"]}))
        self.receipts = {}
        self.produced = {}
        for implementation in ("rust", "c", "component"):
            reference = checked(manifest["build_receipts"][implementation])
            self.bindings.append(reference)
            receipt = load_json(reference["path"])
            if receipt.get("status") != "passed":
                raise Blocked("actual successful compiler evidence is missing: " + implementation)
            if implementation == "rust":
                expected_source = manifest["source_inputs"]
                actual_source = receipt.get("source_inputs", {})
                if any(actual_source.get(k) != expected_source.get(k) for k in ("path", "sha256")):
                    raise Blocked("Rust normal cohort is not bound to this current source map")
                binaries = receipt.get("normal_binaries")
                if binaries is not None:
                    # Direct current Root Cargo cohort evidence, without an
                    # invented second approval/index layer.
                    argv = receipt.get("argv", [])
                    if (receipt.get("exit_code") != 0 or receipt.get("reaped") is not True
                            or receipt.get("named_source_inputs_unchanged") is not True
                            or not {"build", "--offline", "--locked"} <= set(argv)
                            or "--target" in argv):
                        raise Blocked("actual native Cargo cohort evidence is incomplete")
                    names = {"gnunet-service-" + n: "rust.service." + n for n in SERVICES}
                    names.update({"gnunet-communicator-unix": "rust.communicator.unix",
                                  "gnunet-pils": "rust.cli.pils", "gnunet-hello": "rust.cli.hello"})
                    produced = {}
                    for row in binaries:
                        if row["name"] not in names or row.get("profile", {}).get("test") is not False:
                            raise Blocked("Cargo cohort includes an unexpected/non-normal participant")
                        ident = names[row["name"]]
                        if ident in produced:
                            raise Blocked("duplicate normal Cargo binary")
                        produced[ident] = {"path": row["path"], "sha256": row["sha256"]}
                    if set(produced) != REQUIRED_RUST:
                        raise Blocked("Cargo cohort did not actually produce all nine selected normal programs")
                    proofs = [receipt["cargo.jsonl"], receipt["stderr.log"]]
                else:
                    if (receipt.get("kind") != "normal-binary-build" or receipt.get("implementation") != "rust"
                            or receipt.get("build_executed") is not True):
                        raise Blocked("Rust provider is not an actual normal-binary build")
                    produced = receipt.get("artifacts", {})
                    proofs = receipt.get("source_bindings", []) + receipt.get("underlying_receipts", [])
            else:
                if receipt.get("build_executed") is not True:
                    raise Blocked("actual C/component compilation was not performed")
                if receipt.get("native_system") != platform.system() or receipt.get("native_machine") != platform.machine():
                    raise Blocked("selected C/compiler-produced artifacts are not native")
                if receipt.get("official_revision") != REVISION or receipt.get("modified_official_source") is not False:
                    raise Blocked("official C source revision/unchanged status differs")
                expected = "normal-binary-build" if implementation == "c" else "public-api-component-build"
                if receipt.get("kind") != expected:
                    raise Blocked("normal C and public API component evidence must stay distinct")
                if implementation == "component" and receipt.get("public_api_only") is not True:
                    raise Blocked("payload caller must use only official CORE/application public APIs")
                if implementation == "c" and (receipt.get("runtime_closure_staged") is not True
                                               or receipt.get("generated_defaults_complete") is not True):
                    raise Blocked("actual C loader and complete generated-default closure are required")
                produced = receipt.get("artifacts", {})
                proofs = receipt.get("source_bindings", []) + receipt.get("underlying_receipts", [])
            if not 1 <= len(proofs) <= 1024:
                raise Blocked("compiler/source/default provenance is absent or unbounded")
            self.bindings.extend(checked(row) for row in proofs)
            self.receipts[implementation] = receipt
            self.produced[implementation] = produced
        self.artifacts = {}
        rows = manifest["artifacts"]
        if not 1 <= len(rows) <= 1024:
            raise Blocked("actual loader/default artifact closure is absent or unbounded")
        for row in rows:
            ident = row["id"]
            implementation = row["implementation"]
            if (ident in self.artifacts or implementation not in self.receipts
                    or not ident.startswith(implementation + ".")):
                raise Blocked("duplicate/unknown actual artifact producer")
            if row.get("kind") not in ("binary", "library", "default", "plugin"):
                raise Blocked("unsupported artifact kind")
            produced = self.produced[implementation].get(ident)
            if produced != {"path": row["path"], "sha256": row["sha256"]}:
                raise Blocked("artifact lacks its exact compiler/normal-default producer binding: " + ident)
            self.bindings.append(checked(row))
            if row["kind"] == "binary" and not os.access(row["path"], os.X_OK):
                raise Blocked("normal participant is not executable: " + ident)
            self.artifacts[ident] = row
        required = REQUIRED_RUST | REQUIRED_C | REQUIRED_COMPONENT
        if middle == "c":
            required = required | {"c.service.transport"}
        if not required <= self.artifacts.keys() or any(self.artifacts[x]["kind"] != "binary" for x in required):
            raise Blocked("required normal service/CLI/public-API compiler artifacts are missing")
        closure = {ident for ident in self.produced["c"] if ident.startswith((
            "c.library.", "c.dependency.", "c.default.", "c.plugin."))}
        if not closure or not closure <= self.artifacts.keys():
            raise Blocked("manifest omits compiler-staged C loader/default closure files")
        template_ref = checked(manifest["default_expansion"])
        self.bindings.append(template_ref)
        template = load_json(template_ref["path"])
        if template.get("kind") != "complete-generated-default-expansion" or template.get("complete") is not True:
            raise Blocked("complete current official generated-default expansion is required")
        defaults = checked(template["defaults_receipt"])
        if not any(row.get("path") == defaults["path"] and row.get("sha256") == defaults["sha256"]
                   for row in self.receipts["c"]["underlying_receipts"]):
            raise Blocked("expanded defaults are not bound to this current C build")
        self.bindings.append(defaults)
        component = checked(template["actual_component_receipt"])
        self.bindings.append(component)
        # Configuration export and the runtime CORE caller are independent
        # compiler products. Retain the actual exporter producer rather than
        # rerunning an unchanged config_dump when only the CORE caller changes.
        config_producer = load_json(component["path"])
        if (not isinstance(config_producer, dict)
                or config_producer.get("status") != "passed"
                or config_producer.get("kind") != "public-api-component-build"
                or config_producer.get("build_executed") is not True
                or config_producer.get("public_api_only") is not True
                or config_producer.get("native_system") != platform.system()
                or config_producer.get("native_machine") != platform.machine()
                or config_producer.get("official_revision") != REVISION
                or config_producer.get("modified_official_source") is not False):
            raise Blocked("default expansion lacks an actual native public configuration component producer")
        sources = config_producer.get("source_bindings", [])
        underlying = config_producer.get("underlying_receipts", [])
        if (not isinstance(sources, list) or not 1 <= len(sources) <= 512
                or not isinstance(underlying, list) or not 1 <= len(underlying) <= 512):
            raise Blocked("configuration component source/compiler provenance is absent or unbounded")
        config_bindings = [checked(row) for row in sources + underlying]
        if not any(row.get("path") == manifest["build_receipts"]["c"]["path"]
                   and row.get("sha256") == manifest["build_receipts"]["c"]["sha256"]
                   for row in underlying):
            raise Blocked("configuration component is not bound to this current C build")
        config_artifacts = config_producer.get("artifacts", {})
        if not isinstance(config_artifacts, dict):
            raise Blocked("configuration component artifact index is invalid")
        config_binary = config_artifacts.get("component.config_dump")
        if not isinstance(config_binary, dict):
            raise Blocked("configuration producer did not build the actual config_dump artifact")
        config_bindings.append(checked(config_binary))
        if not os.access(config_binary["path"], os.X_OK):
            raise Blocked("actual configuration exporter artifact is not executable")
        self.bindings.extend(config_bindings)
        self.bindings.extend(checked(template[key]) for key in ("actual_stdout", "actual_stderr", "bootstrap"))
        self.sections = template["sections"]
        if not isinstance(self.sections, dict) or not all(isinstance(v, dict) for v in self.sections.values()):
            raise Blocked("complete configuration sections are missing")
        self.prefix = absolute(manifest["reference_prefix"])
        if not self.prefix.is_dir():
            raise Blocked("actual private reference prefix is missing")
        dependency_prefix = absolute(manifest["dependency_prefix"])
        if not dependency_prefix.is_dir():
            raise Blocked("actual private reference dependency prefix is missing")
        for prefix in (self.prefix, dependency_prefix):
            if not any(within(prefix, root) for root in (REPO / "target", Path("/private/tmp"))):
                raise Blocked("reference/dependency prefix is not a selected private build root")
        self.library_dirs = [absolute(p) for p in manifest["library_directories"]]
        if not 1 <= len(self.library_dirs) <= 16 or any(not p.is_dir() for p in self.library_dirs):
            raise Blocked("actual private loader closure directories are missing")
        known = {absolute(row["path"]).resolve(): row["sha256"] for row in self.artifacts.values()
                 if row["kind"] in ("library", "plugin")}
        for directory in self.library_dirs:
            if not any(within(directory, p) for p in (self.prefix, dependency_prefix)):
                raise Blocked("loader directory is outside the selected private closure")
            entries = list(directory.iterdir())
            if len(entries) > 1024:
                raise Blocked("loader directory exceeds its finite closure bound")
            for path in entries:
                if not path.is_file() or not (path.name.endswith((".so", ".dylib")) or ".so." in path.name):
                    continue
                digest = known.get(path.resolve())
                if digest is None:
                    raise Blocked("unbound shared library could shadow the selected loader closure: " + str(path))
                self.bindings.append(checked({"path": str(path), "sha256": digest}))

    def binary(self, ident):
        return str(absolute(self.artifacts[ident]["path"]))

    def unchanged(self):
        failures = []
        for row in self.bindings + self.sources:
            try:
                if file_hash(row["path"])[0] != row["sha256"]:
                    failures.append({"path": row["path"], "error": "named input changed"})
            except BaseException as error:
                failures.append({"path": row["path"], "error": described(error)})
        return failures


def build_config(template, name, runtime, inputs):
    node = runtime / name
    for part in ("home", "data", "config", "r", "tmp", "denied"):
        (node / part).mkdir(parents=True, mode=0o700)
    normalized = {}
    tokens = {"@NODE@": str(node), "@RUNTIME@": str(node / "r"),
              "@C_PREFIX@": str(inputs.prefix)}
    for section, values in template.items():
        label = section.upper()
        if label in normalized or any(c in section for c in "\r\n[]\0"):
            raise Blocked("ambiguous complete configuration section")
        normalized[label] = {}
        for key, value in values.items():
            key = key.upper()
            if not isinstance(value, str) or any(c in key + value for c in "\r\n\0") or any(c in key for c in "=[]"):
                raise Blocked("configuration must contain reviewed flat values")
            for token, replacement in tokens.items():
                value = value.replace(token, replacement)
            if "$" in value or re.search(r"@[A-Z][A-Z0-9_-]*@", value):
                raise Blocked("complete default expansion has an unresolved variable: " + label + "/" + key)
            normalized[label][key] = value
    def put(section, **values):
        normalized.setdefault(section, {}).update(values)
    for section, values in normalized.items():
        values.pop("USERNAME", None)
        if "BINARY" in values:
            values.update(START_ON_DEMAND="NO", PREFIX="", BINARY=str(node / "denied" / "no-autostart"))
        if section.startswith("COMMUNICATOR-"):
            values["IMMEDIATE_START"] = "NO"
    put("PATHS", GNUNET_HOME=str(node / "home"), GNUNET_DATA_HOME=str(node / "data"),
        GNUNET_CONFIG_HOME=str(node / "config"), GNUNET_CACHE_HOME=str(node / "data" / "cache"),
        GNUNET_RUNTIME_DIR=str(node / "r"), GNUNET_USER_RUNTIME_DIR=str(node / "r"),
        GNUNET_TMP=str(node / "tmp"), DEFAULTCONFIG=str(node / "node.conf"))
    put("PEER", PRIVATE_KEY=str(node / "data" / "peer.key"))
    put("PILS", SECRET_KEY_FILE=str(node / "data" / "unused-template-pils.key"))
    put("UTIL", MONOTONIC_TIME_FILENAME=str(node / "data" / "monotonic-time"))
    put("STATISTICS", DATABASE=str(node / "data" / "statistics.dat"))
    put("PEERSTORE", USE_INCLUDED_HELLOS="NO")
    put("PEERSTORE-RUST", DIRECTORY=str(node / "data" / "peerstore"))
    put("TRANSPORT", USE_BURST_NAT="NO")
    put("TRANSPORT-RUST", MONOTIME_STORE=str(node / "data" / "transport-monotime"),
        DV_STORE=str(node / "data" / "transport-dv"), PILS_PROFILE="reference-0.29.1")
    put("COMMUNICATOR-UNIX", UNIXPATH=str(node / "r" / "u"), IMMEDIATE_START="NO")
    put("NAT", ENABLE_UPNP="NO", ENABLE_IPSCAN="NO", USE_STUN="NO", STUN_SERVERS="",
        RETURN_LOCAL_ADDRESSES="YES", DISABLEV6="YES")
    put("TESTING", SKEW_OFFSET="0", SKEW_VARIANCE="0", SPEEDUP_INTERVAL="0 s", SPEEDUP_DELTA="0 s")
    put("ARM", START_SYSTEM_SERVICES="NO", DEFAULTSERVICES="")
    for service in SERVICES:
        put(service.upper(), UNIXPATH=str(node / "r" / service), PORT="0", HOSTNAME="localhost",
            BINDTO="127.0.0.1", DISABLEV6="YES", UNIX_MATCH_UID="YES", UNIX_MATCH_GID="YES",
            START_ON_DEMAND="NO", DISABLE_SOCKET_FORWARDING="YES",
            ACCEPT_FROM="127.0.0.1;", ACCEPT_FROM6="::1;")
    # The complete template must explicitly privateize official time-file state
    # and any other mutable defaults. Never read/hash those eventual files.
    mutable = {"PRIVATE_KEY", "SECRET_KEY_FILE", "UNIXPATH", "FILENAME", "DATABASE_FILE",
               "MONOTIME_STORE", "DV_STORE", "PEER_MONOTIME_FILE", "DIRECTORY"}
    for section, values in normalized.items():
        for key, value in values.items():
            file_key = key in mutable or ("TIME" in key and ("FILE" in key or "DIR" in key))
            if file_key and value and not within(absolute(value), node):
                raise Blocked("mutable default is not private: " + section + "/" + key)
            if ("POSTGRES" in section or "MYSQL" in section) and key in ("CONFIG", "CONNECTION", "CONNECTION_STRING"):
                values[key] = ""
    for service in SERVICES:
        if len(normalized[service.upper()]["UNIXPATH"].encode()) > 95:
            raise Blocked("owned Unix endpoint exceeds the short-path policy")
    path = node / "node.conf"
    parser = configparser.RawConfigParser(interpolation=None)
    parser.optionxform = str
    for section, values in normalized.items():
        parser[section] = values
    with path.open("x", encoding="utf-8") as stream:
        parser.write(stream)
    path.chmod(0o600)
    return {"root": node, "config": path, "sections": normalized,
            "config_sha256": file_hash(path)[0], "unix_address": str(node / "r" / "u")}


def environment(node, inputs):
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
           "XDG_CONFIG_HOME": str(node["root"] / "config"),
           "XDG_DATA_HOME": str(node["root"] / "data"),
           "XDG_RUNTIME_DIR": str(node["root"] / "r"), "TMPDIR": str(node["root"] / "tmp"),
           "GNUNET_HOME": str(node["root"] / "home"), "GNUNET_PREFIX": str(inputs.prefix)}
    for name in ("HOME", "home", "CODEX_HOME"):
        if name in os.environ:
            env[name] = os.environ[name]
    env["DYLD_LIBRARY_PATH" if sys.platform == "darwin" else "LD_LIBRARY_PATH"] = ":".join(map(str, inputs.library_dirs))
    return env


def unix_probe(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(0.1)
        try:
            channel.connect(str(path))
            return True
        except (FileNotFoundError, ConnectionRefusedError, socket.timeout):
            return False


def current_pid(data):
    matches = re.findall(rb"(?m)^(" + BASE32.encode() + rb"{52})\r?$", data)
    if len(matches) != 1:
        raise ObservationError("PILS once must return exactly one actual public peer")
    return matches[0].decode("ascii")


def checked_hello(data, address):
    lines = [line.decode("ascii") for line in data.splitlines() if line.startswith(b"gnunet://hello/")]
    if len(lines) != 1:
        raise ObservationError("normal HELLO export did not return exactly one signed URL")
    url = urlsplit(lines[0])
    parts = url.path.strip("/").split("/")
    if (url.scheme != "gnunet" or url.netloc != "hello" or len(parts) != 3
            or not PUBLIC.fullmatch(parts[0]) or not re.fullmatch(BASE32 + r"{103}", parts[1])
            or not parts[2].isdigit() or url.fragment):
        raise ObservationError("normal signed HELLO URL has an invalid public shape")
    if not url.query:
        return None
    rows = parse_qsl(url.query, keep_blank_values=True, strict_parsing=True)
    if rows != [("unix", address)]:
        raise ObservationError("signed HELLO must advertise only this node's exact owned UNIX endpoint")
    return parts[0], (lines[0] + "\n").encode("ascii")


def wait_child(control, owner, deadline, required=True):
    owner.allow_exit = True
    control.wait(lambda: owner.process.poll() if owner.process.poll() is not None else None,
                 deadline, "original child exit")
    while owner.open_readers:
        deadline.check()
        control.pump(min(0.05, deadline.remaining()))
    code = owner.process.wait(timeout=0)
    owner.row.update(exit_code=code, reaped=True)
    control.finalize(owner)
    if required and code != 0:
        raise ObservationError("original normal child failed: " + owner.row["name"] + " code=" + str(code))
    return code


def command(control, inputs, nodes, envs, phase, ident, node, args, name, stdin=None, seconds=10):
    target = Deadline(seconds, phase)
    owner = control.start(name, [inputs.binary(ident), "-c", str(nodes[node]["config"]), "-L", "ERROR"] + list(args),
                          envs[node], role="command", stdin_data=stdin, deadline=target)
    wait_child(control, owner, target)
    return bytes(owner.output["stdout"])


def payload_observation(owner, local, remote, middle, role):
    data = bytes(owner.output["stdout"]).replace(b"\r", b"")
    expected = ["OPEN role=" + role,
                "MIDDLE_INTEREST peer=" + middle + " admission=local-only",
                "INITIALIZED peer=" + local + " matched=yes",
                "TARGET peer=" + remote,
                "PEER_MQ_HANDOFF peer=" + remote + " bytes=16 assurance=core-client-queue-only",
                "RECEIVE peer=" + remote + " bytes=16 matched=yes",
                "END passed=yes peer_mq_handoff=yes received=yes reason=complete"]
    lines = data.decode("ascii").splitlines()
    duplicate = "DUPLICATE_RECEIVE peer=" + remote + " bytes=16"
    middle_disconnect = "DISCONNECTED peer=" + middle
    optional = {duplicate, middle_disconnect}
    if any(lines.count(line) != 1 for line in expected) or any(line not in expected and line not in optional for line in lines):
        raise ObservationError("actual C public-API caller lacks exact once-only peer/handoff/receive evidence")
    if lines[0] != expected[0] or lines[-1] != expected[-1]:
        raise ObservationError("public API terminal observation is out of order")
    if lines.index(expected[2]) > lines.index(expected[3]):
        raise ObservationError("CORE target was reported before actual local initialization")
    return {"owner": owner.row["id"], "role": role, "local": local, "remote": remote,
            "middle": middle, "exact_lines": expected, "duplicate_receive_observations": lines.count(duplicate),
            "middle_disconnect_observations": lines.count(middle_disconnect),
            "peer_mq_handoff_proves_core_ipc_write": False,
            "peer_mq_handoff_is_remote_ack": False}


def route_observation(data, target):
    text = data.decode("utf-8").replace("\r", "")
    blocks = re.split(r"\n\s*\n", text.strip())
    selected = [block for block in blocks if block.splitlines() and block.splitlines()[0] == target]
    if len(selected) != 1:
        raise ObservationError("official CLI did not list exactly the requested full peer")
    block = selected[0]
    if not re.search(r"(?m)^  routed:\s+dv \(2 hops\) over unix \(1 queue\(s\)\)$", block):
        raise ObservationError("official CLI target is not the required two-hop UNIX path")
    if not re.search(r"(?m)^  established:\s+yes$", block):
        raise ObservationError("official CLI two-hop target is not established")
    return {"target": target, "actual_verbose_block": block}


def early_snapshot(control, inputs, nodes, envs, phase, node, result):
    """Optional evidence only: its real failure is retained without changing data predicates."""
    target = Deadline(5, phase)
    owner = control.start(node + "-early-links", [inputs.binary("c.cli.transport"), "-c", str(nodes[node]["config"]),
                          "-L", "ERROR", "-a", "-V"], envs[node], role="command", deadline=target)
    owner.allow_exit = True
    row = {"node": node, "owner": owner.row["id"], "required_for_data_pass": False}
    result.setdefault("early_route_observations", []).append(row)
    try:
        row["exit_code"] = wait_child(control, owner, target, required=False)
    except ObservationError as error:
        # A diagnostic's own timeout is optional. Output loss, a service exit
        # or a batch/source failure is never downgraded into optional evidence.
        if (time.monotonic() < target.hard or time.monotonic() >= phase.hard
                or any(child.row.get("output_overflow") for child in control.children)
                or any(child.process is not None and not child.allow_exit
                       and child.row["role"] != "command" and child.process.poll() is not None
                       for child in control.children)):
            raise
        row["observation_failure"] = described(error)
        # This is retirement of the failed original diagnostic, not a new list
        # attempt or a renewed caller/operation deadline.
        cleanup = Deadline(2, phase)
        control.signal(owner, signal.SIGTERM)
        try:
            wait_child(control, owner, cleanup, required=False)
        except ObservationError:
            control.signal(owner, signal.SIGKILL)
            raise  # unreaped original output/child can never be ignored


def run_profile(control, inputs, runtime, result, nodes):
    phase = Deadline(230, control.deadline)
    phase.hard = min(phase.hard, control.deadline.hard - 10)
    result["business_deadline_monotonic"] = phase.hard
    services, envs = {}, {}
    for name in ("a", "b", "c"):
        nodes[name] = build_config(inputs.sections, name, runtime, inputs)
        envs[name] = environment(nodes[name], inputs)
    if inputs.diagnostic:
        # Official, existing function/line log filters only. B sees one remote
        # address; C remains isolated. No reference source or timing is changed.
        functions = (("start_address_validation", "10749-10753"),
                     ("handle_flow_control", "11992-11994"),
                     ("handle_validation_challenge", "11088-11091"),
                     ("validation_start_cb", ""), ("", "14800-15045"))
        envs["b"]["GNUNET_FORCE_LOG"] = "/".join(
            ";gnunet-service-transport.c;" + function + ";" + lines + ";DEBUG"
            for function, lines in functions)
    result["nodes"] = {name: {"config": str(node["config"]), "config_sha256": node["config_sha256"],
                                    "runtime": str(node["root"]), "unix_address": node["unix_address"]}
                       for name, node in nodes.items()}
    # Per-node dependencies remain live until the reverse-dependency shutdown.
    for service in SERVICES:
        for name in nodes:
            ident = "c.service.transport" if name == "b" and service == "transport" and inputs.middle == "c" else "rust.service." + service
            child = control.start(name + "-" + service, [inputs.binary(ident), "-c", str(nodes[name]["config"]), "-L", "INFO"],
                                  envs[name], role="service", deadline=phase)
            services[name, service] = child
            startup = Deadline(15, phase)
            control.wait(lambda name=name, service=service: True if unix_probe(nodes[name]["sections"][service.upper()]["UNIXPATH"]) else None,
                         startup, "normal private listener")
            if ident.startswith("rust."):
                control.observed(child, rb"(?m)^READY(?:[ \t]|$)", startup)
        if service == "transport":
            # Every NAT is already ready before any TRANSPORT is launched.
            for name in nodes:
                child = control.start(name + "-communicator-unix", [inputs.binary("rust.communicator.unix"), "-c", str(nodes[name]["config"]), "-L", "INFO"],
                                      envs[name], role="service", deadline=phase)
                services[name, "communicator"] = child
                control.observed(child, rb"(?m)^READY communicator-unix\b", Deadline(15, phase))
    pids, hellos = {}, {}
    for name in nodes:
        candidate = None
        # The official C TRANSPORT batches address publication for three seconds.
        # Observe readiness within one original bound, with a finite number of
        # fresh read-only exports; an empty early HELLO is not a routing failure.
        hello_ready = Deadline(10, phase)
        for attempt in range(5):
            data = command(control, inputs, nodes, envs, hello_ready, "rust.cli.hello", name,
                           ["-e", "-E", "5 min"], name + "-hello-" + str(attempt))
            candidate = checked_hello(data, nodes[name]["unix_address"])
            if candidate is not None:
                break
            if attempt < 4:
                retry_at = time.monotonic() + 1
                control.wait(lambda: True if time.monotonic() >= retry_at else None,
                             hello_ready, "normal signed address publication")
        if candidate is None:
            raise ObservationError("normal HELLO never advertised its exact owned UNIX endpoint")
        peer, hello = candidate
        actual = current_pid(command(control, inputs, nodes, envs, phase, "rust.cli.pils", name,
                                     ["-1"], name + "-pils"))
        if actual != peer or peer in pids.values():
            raise ObservationError("signed HELLO/current PILS peer binding is not original and independent")
        pids[name], hellos[name] = peer, hello
    result["active_public_peers"] = pids
    result["hello_import_edges"] = []
    edges = (("a", "b"), ("b", "a")) if inputs.diagnostic else (
        ("a", "b"), ("b", "a"), ("b", "c"), ("c", "b"))
    for source, destination in edges:
        command(control, inputs, nodes, envs, phase, "rust.cli.hello", destination, ["-i"],
                destination + "-import-" + source, stdin=hellos[source])
        result["hello_import_edges"].append([source, destination])
    if phase.remaining() < 165:
        raise ObservationError("insufficient original batch time for the unchanged130/140s caller targets and shutdown")
    callers = {}
    caller_bound = Deadline(140, phase)
    absolute_us = time.time_ns() // 1000 + 130_000_000
    result["caller_original_deadlines"] = {"absolute_us": absolute_us, "native_monotonic": caller_bound.hard,
                                            "duration_us": 130_000_000}
    for name, remote in (("a", "c"), ("c", "a")):
        child = control.start(name + "-C-public-CORE-application", [inputs.binary("component.core_dv"),
                              "-c", str(nodes[name]["config"]), "-L", "ERROR", name,
                              pids[name], pids[remote], pids["b"], str(absolute_us)],
                              envs[name], role="command", deadline=caller_bound)
        child.allow_exit = True
        callers[name] = child
    snapshot_at = time.monotonic() + 20
    diagnostic_until = time.monotonic() + 75 if inputs.diagnostic else None
    if diagnostic_until is not None:
        result["diagnostic_deadline_monotonic"] = diagnostic_until
        result["diagnostic_observation_seconds"] = 75
    snapshotted = False
    while any(child.process.poll() is None for child in callers.values()):
        caller_bound.check()
        phase.check()
        if diagnostic_until is not None and time.monotonic() >= diagnostic_until:
            raise DiagnosticComplete("fixed single-neighbour validation observation ended; no interoperability result")
        for child in callers.values():
            code = child.process.poll()
            if code is not None and code != 0:
                wait_child(control, child, caller_bound)
        if not snapshotted and time.monotonic() >= snapshot_at:
            snapshotted = True
            if inputs.manifest.get("early_route_snapshots", True) and all(child.process.poll() is None for child in callers.values()):
                for name in nodes:
                    early_snapshot(control, inputs, nodes, envs, phase, name, result)
        control.pump(min(0.1, caller_bound.remaining(), phase.remaining()))
    observations = []
    for name, remote in (("a", "c"), ("c", "a")):
        wait_child(control, callers[name], caller_bound)
        observations.append(payload_observation(callers[name], pids[name], pids[remote], pids["b"], name))
    result["checks"].append({"id": "both-exact-public-CORE-receives-and-peer-MQ-handoff", "observations": observations})
    routes = []
    for name, remote in (("a", "c"), ("c", "a")):
        data = command(control, inputs, nodes, envs, phase, "c.cli.transport", name,
                       ["-a", "-V", "-p", pids[remote]], name + "-final-two-hop", seconds=10)
        routes.append(route_observation(data, pids[remote]))
    result["checks"].append({"id": "both-actual-official-CLI-established-two-hop-UNIX-routes", "observations": routes})
    for name in nodes:
        actual = current_pid(command(control, inputs, nodes, envs, phase, "rust.cli.pils", name,
                                     ["-1"], name + "-pils-final"))
        if actual != pids[name]:
            raise ObservationError("actual original PILS identity changed during the case")
    stop = Deadline(20, phase)
    for role in STOP_ORDER:
        group = [services[name, role] for name in nodes]
        for child in group:
            child.allow_exit = True
            control.signal(child, signal.SIGTERM)
        for child in group:
            wait_child(control, child, stop)
    result["checks"].append({"id": "all-normal-services-exit0", "owners": [child.row["id"] for child in services.values()]})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--middle", choices=("rust", "c"), required=True)
    parser.add_argument("--execute", action="store_true", help="explicitly run the already authorized private profile")
    args = parser.parse_args(argv)
    if not args.execute:
        raise Blocked("explicit --execute is required; import/source preparation starts no product")
    output = absolute(args.output)
    if output.exists() or not any(within(output, root) for root in (REPO / "target", Path("/private/tmp"))):
        raise Blocked("output must be a fresh selected private evidence directory")
    output.mkdir(mode=0o700)
    result = {"schema": 1, "profile": PROFILE, "middle": args.middle, "official_revision": REVISION,
              "status": "blocked", "executed": False, "checks": [], "whole_goal_complete": False,
              "normal_services": True, "payload_caller_is_explicit_public_API_component": True,
              "full_C_CORE_or_BOX_endpoint_algorithm_credit": False,
              "private_runtime_removed": False, "cleanup_errors": [], "participants": []}
    control, inputs, runtime, nodes = None, None, None, {}
    previous = {}
    try:
        manifest_ref = checked({"path": str(absolute(args.manifest)), "sha256": file_hash(args.manifest, MAX_METADATA)[0]})
        result["manifest"] = manifest_ref
        inputs = Inputs(load_json(manifest_ref["path"]), args.middle)
        result["diagnostic_mode"] = inputs.diagnostic
        inputs.bindings.append(manifest_ref)
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise Blocked("ordinary exclusive consuming child-wait ownership is required")
        processes = output / "processes"
        processes.mkdir(mode=0o700)
        control = Controller(processes, seconds=240, output_bytes=2 << 20,
                             total_output_bytes=96 << 20, maximum_children=64)
        result["global_original_deadline_monotonic"] = control.deadline.hard
        def interrupted(signum, frame):
            if not control.active:
                control.cleanup_signal(signum)
            else:
                raise InterruptedError("original private DV case interrupted: " + str(signum))
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, interrupted)
        allocation = Owner(0, "private-runtime-root", "metadata", [])
        result["runtime_acquisition"] = allocation.row
        def acquire_runtime():
            nonlocal runtime
            runtime = Path(tempfile.mkdtemp(prefix="gdv-", dir="/private/tmp"))
            runtime.chmod(0o700)
        control.acquire(allocation, acquire_runtime)
        result["private_runtime"] = str(runtime)
        run_profile(control, inputs, runtime, result, nodes)
        result["status"] = "passed"
    except BaseException as error:
        result["primary"] = described(error)
        spawned = control is not None and any(child.row["spawned"] for child in control.children)
        result["status"] = ("observed" if isinstance(error, DiagnosticComplete) else
                            "blocked" if isinstance(error, Blocked) and not spawned else "failed")
    finally:
        if control is not None:
            control.active = False
            # The cleanup target is the remaining part of the original240s,
            # never a renewed business/caller deadline or fresh240s attempt.
            remaining = max(0, min(10, control.deadline.hard - time.monotonic()))
            try:
                control.cleanup(remaining)
            except BaseException as error:
                control.cleanup_error(None, "controller-cleanup", error)
            result["participants"] = control.reports()
            result["cleanup_errors"] = list(control.cleanup_errors)
            result["cleanup_overflow"] = control.cleanup_overflow
            result["executed"] = any(child.row["spawned"] for child in control.children)
            result["global_target_exceeded"] = time.monotonic() > control.deadline.hard
        if inputs is not None:
            result["participant_or_source_changes"] = inputs.unchanged()
        configs_unchanged = True
        for name, node in nodes.items():
            try:
                if file_hash(node["config"])[0] != node["config_sha256"]:
                    configs_unchanged = False
            except BaseException as error:
                configs_unchanged = False
                result["cleanup_errors"].append({"stage": "config-final-hash", "error": described(error)})
        result["configs_unchanged"] = configs_unchanged
        result["all_original_children_reaped"] = control is None or all(
            child.process is None or child.row["reaped"] for child in control.children)
        result["all_capture_drained"] = control is None or all(
            child.process is None or child.row.get("capture_drained") is True for child in control.children)
        result["all_parent_resources_closed"] = control is None or all(
            child.row.get("parent_resources_closed") is True for child in control.children)
        result["output_bounds_respected"] = control is None or not any(
            child.row.get("output_overflow") for child in control.children)
        clean = (result["all_original_children_reaped"] and result["all_capture_drained"]
                 and result["all_parent_resources_closed"] and not result["cleanup_errors"]
                 and result["output_bounds_respected"]
                 and not result.get("cleanup_overflow") and not result.get("participant_or_source_changes")
                 and configs_unchanged and not result.get("global_target_exceeded", False))
        if runtime is not None and clean and result["status"] == "passed":
            try:
                shutil.rmtree(runtime)
                result["private_runtime_removed"] = not runtime.exists()
            except BaseException as error:
                clean = False
                result["cleanup_errors"].append({"stage": "private-runtime-remove", "error": described(error)})
        if not clean:
            result["status"] = "failed"
        for signum, handler in previous.items():
            try:
                signal.signal(signum, handler)
            except BaseException as error:
                result["cleanup_errors"].append({"stage": "restore-signal-handler", "error": described(error)})
                result["status"] = "failed"
        result["selected_runtime_verified"] = (result["status"] == "passed"
                                                and not result.get("diagnostic_mode")
                                                and len(result["checks"]) == 3)
        if result["status"] == "passed" and not result["selected_runtime_verified"]:
            result["status"] = "failed"
        write_json(output / "result.json", result)
    print(json.dumps({"status": result["status"], "result": str(output / "result.json")}), flush=True)
    return 0 if result["status"] in ("passed", "observed") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Blocked as error:
        raise SystemExit(str(error))
