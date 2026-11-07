#!/usr/bin/env python3
"""Owned first-normal Conversation no-device controller; execution is opt-in.

No product, build, helper, codec actor, key, socket or device is used at import.
Root must supply real normal-build receipts and an explicit human-approval
binding before this script may create normal participant processes. This file
contains no build/download/test catalog or device/reverse-peer implementation.
"""
import argparse
import configparser
import ipaddress
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

from conversation_owned import (Blocked, Controller, Deadline, ObservationError,
                                Owner, described, file_hash)

REVISION = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165"
PROFILE = "first-normal-no-device-c-caller-to-rust-callee"
RUST_CADET_PROFILE = "first-normal-no-device-c-caller-to-rust-callee-rust-cadet-backbone"
CADET_PROFILES = {"c": PROFILE, "rust": RUST_CADET_PROFILE}
SERVICES = ("resolver", "statistics", "peerstore", "pils", "setu", "revocation",
            "nat", "transport", "core", "dht", "cadet", "identity", "namestore", "namecache",
            "zonemaster", "gns")
C_CLIENTS = ("pils", "hello", "identity", "namestore", "transport", "conversation")
REQUIRED_C = {"c.service." + name for name in SERVICES} | {
    "c.communicator.tcp", "c.service.conversation"} | {"c.cli." + name for name in C_CLIENTS}
REQUIRED_RUST = {"rust.cli.conversation", "rust.service.conversation", "rust.cli.gns",
                 "rust.helper.launcher"}
BASE32 = r"[0123456789ABCDEFGHJKMNPQRSTVWXYZ]"
PERMISSIONS = {"private-runtime-files", "normal-keygen-signing", "normal-storage",
               "private-unix", "two-loopback-tcp-peers", "owned-normal-process-control",
               "participant-source-artifact-hashing"}
MAX_METADATA = 16 << 20


def load_json(path):
    path = Path(path)
    try:
        if path.stat().st_size > MAX_METADATA:
            raise Blocked("metadata file exceeds its finite JSON bound")
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise Blocked("required public metadata is missing/unreadable/invalid: " + str(path) + ": " + str(error)) from error


def write_json(path, value):
    # Never overwrite a previous attempt's evidence. Each run uses a fresh root.
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()


def absolute(path):
    value = Path(path)
    if not value.is_absolute() or "\0" in str(value):
        raise Blocked("all selected input paths must be absolute")
    return value


def within(path, root):
    return Path(path).resolve().is_relative_to(Path(root).resolve())


def checked_ref(row):
    path = absolute(row["path"])
    try:
        actual, size = file_hash(path)
    except OSError as error:
        raise Blocked("required named build/source participant is unavailable: " + str(path) + ": " + str(error)) from error
    if not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) or actual != row["sha256"]:
        raise Blocked("named prerequisite changed: " + str(path))
    return {"path": str(path), "sha256": actual, "bytes": size}


def selected_profile(cadet_backend):
    if cadet_backend not in CADET_PROFILES:
        raise Blocked("unknown explicitly selected CADET backend")
    return CADET_PROFILES[cadet_backend]


def approval(manifest_path, approval_path, script_path, cadet_backend="c"):
    try:
        digest, _ = file_hash(manifest_path, MAX_METADATA)
    except OSError as error:
        raise Blocked("required selected manifest is unavailable: " + str(error)) from error
    record = load_json(approval_path)
    script_digest, _ = file_hash(script_path, MAX_METADATA)
    owner_digest, _ = file_hash(Path(script_path).with_name("conversation_owned.py"), MAX_METADATA)
    if record.get("authorized") is not True or record.get("schema") != 1:
        raise Blocked("explicit future no-device runtime approval is absent")
    if record.get("manifest_sha256") != digest or record.get("controller_sha256") != script_digest or record.get("owner_module_sha256") != owner_digest:
        raise Blocked("approval does not bind these exact reviewed inputs/controller bytes")
    if record.get("profile") != selected_profile(cadet_backend) or set(record.get("permissions", [])) != PERMISSIONS:
        raise Blocked("approval scope differs from the selected private no-device profile")
    if record.get("cadet_backend", "c") != cadet_backend:
        raise Blocked("approval does not explicitly select this CADET backend")
    if not isinstance(record.get("human_authorization_reference"), str) or not record["human_authorization_reference"].strip():
        raise Blocked("Root must retain the actual explicit human authorization reference")
    expires = record.get("expires_unix")
    if not isinstance(expires, (float, int)) or not time.time() < expires <= time.time() + 86400:
        raise Blocked("approval is expired or not a finite current one-day authorization")
    # JSON is an accidental-execution fence, not a cryptographic proof of who
    # typed permission. Root must create it only after the actual human reply.
    return {"manifest_sha256": digest, "controller_sha256": script_digest,
            "profile": selected_profile(cadet_backend), "cadet_backend": cadet_backend,
            "owner_module_sha256": owner_digest, "approval": checked_ref({
                "path": str(absolute(approval_path)), "sha256": file_hash(approval_path)[0]}),
            "human_authorization_reference": record["human_authorization_reference"]}


class Inputs:
    def __init__(self, manifest, cadet_backend="c"):
        self.cadet_backend = cadet_backend
        self.profile = selected_profile(cadet_backend)
        if manifest.get("schema") != 1 or manifest.get("profile") != self.profile:
            raise Blocked("manifest profile differs from the explicitly selected no-device profile")
        if manifest.get("cadet_backend", "c") != cadet_backend:
            raise Blocked("manifest does not explicitly select this CADET backend")
        required_c, required_rust = set(REQUIRED_C), set(REQUIRED_RUST)
        if cadet_backend == "rust":
            required_c.remove("c.service.cadet")
            required_rust.add("rust.service.cadet")
        if manifest.get("official_revision") != REVISION:
            raise Blocked("official source must be the fixed unmodified v0.29.1 revision")
        if manifest.get("gns_probe") != "rust-normal-cli":
            raise Blocked("normal C gnunet-gns requires ARM; this no-ARM profile uses the real Rust GNS CLI, never a fake ARM listener")
        if manifest.get("device") is not False or manifest.get("reverse_peer") is not False:
            raise Blocked("device and Rust-peer -> C-callee stages remain unapproved/blocked")
        self.manifest = manifest
        self.receipts = {}
        self.bindings = []
        for name in ("c", "rust"):
            row = manifest["build_receipts"][name]
            self.bindings.append(checked_ref(row))
            receipt = load_json(row["path"])
            if receipt.get("schema") != 1 or receipt.get("status") != "passed" or receipt.get("kind") != "normal-binary-build" or receipt.get("build_executed") is not True:
                raise Blocked("a static check/declared Meson target is not an actual normal-binary build receipt")
            if receipt.get("native_system") != platform.system() or receipt.get("native_machine") != platform.machine():
                raise Blocked("selected binary build is not native to this execution host")
            if receipt.get("implementation") != name or receipt.get("modified_official_source", False):
                raise Blocked("unmodified official C / actual normal Rust producer receipt mismatch")
            if name == "c" and receipt.get("official_revision") != REVISION:
                raise Blocked("C build receipt does not bind the exact official revision")
            if not 1 <= len(receipt.get("underlying_receipts", [])) <= 64 or not 1 <= len(receipt.get("source_bindings", [])) <= 512:
                raise Blocked("bounded underlying build/source index is absent or too large")
            for underlying in receipt.get("underlying_receipts", []):
                self.bindings.append(checked_ref(underlying))
            if not receipt.get("underlying_receipts") or not receipt.get("source_bindings"):
                raise Blocked("normalized build index must point to actual compiler/source build evidence")
            for source in receipt["source_bindings"]:
                # Explicit source/manifest/receipt inputs only; never runtime
                # node keys/DB/dump/PCM. No legacy catalog/source_state is called.
                self.bindings.append(checked_ref(source))
            self.receipts[name] = receipt
        if self.receipts["c"].get("runtime_closure_staged") is not True or self.receipts["c"].get("generated_defaults_complete") is not True or self.receipts["c"].get("phone_plugin_present") is not True:
            raise Blocked("C selected libraries/plugins/defaults/PHONE closure has not actually been staged and receipted")
        self.artifacts = {}
        total = 0
        rows = manifest.get("artifacts", [])
        if not 1 <= len(rows) <= 512:
            raise Blocked("selected artifact closure count is invalid")
        destinations = set()
        for row in rows:
            ident = row["id"]
            if ident in self.artifacts or row["implementation"] not in self.receipts or not ident.startswith(row["implementation"] + "."):
                raise Blocked("duplicate/unknown normal artifact producer")
            dest = Path(row["snapshot_relative"])
            if dest.is_absolute() or ".." in dest.parts or not dest.parts or dest.parts[0] not in ("c-prefix", "rust", "deps"):
                raise Blocked("artifact snapshot path escapes its owned root")
            if str(dest) in destinations:
                raise Blocked("artifact snapshot paths must be unique")
            destinations.add(str(dest))
            if dest.name.startswith("gnunet-helper-audio-"):
                raise Blocked("audio executables are not staged into this physical no-device guard")
            actual = checked_ref(row)
            total += actual["bytes"]
            if total > 2 << 30:
                raise Blocked("selected artifact closure exceeds2GiB")
            produced = self.receipts[row["implementation"]].get("artifacts", {}).get(ident)
            if produced != {"path": row["path"], "sha256": row["sha256"]}:
                raise Blocked("artifact lacks its exact actual normal compiler-produced receipt: " + ident)
            if row.get("kind") not in ("binary", "library", "plugin", "default"):
                raise Blocked("only selected normal binaries/libraries/plugins/generated defaults may be staged")
            row = dict(row)
            row["bytes"] = actual["bytes"]
            self.artifacts[ident] = row
        if not (required_c | required_rust) <= self.artifacts.keys():
            raise Blocked("required normal C/Rust Conversation/backbone/GNS artifacts are missing")
        for ident in required_c | required_rust:
            if self.artifacts[ident]["kind"] != "binary":
                raise Blocked("normal participant must be a real receipted executable")
        self.templates = {}
        for name in ("a", "b"):
            row = manifest["configs"][name]
            self.bindings.append(checked_ref(row))
            template = load_json(row["path"])
            if template.get("kind") != "complete-generated-default-expansion" or template.get("complete") is not True:
                raise Blocked("a short override alone is not a complete private generated-default configuration")
            self.bindings.append(checked_ref(template["defaults_receipt"]))
            sections = template.get("sections")
            if not isinstance(sections, dict) or not all(isinstance(v, dict) for v in sections.values()):
                raise Blocked("complete configuration sections are absent")
            self.templates[name] = sections
        self.snapshots = {}
        self.snapshot_rows = []

    def snapshot(self, root):
        self.root = root
        for ident, row in self.artifacts.items():
            target = root / row["snapshot_relative"]
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with absolute(row["path"]).open("rb") as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, 1 << 16)
            target.chmod(0o555 if row["kind"] == "binary" else 0o444)
            actual, size = file_hash(target)
            if actual != row["sha256"]:
                raise Blocked("snapshot changed during copy: " + ident)
            self.snapshots[ident] = target
            self.snapshot_rows.append({"id": ident, "path": str(target), "sha256": actual, "bytes": size})
        (root / "c-prefix/lib/gnunet/libexec").mkdir(parents=True, exist_ok=True, mode=0o700)
        for name in ("gnunet-helper-audio-record", "gnunet-helper-audio-playback"):
            if (root / "c-prefix/lib/gnunet/libexec" / name).exists():
                raise Blocked("the C no-device private libexec contains an audio helper")

    def unchanged(self):
        failures = []
        for row in self.bindings + list(self.artifacts.values()) + self.snapshot_rows:
            try:
                actual, _ = file_hash(row["path"])
                if actual != row["sha256"]:
                    failures.append({"path": row["path"], "error": "input/participant bytes changed"})
            except BaseException as error:
                failures.append({"path": row["path"], "error": described(error)})
        return failures

    def binary(self, name):
        return str(self.snapshots[name])


def public_key(data, name):
    pattern = rb"(?m)^" + re.escape(name.encode()) + rb" - (" + BASE32.encode() + rb"{58}) - (?:ECDSA|EdDSA)\r?$"
    matches = re.findall(pattern, data)
    if len(matches) != 1:
        raise ObservationError("actual public IDENTITY lookup did not return exactly the selected ego")
    return matches[0].decode("ascii")


def current_pid(data):
    matches = re.findall(rb"(?m)^(" + BASE32.encode() + rb"{52})\r?$", data)
    if len(matches) != 1:
        raise ObservationError("actual normal PILS once output did not contain one active public peer")
    return matches[0].decode("ascii")


def checked_hello(data, port):
    # This is only a public URL candidate. Startup acceptance still requires
    # one subsequent actual normal PILS sample with the exact same peer.
    lines = [line.decode("ascii") for line in data.splitlines() if line.startswith(b"gnunet://hello/")]
    if len(lines) != 1:
        raise ObservationError("actual normal HELLO export did not return one public signed URL")
    url = urlsplit(lines[0])
    parts = url.path.strip("/").split("/")
    if url.scheme != "gnunet" or url.netloc != "hello" or len(parts) != 3 or not re.fullmatch(BASE32 + r"{52}", parts[0]) or not re.fullmatch(BASE32 + r"{103}", parts[1]) or not parts[2].isdigit() or url.fragment:
        raise ObservationError("normal HELLO URL public shape is invalid")
    if not url.query:
        return None  # completed empty announcement, not a ready TCP source
    rows = parse_qsl(url.query, keep_blank_values=True, strict_parsing=True)
    for transport, address in rows:
        item = urlsplit("tcp://" + address)
        if transport != "tcp" or item.username or item.password or item.path or item.query or item.fragment or item.hostname != "127.0.0.1" or item.port != port or not ipaddress.ip_address(item.hostname).is_loopback:
            raise ObservationError("actual signed HELLO advertises a non-approved address")
    return parts[0], (lines[0] + "\n").encode("ascii")


def source_failure(owner):
    text = bytes(owner.output["stdout"] + owner.output["stderr"]).lower()
    return any(token in text for token in (b"source lost", b"service lost", b"trying to reconnect", b"source was lost", b"failed to resolve", b"error with the call", b"connection established to", b"pickedup738"))


def line_source_checkpoint(service, identity, since):
    # CallClosed retires one call, whereas this ordinary session diagnostic
    # retires the whole original IPC/PILS/CADET Line. Never substitute it for
    # a per-channel Destroyed event, including when its error is just Closed.
    client = identity["groups"][0].encode("ascii")
    captured = bytes(service.output["stderr"][since:]).replace(b"\r", b"")
    if re.search(rb"CONVERSATION original session " + client + rb":", captured):
        raise ObservationError("original Conversation Line retired during the unanswered-call case")
    return {"client": identity["groups"][0], "identity_epoch": identity["groups"][1],
            "from_offset": since, "through_offset": len(service.output["stderr"]),
            "line_terminal_diagnostic_observed": False,
            "qualification": "captured original-Line diagnostics only; not future source liveness"}


def build_config(sections, name, runtime, artifacts, port, nodes, cadet_backend="c"):
    node = runtime / name
    denied = node / "denied"
    # Register partial directory/config ownership before the first acquisition.
    state = {"root": node, "config": None, "sections": {}, "port": port,
             "denied": denied}
    nodes[name] = state
    for part in ("home", "data", "config", "r"):
        (node / part).mkdir(parents=True, mode=0o700)
    denied.mkdir(mode=0o000)
    tokens = {"@NODE@": str(node), "@RUNTIME@": str(node / "r"),
              "@C_PREFIX@": str(artifacts.root / "c-prefix"), "@PORT@": str(port)}
    normalized = {}
    for section, values in sections.items():
        label = section.upper()
        if label in normalized or any(c in section for c in "\r\n[]"):
            raise Blocked("ambiguous complete configuration section")
        normalized[label] = {}
        for key, value in values.items():
            key = key.upper()
            if not isinstance(value, str) or any(c in key + value for c in "\r\n\0") or any(c in key for c in "=[]"):
                raise Blocked("configuration must contain only flat reviewed ordinary values")
            for token, replacement in tokens.items():
                value = value.replace(token, replacement)
            if "@" in value or "$" in value:
                raise Blocked("configuration expansion must be complete before launch")
            normalized[label][key] = value
    def put(section, **values):
        normalized.setdefault(section.upper(), {}).update(values)
    # No normal participant may use inherited/system autostart or arbitrary
    # process prefixes. Manually launched TCP uses the true artifact argv below.
    for section, values in normalized.items():
        # Fixed C expands even an empty USERNAME as a filename. Omit it so
        # the normal service keeps the original caller UID/GID.
        values.pop("USERNAME", None)
        if "BINARY" in values:
            values.update(START_ON_DEMAND="NO", PREFIX="",
                          BINARY=str(denied / values["BINARY"].split("/")[-1]))
        if section.startswith("COMMUNICATOR-"):
            values["IMMEDIATE_START"] = "NO"
    put("PATHS", GNUNET_HOME=str(node / "home"), GNUNET_DATA_HOME=str(node / "data"),
        GNUNET_CONFIG_HOME=str(node / "config"), GNUNET_RUNTIME_DIR=str(node / "r"))
    put("PEER", PRIVATE_KEY=str(node / "peer.key"))
    put("PILS", SECRET_KEY_FILE=str(node / "data" / "pils-key.bin"))
    put("IDENTITY", EGODIR=str(node / "data" / "egos"),
        SUBSYSTEM_CFG=str(node / "config" / "identity-defaults.conf"))
    put("STATISTICS", DATABASE=str(node / "data" / "statistics.dat"))
    put("REVOCATION", DATABASE=str(node / "data" / "revocation.dat"))
    # Fixed peerstore defaults load distributed HELLOs. They are unsuitable
    # for a two-owned-loopback-only graph even without a HOSTLIST daemon.
    put("PEERSTORE", USE_INCLUDED_HELLOS="NO", DATABASE="sqlite")
    put("NAMESTORE", DATABASE="sqlite")
    put("NAMECACHE", DATABASE="sqlite", DISABLE="NO")
    for section in ("peerstore", "namestore", "namecache"):
        put(section + "-sqlite", FILENAME=str(node / "data" / (section + ".sqlite")))
    put("DHTCACHE", DATABASE="heap")
    for section in SERVICES + ("conversation",):
        put(section, UNIXPATH=str(node / "r" / (section + ".sock")), PORT="0", HOSTNAME="localhost",
            UNIX_MATCH_UID="YES", UNIX_MATCH_GID="YES", START_ON_DEMAND="NO",
            ACCEPT_FROM="127.0.0.1;", ACCEPT_FROM6="::1;", DISABLE_SOCKET_FORWARDING="YES")
    # Fixed v0.29.1 SETU's normal daemon uses section SET, while its API
    # selects SETU. Bind that one daemon and its clients to the same endpoint.
    put("SET", **{key: normalized["SETU"][key] for key in (
        "UNIXPATH", "PORT", "HOSTNAME", "UNIX_MATCH_UID", "UNIX_MATCH_GID",
        "START_ON_DEMAND", "ACCEPT_FROM", "ACCEPT_FROM6", "DISABLE_SOCKET_FORWARDING")})
    put("CONVERSATION", LINE="1")
    if cadet_backend == "rust":
        put("CADET-RUST", PEER_CORE="YES",
            PEER_MONOTIME_FILE=str(node / "data" / "cadet.monotime"))
    put("COMMUNICATOR-TCP", BINDTO="127.0.0.1:" + str(port),
        HOLE_EXTERNAL="127.0.0.1:" + str(port), DISABLE_V6="YES", IMMEDIATE_START="NO")
    put("NAT", ENABLE_UPNP="NO", ENABLE_IPSCAN="NO", USE_STUN="NO", STUN_SERVERS="",
        RETURN_LOCAL_ADDRESSES="YES", DISABLEV6="YES")
    put("ARM", START_SYSTEM_SERVICES="NO", DEFAULTSERVICES="")
    put("CONVERSATION-COMMAND-RUST", HELPER_RECORD=str(denied / "gnunet-helper-audio-record"),
        HELPER_PLAYBACK=str(denied / "gnunet-helper-audio-playback"),
        HELPER_LAUNCHER=artifacts.binary("rust.helper.launcher"))
    # Unknown backend connection strings must not silently contact an external
    # SQL/DNS service. Root supplies local storage profiles in the full template.
    for section, values in normalized.items():
        if any(key in values for key in ("CONFIG", "CONNECTION", "CONNECTION_STRING")) and ("POSTGRES" in section or "MYSQL" in section):
            # These are inactive installed defaults; do not require dropping
            # them from the complete expansion, and never retain a live DSN.
            for key in ("CONFIG", "CONNECTION", "CONNECTION_STRING"):
                if key in values:
                    values[key] = ""
        for key, value in values.items():
            if (key in ("PRIVATE_KEY", "SECRET_KEY_FILE", "EGODIR", "SUBSYSTEM_CFG", "KEYFILE", "KEYFILENAME", "UNIXPATH", "FILENAME", "DATABASE_FILE", "PEER_MONOTIME_FILE") or (section == "REVOCATION" and key == "DATABASE")) and value and not within(Path(value), node):
                raise Blocked("mutable node path is not owned by its original private node")
    for section in SERVICES + ("conversation",):
        if len(normalized[section.upper()]["UNIXPATH"].encode()) > 95:
            raise Blocked("private Unix path exceeds the portable short-path policy")
    path = node / "node.conf"
    config = configparser.RawConfigParser(interpolation=None)
    config.optionxform = str
    for section, values in normalized.items():
        config[section] = values
    with path.open("x", encoding="utf-8") as output:
        config.write(output)
    path.chmod(0o600)
    state.update(config=path, sections=normalized)
    return state


def child_environment(node, artifacts):
    # No inherited activation/control fds, GNUNET_ARGS/prefixes, credentials,
    # service overrides, audio server or ambient user configuration are retained.
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
           "HOME": str(node["root"] / "home"), "XDG_CONFIG_HOME": str(node["root"] / "config"),
           "XDG_DATA_HOME": str(node["root"] / "data"), "XDG_RUNTIME_DIR": str(node["root"] / "r"),
           "GNUNET_HOME": str(node["root"] / "home"),
           "GNUNET_PREFIX": str(artifacts.root / "c-prefix"),
           "PULSE_SERVER": "unix:" + str(node["denied"] / "no-audio-server")}
    libraries = [str(artifacts.root / "c-prefix/lib"), str(artifacts.root / "deps/lib")]
    env["DYLD_LIBRARY_PATH" if sys.platform == "darwin" else "LD_LIBRARY_PATH"] = ":".join(libraries)
    return env


def unix_probe(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(0.1)
        try:
            channel.connect(str(path))
            return True
        except (FileNotFoundError, ConnectionRefusedError, socket.timeout):
            return False


def reserve_ports(control, result):
    values = []
    row = Owner(0, "loopback-port-reservations", "metadata", [])
    result["loopback_reservations"] = row.row
    row.row["ports"] = values
    sockets = [None, None]
    def acquire():
        for index in range(2):
            sockets[index] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockets[index].bind(("127.0.0.1", 0))
            value = sockets[index].getsockname()[1]
            if not 1024 <= value <= 65535:
                raise Blocked("kernel did not reserve an unprivileged loopback port")
            values.append(value)
    original = None
    errors = []
    try:
        control.acquire(row, acquire)
    except BaseException as error:
        original = error
    finally:
        for channel in sockets:
            if channel is not None:
                try:
                    channel.close()
                except BaseException as error:
                    control.cleanup_error(None, "loopback-reservation-close", error)
                    errors.append(error)
        row.row["all_closed"] = not errors
    if original is not None:
        raise original
    if errors:
        raise errors[0]
    if len(values) != 2 or values[0] == values[1]:
        raise ObservationError("two distinct original loopback reservations were not obtained")
    return values


def run_profile(control, artifacts, runtime, result, nodes):
    ports = reserve_ports(control, result)
    for index, name in enumerate(("a", "b")):
        build_config(artifacts.templates[name], name, runtime, artifacts, ports[index], nodes, artifacts.cadet_backend)
    envs = {name: child_environment(node, artifacts) for name, node in nodes.items()}
    result["nodes"] = {name: {"config": str(node["config"]), "config_sha256": file_hash(node["config"])[0],
                                     "runtime": str(node["root"]), "tcp_loopback_port": node["port"]}
                       for name, node in nodes.items()}
    cservice = {}
    for name, node in nodes.items():
        for service in SERVICES:
            deadline = Deadline(15, control.deadline)
            service_env = envs[name]
            if service in ("setu", "revocation"):
                service_env = dict(envs[name])
                library_key = "DYLD_LIBRARY_PATH" if sys.platform == "darwin" else "LD_LIBRARY_PATH"
                service_env[library_key] = ":".join((
                    str(artifacts.root / "c-prefix/gns-backend/lib"),
                    str(artifacts.root / "deps/gns-backend/lib"),
                    service_env[library_key]))
            ident = "rust.service.cadet" if service == "cadet" and artifacts.cadet_backend == "rust" else "c.service." + service
            child = control.start(name + "-" + service,
                                  [artifacts.binary(ident), "-c", str(node["config"]), "-L",
                                   "DEBUG" if service in ("nat", "transport", "gns") else "INFO"],
                                  service_env, role="service", deadline=deadline)
            cservice[name, service] = child
            control.wait(lambda: True if unix_probe(node["sections"][service.upper()]["UNIXPATH"]) else None,
                         deadline, "bound private service socket")
        cservice[name, "tcp"] = control.start(name + "-tcp", [artifacts.binary("c.communicator.tcp"), "-c", str(node["config"]), "-L", "DEBUG"], envs[name], role="service")
    def command(name, ident, node, args, stdin=None, seconds=20):
        return control.command(name, [artifacts.binary(ident), "-c", str(nodes[node]["config"]), "-L", "INFO"] + list(args), envs[node], seconds, stdin)
    # Address publication can legitimately replace the initial empty-address
    # PILS identity. Freeze each startup peer only after a complete nonempty
    # HELLO and one fresh, independent normal PILS observation agree.
    pids = {}
    result["active_public_peers"] = {}
    exports = {}
    for name in nodes:
        for attempt in range(16):
            data = command(f"{name}-hello-export-{attempt}", "c.cli.hello", name, ["-e", "-b", "-E", "5 min"])
            candidate = checked_hello(data, nodes[name]["port"])
            if candidate is not None:
                hello_peer, hello = candidate
                observed_peer = current_pid(command(name + "-pils-for-hello", "c.cli.pils", name, ["-1"]))
                if observed_peer != hello_peer:
                    raise ObservationError("normal HELLO URL peer differs from fresh actual PILS output")
                if observed_peer in pids.values():
                    raise ObservationError("the two actual original PILS peers are not independent")
                pids[name] = observed_peer
                result["active_public_peers"] = dict(pids)
                exports[name] = hello
                break
            # A completed empty export permits a fresh independent readiness
            # observation; an unknown/failed command is never replayed.
            control.pump(min(0.5, control.deadline.remaining()))
        if name not in exports:
            raise ObservationError("normal signed HELLO never advertised its approved loopback TCP address")
    command("b-import-a", "c.cli.hello", "b", ["-i"], exports["a"])
    command("a-import-b", "c.cli.hello", "a", ["-i"], exports["b"])
    command("a-links", "c.cli.transport", "a", ["-p", pids["b"], "-V"])
    for name, ego in (("a", "caller-a"), ("a", "addressbook-a"), ("b", "callee-b")):
        command("create-" + ego, "c.cli.identity", name, ["-C", ego])
    public = {ego: public_key(command("public-" + ego, "c.cli.identity", name, ["-d", "-e", ego]), ego)
              for name, ego in (("a", "caller-a"), ("a", "addressbook-a"), ("b", "callee-b"))}
    result["public_egos"] = public
    aconv = control.start("a-c-conversation-service", [artifacts.binary("c.service.conversation"), "-c", str(nodes["a"]["config"]), "-L", "INFO"], envs["a"], role="service")
    bconv = control.start("b-rust-conversation-service", [artifacts.binary("rust.service.conversation"), "-c", str(nodes["b"]["config"]), "-L", "DEBUG"], envs["b"], role="service")
    for name in nodes:
        control.wait(lambda name=name: True if unix_probe(nodes[name]["sections"]["CONVERSATION"]["UNIXPATH"]) else None,
                     Deadline(15, control.deadline), "normal Conversation listener")
    control.observed(bconv, rb"READY gnunet-service-conversation[^\n]*", Deadline(15, control.deadline))
    def frontend(name, implementation, node, ego, pipe=False):
        deadline = Deadline(20, control.deadline)
        args = [artifacts.binary(implementation + ".cli.conversation"), "-c", str(nodes[node]["config"]), "-L", "INFO", "-e", ego, "-p", "1"]
        if implementation == "rust":
            args += ["--timeout", str(max(1, int(control.deadline.remaining()))) + " s"]
        child = control.start(name, args, envs[node], role="frontend", interactive=True, pty_mode=not pipe, deadline=deadline)
        ready = rb"Whole Register731 written locally" if implementation == "rust" else rb"Phone active at `[^\n]+'"
        control.observed(child, ready, deadline)
        return child
    baseline = frontend("b-rust-register-baseline", "rust", "b", "callee-b", pipe=True)
    cursor = len(baseline.output["stdout"])
    control.send(baseline, "/address\n", Deadline(5, control.deadline))
    observed = control.observed(baseline, rb"PHONE (" + BASE32.encode() + rb"{103}-" + BASE32.encode() + rb"{52})\r?\n", Deadline(10, control.deadline), cursor)
    phone = observed["groups"][0]
    if phone.rsplit("-", 1)[1] != pids["b"]:
        raise ObservationError("actual Rust PHONE does not name the current callee PILS peer")
    result["selected_phone"] = {"normal_text": phone, "observation": observed,
                                "version_reserved_contract": "normal Rust v1/reserved0 constructor; no private binary decoder"}
    control.stop_frontend(baseline, "eof")
    result["cases"].append({"id": "register-rust-and-pipe-eof", "status": "passed", "observation": observed})
    command("store-phone", "c.cli.namestore", "a", ["-a", "-z", "addressbook-a", "-n", "callee", "-t", "PHONE", "-V", phone, "-e", "5 min", "-p"])
    full_name = "callee." + public["addressbook-a"]
    def probe_phone(label):
        data = command(label, "rust.cli.gns", "a", ["-u", full_name, "-t", "PHONE", "-T", "20 s", "-r"], seconds=25)
        if data.splitlines() != [phone.encode("ascii")]:
            raise ObservationError("actual normal GNS result is not the selected active-PID PHONE")
    probe_phone("normal-phone-lookup")
    pairs = []
    for index, (caller_impl, callee_impl) in enumerate((("c", "rust"), ("rust", "c"))):
        for name in nodes:
            actual = current_pid(command(f"{name}-pils-pair-{index}", "c.cli.pils", name, ["-1"]))
            if actual != pids[name]:
                raise ObservationError("actual PILS peer changed; old original calls are not retargeted")
        caller = frontend(f"pair-{index}-caller-{caller_impl}", caller_impl, "a", "caller-a")
        identity_start = len(bconv.output["stderr"])
        callee = frontend(f"pair-{index}-callee-{callee_impl}", callee_impl, "b", "callee-b")
        identity = control.observed(bconv, rb"CONVERSATION event: Identity \{ client: ([0-9]+), peer: \[[0-9, ]+\], epoch: ([0-9]+) \}", Deadline(10, control.deadline), identity_start, "stderr")
        start = len(callee.output["stdout"])
        service_start = len(bconv.output["stderr"])
        control.send(caller, "/call " + full_name + "\n", Deadline(5, control.deadline))
        if callee_impl == "rust":
            ring = control.observed(callee, rb"Actual incoming Ring735 #([0-9]+)", Deadline(30, control.deadline), start)
            status_start = len(callee.output["stdout"])
            control.send(callee, "/status\n", Deadline(5, control.deadline))
            control.observed(callee, rb"(?m)^#" + ring["groups"][0].encode() + rb" incoming [^\n]* caller=" + public["caller-a"].encode() + rb"$", Deadline(5, control.deadline), status_start)
        else:
            ring = control.observed(callee, rb"Incoming call from `(" + BASE32.encode() + rb"{58})'\. Please /accept ([0-9]+) or /cancel [0-9]+ the call\.", Deadline(30, control.deadline), start)
            if ring["groups"][0] != public["caller-a"]:
                raise ObservationError("normal C consumer received a different actual caller ego")
        cancel_index = len(caller.row["stdin_events"])
        control.send(caller, "/cancel\n", Deadline(5, control.deadline))
        cancel_input = dict(caller.row["stdin_events"][cancel_index])
        if not cancel_input["whole"] or cancel_input["written"] != cancel_input["bytes"]:
            raise ObservationError("original caller cancel input was not wholly written")
        if callee_impl == "rust":
            hangup = control.observed(callee, rb"Actual service HangUp733 \(peer delivery is not inferred\) #" + ring["groups"][0].encode() + rb"(?![0-9])", Deadline(20, control.deadline), start)
        else:
            hangup = control.observed(callee, rb"Call from `" + public["caller-a"].encode() + rb"' terminated", Deadline(20, control.deadline), start)
        client = identity["groups"][0].encode("ascii")
        retirement_target = Deadline(20, control.deadline)
        # Both unanswered outgoing frontends close the original Call MQ.
        # C calls call_stop; Rust has not observed an outgoing CID and uses
        # Line.close rather than inventing CID0/CLIENT733. The C service then
        # destroys that actual channel. Neither path proves PEER741 receipt.
        channel_end = control.observed(
            bconv, rb"CONVERSATION event: ChannelDestroyed \{ client: " + client
            + rb", call: ([0-9]+), cid: ([0-9]+), channel: ([0-9]+), epoch: ([0-9]+), mq_current: true \}",
            retirement_target, service_start, "stderr")
        call, cid = (value.encode("ascii") for value in channel_end["groups"][:2])
        peer_end = control.observed(
            bconv, rb"CONVERSATION event: CallClosed \{ client: " + client
            + rb", report: CallSummary \{ call: " + call + rb", cid: " + cid
            + rb", peer: \[[0-9, ]+\], reason: Failed\(Closed\), failure: Some\(Closed\), ring_written: false, remote_pickup: false, local_pickup_written: false, remote_hangup: false, local_hangup_written: false \} \}",
            retirement_target, service_start, "stderr")
        original_call = {"client": identity["groups"][0], "call": channel_end["groups"][0],
                         "cid": channel_end["groups"][1], "channel": channel_end["groups"][2],
                         "cadet_epoch": channel_end["groups"][3]}
        termination = ("normal-c-outgoing-call-stop-channel-destroy" if caller_impl == "c"
                       else "normal-rust-outgoing-prepickup-close-channel-destroy")
        checkpoint = line_source_checkpoint(bconv, identity, identity_start)
        if source_failure(caller) or source_failure(callee):
            raise ObservationError("source/answered-call diagnostics cannot be promoted to an unanswered hangup pass")
        result["cases"].append({"id": "c-to-rust-unanswered-" + str(index), "status": "passed", "frontends": [caller_impl, callee_impl], "ring": ring, "consumer_hangup": hangup, "actual_source_identity": identity,
                                "termination_kind": termination, "original_call": original_call,
                                "original_cancel_input": {"frontend_owner": caller.row["id"], "stdin_event_index": cancel_index, "command": "/cancel", "local_write": cancel_input, "remote_ack": False},
                                "actual_channel_destroy": channel_end, "actual_call_retirement": peer_end,
                                "actual_peer_hangup": None,
                                "peer741_hangup_credit": False, "source_checkpoint": checkpoint, "device": False})
        pairs.append((caller, callee))
        control.stop_frontend(caller, "sigint" if caller_impl == "c" else "quit", expected=(0, -signal.SIGINT))
        control.stop_frontend(callee, "quit")
    # Controlled source EOF is a diagnostic expected failure, not healthy peer
    # hangup/pickup. Use a fresh registered Rust frontend after old owners reap.
    observer = frontend("b-rust-original-source-eof", "rust", "b", "callee-b", pipe=True)
    observer.allow_exit = True
    bconv.allow_exit = True
    eof_target = Deadline(15, control.deadline)
    eof_target.check()
    control.signal(bconv, signal.SIGTERM)
    control.wait(lambda: observer.process.poll() if observer.process.poll() is not None else None, eof_target, "original source EOF exit")
    while observer.open_readers:
        eof_target.check()
        control.pump(min(0.05, eof_target.remaining()))
    code = observer.process.wait(timeout=0)
    diagnostic = bytes(observer.output["stderr"])
    source_event = b"original Conversation source lost; old exposed controls are not replayed"
    # This fresh observer has only its original Register Line. Match that first
    # SDK Loss's cause before its initializer, not an arbitrary Eof elsewhere
    # in retained history, a native target deadline, or a local Cancelled loss.
    loss = re.search(rb"sdk_first: Some\(Loss \{ ([^\r\n]*?)initializer: Receipt \{", diagnostic)
    retained_eof = loss is not None and loss.group(1).endswith(b"cause: Eof, ")
    if code == 0 or source_event not in diagnostic or not retained_eof:
        raise ObservationError("original source EOF lacks its actual nonzero source-event diagnostic and original SDK Eof cause")
    result["cases"].append({"id": "source-eof", "status": "observed-expected-failure", "frontend_exit": code, "owner": observer.row["id"], "source_owner": bconv.row["id"], "retained_sdk_cause": "Eof", "healthy_call_credit": False})
    underlay_exclusion = ("Rust TCP/CORE/CADET underlay" if artifacts.cadet_backend == "c" else
                          "Rust TCP/CORE underlay and CADET encrypted interoperability with an unmodified C peer")
    result["excluded"] = ["device/pickup/suspend/resume", "Rust caller service -> C callee", "C gnunet-gns ARM-gated CLI", "C stdin EOF shutdown", underlay_exclusion, "whole Conversation/GNUnet completion"]
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--phase", choices=("no-device",), required=True)
    parser.add_argument("--cadet-backend", choices=("c", "rust"), default="c")
    args = parser.parse_args(argv)
    profile = selected_profile(args.cadet_backend)
    output = absolute(args.output)
    if not within(output, Path("/private/tmp")) or output.exists():
        raise Blocked("evidence output must be a fresh explicitly owned /private/tmp directory")
    output.mkdir(mode=0o700)
    result = {"profile": profile, "cadet_backend": args.cadet_backend,
              "status": "blocked", "executed": False, "runtime_verified": False,
              "whole_goal_complete": False, "cases": [], "cleanup_errors": [], "participants": [],
              "private_runtime_removed": False, "normal_participants_only": True, "device": False}
    control, runtime, artifacts, nodes = None, None, None, {}
    previous = {}
    primary = None
    try:
        result["approval"] = approval(absolute(args.manifest), absolute(args.approval), Path(__file__).resolve(), args.cadet_backend)
        artifacts = Inputs(load_json(args.manifest), args.cadet_backend)
        artifacts.snapshot(output / "participants")
        result["snapshots"] = artifacts.snapshot_rows
        result["producer_bindings"] = artifacts.bindings
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise Blocked("controller requires exclusive ordinary consuming wait ownership")
        def interrupted(signum, _frame):
            if control is not None and not control.active:
                # The original cleanup phase retains this bounded intent and
                # continues all exact-handle retirement, rather than raising
                # from arbitrary poll/wait/FD bookkeeping bytecode.
                control.cleanup_signal(signum)
                return
            raise InterruptedError("original Conversation controller interrupted by signal " + str(signum))
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, interrupted)
        evidence = output / "processes"
        evidence.mkdir(mode=0o700)
        m = artifacts.manifest
        control = Controller(evidence, m.get("phase_seconds", 120), m.get("stream_bytes", 4 << 20), m.get("total_output_bytes", 128 << 20), m.get("maximum_children", 128))
        directory = Owner(0, "private-runtime-root", "metadata", [])
        result["runtime_acquisition"] = directory.row
        def allocate():
            nonlocal runtime
            runtime = Path(tempfile.mkdtemp(prefix="gcv-"))
            runtime.chmod(0o700)
        control.acquire(directory, allocate)
        result["private_runtime"] = str(runtime)
        run_profile(control, artifacts, runtime, result, nodes)
        result["status"] = "passed-selected-no-device-profile"
    except BaseException as error:
        primary = error
        result["primary"] = described(error)
        spawned = control is not None and any(o.row["spawned"] for o in control.children)
        result["status"] = "blocked" if isinstance(error, Blocked) and not spawned else "failed"
    finally:
        if control is not None:
            # Arm the real main handler before calling cleanup, including its
            # first bytecode and deadline acquisition. No handler is swapped or
            # mask inherited while retiring the owned participants.
            control.active = False
            try:
                control.cleanup(10)
            except BaseException as error:
                control.cleanup_error(None, "controller-cleanup", error)
            result["participants"] = control.reports()
            result["executed"] = any(o.row["spawned"] for o in control.children)
            result["cleanup_errors"] = control.cleanup_errors
            result["cleanup_overflow"] = control.cleanup_overflow
        if artifacts is not None:
            result["participant_or_binding_changes"] = artifacts.unchanged()
        # The original config can be checked without ever reading key/DB data.
        result["configs_unchanged"] = True
        for name, node in nodes.items():
            row = result.get("nodes", {}).get(name)
            if row is None:
                continue  # partial unpublished configuration; original error retained
            try:
                if file_hash(node["config"])[0] != row["config_sha256"]:
                    result["configs_unchanged"] = False
            except BaseException as error:
                result["configs_unchanged"] = False
                result["cleanup_errors"].append({"stage": "config-final-hash", "error": described(error)})
        reaped = control is None or all(o.process is None or o.row["reaped"] for o in control.children)
        result["all_owned_children_reaped"] = reaped
        clean = reaped and not result["cleanup_errors"] and not result.get("cleanup_overflow") and not result.get("participant_or_binding_changes") and result.get("configs_unchanged", True)
        # No process name/PID/port scan or foreign listener kill is permitted.
        # A still-live known private listener means preserve runtime evidence.
        active_sockets = []
        if runtime is not None and nodes and reaped:
            for node in nodes.values():
                for section in SERVICES + ("conversation",):
                    path = node["sections"].get(section.upper(), {}).get("UNIXPATH")
                    if path is None:
                        continue
                    try:
                        if Path(path).exists() and unix_probe(path):
                            active_sockets.append(path)
                    except BaseException as error:
                        result["cleanup_errors"].append({"stage": "private-socket-final", "error": described(error)})
        result["remaining_private_listeners"] = active_sockets
        if active_sockets or result["cleanup_errors"]:
            clean = False
        if runtime is not None and clean:
            try:
                for node in (nodes or {}).values():
                    if node["denied"].exists():
                        node["denied"].chmod(0o700)
                shutil.rmtree(runtime)
                result["private_runtime_removed"] = not runtime.exists()
            except BaseException as error:
                result["cleanup_errors"].append({"stage": "owned-runtime-remove", "error": described(error)})
                clean = False
        if not clean or result["cleanup_errors"]:
            result["status"] = "failed"
        if result["status"] == "passed-selected-no-device-profile":
            result["runtime_verified"] = True
            result["verification_scope"] = profile
        for signum, handler in previous.items():
            try:
                signal.signal(signum, handler)
            except BaseException as error:
                result["cleanup_errors"].append({"stage": "restore-controller-handler", "error": described(error)})
                result["status"] = "failed"
                result["runtime_verified"] = False
        # A handled signal can arrive while post-cleanup hashes or handler
        # restoration run. The aliased original error list retains its row;
        # never leave the earlier positive status after such an interruption.
        if result["cleanup_errors"]:
            result["status"] = "failed"
            result["runtime_verified"] = False
        try:
            write_json(output / "result.json", result)
        except BaseException as error:
            # Preserve original cause and independent report failure. A result
            # that could not be saved is never emitted as a successful run.
            sys.stderr.write(json.dumps({"report_failure": described(error), "original": described(primary) if primary else None}) + "\n")
            return 2
    return 0 if result["status"] == "passed-selected-no-device-profile" else 3 if result["status"] == "blocked" else 1


if __name__ == "__main__":
    raise SystemExit(main())
