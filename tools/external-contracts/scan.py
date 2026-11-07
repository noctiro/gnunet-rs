#!/usr/bin/env python3
"""Versioned protocol discovery; source tokens do not prove an active protocol."""
import hashlib
import re
from pathlib import Path

PREFIX = "GNUNET_MESSAGE_TYPE_"
REVISION = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165"
SUBSYSTEMS = tuple("util statistics testbed arm peerstore nat nat-auto pils transport core nse hostlist topology dns identity namecache namestore datacache datastore dht cadet seti setu regex revocation vpn gns zonemaster fs exit pt reclaim messenger rest".split())
FOUNDATIONS = tuple("wire crypto hello block gnsrecord service-runtime storage-contracts reference-harness".split())


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def lexical_code(text):
    """Mask comments and quoted literals, preserving original line positions."""
    result = list(text)
    index = 0
    while index < len(text):
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = len(text) if end < 0 else end + 2
        elif text.startswith("//", index):
            end = text.find("\n", index + 2)
            end = len(text) if end < 0 else end
        elif text[index] in ("\"", "'"):
            quote = text[index]
            end = index + 1
            while end < len(text):
                if text[end] == "\\":
                    end += 2
                    continue
                if text[end] == quote:
                    end += 1
                    break
                end += 1
        else:
            index += 1
            continue
        for position in range(index, min(end, len(text))):
            if result[position] != "\n":
                result[position] = " "
        index = end
    return "".join(result)


def splice_lines(text):
    """C phase-2 splicing with a map back to original physical source lines."""
    output, lines = [], []
    index, line = 0, 1
    while index < len(text):
        if text.startswith("\\\n", index):
            index += 2
            line += 1
        elif text.startswith("\\\r\n", index):
            index += 3
            line += 1
        else:
            output.append(text[index])
            lines.append(line)
            if text[index] == "\n":
                line += 1
            index += 1
    return "".join(output), lines


def registry(text):
    # C line splicing precedes comment recognition. Numeric aliases are separate
    # assignments; neither their name nor their numeric identity is discarded.
    code = lexical_code(splice_lines(text)[0])
    rows = {}
    for name, value in re.findall(r"^\s*#define\s+(GNUNET_MESSAGE_TYPE_\w+)\s+([^\n]+)", code, re.M):
        value = value.strip()
        if name in rows or not value.isdecimal() or not 0 <= int(value) <= 65535:
            raise ValueError("unreviewed registry expression or duplicate: " + name)
        rows[name] = int(value)
    if not rows:
        raise ValueError("empty protocol registry")
    return rows


def relative_file(source, path):
    source = Path(source).resolve()
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("nonregular discovery input: " + str(path))
    relative = path.resolve().relative_to(source).as_posix()
    if path != source / relative:
        raise ValueError("aliased discovery input: " + str(path))
    return relative


def source_area(relative):
    """Location hint only; it grants no external operation ownership."""
    parts = Path(relative).parts
    if len(parts) > 3 and parts[2] in SUBSYSTEMS + FOUNDATIONS:
        return parts[2]
    return None


def discover(source, extra_inputs=()):
    source = Path(source).resolve()
    header = source / "src/include/gnunet_protocols.h"
    assignments = registry(header.read_text(encoding="utf-8"))
    paths = sorted(path for path in (source / "src").rglob("*.c")
                   if not path.name.startswith(("test_", "perf_")))
    if not paths:
        raise ValueError("empty C discovery scope")
    references = {}
    for path in paths:
        relative = relative_file(source, path)
        spliced, lines = splice_lines(path.read_text(encoding="utf-8"))
        code = lexical_code(spliced)
        for match in re.finditer(r"\bGNUNET_MESSAGE_TYPE_[A-Z0-9_]+\b", code):
            references.setdefault(match[0], []).append({
                "path": relative,
                "line": lines[match.start()],
                "source_area_hint": source_area(relative),
            })
    inputs = set(paths) | {header}
    inputs.update((source / "src").rglob("meson.build"))
    inputs.add(source / "meson.build")
    aliases = {}
    for name in ("meson.options", "meson_options.txt"):
        path = source / name
        if path.is_symlink():
            target = path.readlink()
            if target.is_absolute() or ".." in target.parts:
                raise ValueError("unsafe official Meson option alias: " + name)
            resolved = path.resolve()
            relative_file(source, resolved)
            aliases[name] = target.as_posix()
            inputs.add(resolved)
        elif path.exists():
            inputs.add(path)
    for relative in extra_inputs:
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("unsafe extra input: " + relative)
        inputs.add(source / path)
    bound = {relative_file(source, path): digest(path) for path in sorted(inputs)}
    return {
        "schema": 1,
        "kind": "official-message-discovery-candidates",
        "reference_revision": REVISION,
        "scan_policy": {
            "C_scope": "src/**/*.c excluding file names starting test_ or perf_",
            "preprocessor_conditions_evaluated": False,
            "build_activation_inferred": False,
            "operation_or_semantic_completeness_inferred": False,
            "unframed_or_nonregistry_protocols_complete": False,
        },
        "input_files": bound,
        "source_aliases": aliases,
        "C_files": [path.relative_to(source).as_posix() for path in paths],
        "registry": [{"id": name.removeprefix(PREFIX), "number": number,
                      "source_references": references.get(name, [])}
                     for name, number in sorted(assignments.items())],
        "unregistered_source_tokens": {name: facts for name, facts in sorted(references.items())
                                       if name not in assignments},
    }
