"""Shared local-only path and source checks for startup proof tools."""
import hashlib
import json
import pathlib
import re
import os


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def overlaps(first, second):
    first, second = pathlib.Path(first).resolve(), pathlib.Path(second).resolve()
    return first == second or first in second.parents or second in first.parents


def workspace_root(package):
    """Use the outermost ancestor Cargo workspace, without touching Git state."""
    package = pathlib.Path(package).resolve()
    roots = []
    for parent in (package, *package.parents):
        manifest = parent / 'Cargo.toml'
        if manifest.is_file() and any(line.strip() == '[workspace]'
                                      for line in manifest.read_text().splitlines()):
            roots.append(parent)
    return roots[-1] if roots else package


def require_disjoint_output(output, protected):
    output = pathlib.Path(output).resolve()
    for path in protected:
        if overlaps(output, path):
            raise ValueError('output overlaps protected input tree: ' + str(path))
    if output.exists():
        raise FileExistsError('output must be a fresh directory: ' + str(output))
    return output


def require_lint_contract(package, repo, metadata):
    """A warnings-only prototype cannot stand in for this workspace's lint policy."""
    package, repo = pathlib.Path(package).resolve(), pathlib.Path(repo).resolve()
    actual = (package / 'Cargo.toml').read_text()
    root = (repo / 'Cargo.toml').read_text()
    start, end = root.index('[workspace.lints.rust]'), root.index('[workspace.dependencies]')
    expected = root[start:end].replace('[workspace.lints.', '[lints.').strip()
    inherited = re.search(r'(?ms)^\[lints\]\s*\n\s*workspace\s*=\s*true\s*(?:\n|$)', actual)
    if inherited:
        if pathlib.Path(metadata['workspace_root']).resolve() != repo:
            raise ValueError('lint inheritance uses a different workspace')
    elif '[lints.rust]' not in actual or actual[actual.index('[lints.rust]'):].strip() != expected:
        raise ValueError('actual package does not retain the complete root lint policy')
    return {'root_policy_sha256': hashlib.sha256(expected.encode()).hexdigest(),
            'inherited_from_reviewed_workspace': bool(inherited)}


def unchanged(inputs):
    return all(pathlib.Path(path).is_file() and sha(path) == value
               for path, value in inputs.items())


def validated_build(path):
    receipt = json.loads(pathlib.Path(path).read_text())
    if receipt.get('exit_code') != 0 or not receipt.get('inputs_unchanged'):
        raise ValueError('build receipt is unsuccessful or not source-bound')
    if not receipt.get('inputs') or not unchanged(receipt['inputs']):
        raise ValueError('build inputs no longer match')
    binary = receipt.get('binary')
    if not binary or sha(binary['path']) != binary['sha256']:
        raise ValueError('build binary no longer matches')
    return receipt



def source_files(root, excluded=()):
    """Discover ordinary input files, rejecting directory links as well as files.

    Exclusions are relative top-level output entries, not arbitrary matching
    descendant names. Thus src/target/data remains an ordinary source input.
    """
    root = pathlib.Path(root)
    if root.is_symlink():
        raise ValueError('symbolic input rejected: ' + str(root))
    if not root.exists():
        return []
    if not root.is_dir():
        raise ValueError('source input root is not a directory')
    result = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        base = pathlib.Path(directory)
        for name in list(dirs):
            path = base / name
            if path.relative_to(root).as_posix() in excluded or name == '__pycache__':
                dirs.remove(name)
                continue
            if path.is_symlink():
                raise ValueError('symbolic input rejected: ' + str(path))
        for name in files:
            path = base / name
            if path.relative_to(root).as_posix() in excluded:
                continue
            if path.is_symlink():
                raise ValueError('symbolic input rejected: ' + str(path))
            if not path.is_file():
                raise ValueError('non-regular source input rejected: ' + str(path))
            result.append(path)
    return sorted(result)

def local_snapshot(metadata, package, tools):
    """All reachable local dependency src bytes, plus package tests/tools/docs.

    Registry packages are pinned by the actual workspace Cargo.lock. Include
    non-Rust src files used by include_str!/include_bytes!, not a '*.rs' subset.
    No credentials or unrelated home-directory settings are read.
    """
    package = pathlib.Path(package).resolve()
    selected = next(row for row in metadata['packages']
                    if pathlib.Path(row['manifest_path']).resolve()
                    == package / 'Cargo.toml')
    nodes = {row['id']: row for row in metadata['resolve']['nodes']}
    wanted, todo = set(), [selected['id']]
    while todo:
        current = todo.pop()
        if current in wanted:
            continue
        wanted.add(current)
        todo.extend(nodes[current]['dependencies'])
    paths = set()
    for row in metadata['packages']:
        if row['id'] not in wanted or row['source'] is not None:
            continue
        manifest = pathlib.Path(row['manifest_path']).resolve()
        paths.add(manifest)
        src = manifest.parent / 'src'
        if src.is_dir():
            paths.update(source_files(src))
        for ancestor in (manifest.parent, *manifest.parent.parents):
            outer = ancestor / 'Cargo.toml'
            if outer.is_file() and '[workspace]' in outer.read_text():
                for name in ('Cargo.toml','Cargo.lock','rust-toolchain.toml','rust-toolchain','rustfmt.toml','.rustfmt.toml','.cargo/config','.cargo/config.toml'):
                    if (ancestor/name).is_file(): paths.add(ancestor/name)
                break
        if (manifest.parent / 'build.rs').is_file():
            paths.add(manifest.parent / 'build.rs')
    # Include complete package source/test/docs/tool inputs, excluding generated
    # target/Git data. Output directories were independently proved disjoint.
    paths.update(source_files(package, {'target', '.git'}))
    tool_dir = pathlib.Path(tools).resolve()
    paths.update(source_files(tool_dir))
    root = pathlib.Path(metadata['workspace_root']).resolve()
    for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'rust-toolchain',
                 'rustfmt.toml', '.rustfmt.toml', '.cargo/config', '.cargo/config.toml'):
        path = root / name
        if path.is_file():
            paths.add(path)
    # A member can have narrower Cargo settings between it and the root.
    for parent in (package, *package.parents):
        if root != parent and root not in parent.parents:
            continue
        for name in ('.cargo/config', '.cargo/config.toml', 'rust-toolchain.toml',
                     'rust-toolchain', 'rustfmt.toml', '.rustfmt.toml'):
            if (parent / name).is_file():
                paths.add(parent / name)
    for path in paths:
        if path.is_symlink():
            raise ValueError('symbolic input rejected: ' + str(path))
    return selected, {str(path): sha(path) for path in sorted(paths)}

