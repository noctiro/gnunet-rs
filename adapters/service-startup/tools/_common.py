"""Shared local-only path and source checks for startup proof tools."""
import hashlib
import json
import pathlib


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
            paths.update(path for path in src.rglob('*') if path.is_file())
        if (manifest.parent / 'build.rs').is_file():
            paths.add(manifest.parent / 'build.rs')
    # Include complete package source/test/docs/tool inputs, excluding generated
    # target/Git data. Output directories were independently proved disjoint.
    for path in package.rglob('*'):
        if path.is_file() and not {'target', '.git', '__pycache__'}.intersection(
                path.relative_to(package).parts):
            paths.add(path)
    tool_dir = pathlib.Path(tools).resolve()
    paths.update(path for path in tool_dir.rglob('*') if path.is_file()
                 and '__pycache__' not in path.parts)
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
    return selected, {str(path): sha(path) for path in sorted(paths)}


PINNED_REVISION = '346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
PINNED_TAG = 'v0.29.1'


def source_state(source):
    """Match tools/reference/build_reference.py's tracked-source commitment.

    The entire tracked byte tree, paths, symlink bytes and gitlink IDs participate;
    this is not merely a clean status or a few selected source-file hashes.
    """
    import os
    import subprocess
    source = pathlib.Path(source).resolve()
    def git(*args):
        return subprocess.check_output(['git', '-C', str(source), *args])
    revision = git('rev-parse', 'HEAD').decode().strip()
    tag = git('rev-parse', PINNED_TAG + '^{}').decode().strip()
    if revision != PINNED_REVISION or tag != PINNED_REVISION:
        raise ValueError('reference HEAD/tag is not the pinned official release')
    subprocess.run(['git', '-C', str(source), 'diff', '--quiet',
                    '--ignore-submodules=none', 'HEAD', '--'], check=True)
    entries = git('ls-files', '--stage', '-z').decode().split('\0')
    paths = {}
    for entry in entries:
        if entry:
            metadata, name = entry.split('\t', 1)
            paths[name] = metadata.split()
    digest = hashlib.sha256()
    gitlinks = []
    for name in sorted(paths):
        path = source / name
        if paths[name][0] == '160000':
            data = ('gitlink:' + paths[name][1]).encode()
            gitlinks.append({'path': name, 'commit': paths[name][1]})
        elif path.is_symlink():
            data = os.readlink(path).encode()
        elif path.is_file():
            data = path.read_bytes()
        else:
            raise ValueError('tracked reference input is missing: ' + name)
        encoded = name.encode()
        digest.update(len(encoded).to_bytes(8, 'big') + encoded
                      + len(data).to_bytes(8, 'big') + data)
    return {'revision': revision, 'tag': PINNED_TAG, 'tracked_files': len(paths),
            'tracked_input_sha256': digest.hexdigest(), 'gitlinks': gitlinks,
            'tracked_sources_clean': True}


def _validate_normal_reference_data(receipt, source, current_state):
    """Pure receipt/file boundary; public validation supplies actual Git state."""
    source = pathlib.Path(source).resolve()
    if (receipt.get('status') != 'passed'
            or receipt.get('kind') != 'unmodified-official-c-reference-build'
            or receipt.get('source_unchanged') is not True
            or pathlib.Path(receipt.get('source', '')).resolve() != source):
        raise ValueError('unsuccessful/mismatched normal reference receipt')
    expected = receipt.get('upstream', {})
    if (expected.get('revision') != PINNED_REVISION
            or expected.get('tag') != PINNED_TAG
            or expected.get('tracked_sources_clean') is not True
            or not expected.get('tracked_files')
            or expected != current_state):
        raise ValueError('normal reference tracked source commitment mismatches')
    build, prefix = pathlib.Path(receipt['build']), pathlib.Path(receipt['prefix'])
    generated = receipt.get('generated_config', {})
    if (not generated.get('path') or not generated.get('sha256')
            or pathlib.Path(generated['path']).resolve()
               != (build / 'gnunet_private_config.h').resolve()
            or sha(generated['path']) != generated['sha256']):
        raise ValueError('declared normal generated compile config mismatches')
    library = prefix / 'lib/libgnunetutil.23.dylib'
    matches = [row for row in receipt.get('libraries', [])
               if pathlib.Path(row.get('path', '')).absolute() == library.absolute()]
    if len(matches) != 1 or not matches[0].get('sha256'):
        raise ValueError('normal util library is not uniquely declared')
    if sha(library) != matches[0]['sha256']:
        raise ValueError('declared normal util library mismatches')
    environment = {'GNUNET_PREFIX': str(prefix),
                   'LD_LIBRARY_PATH': str(prefix / 'lib'),
                   'DYLD_LIBRARY_PATH': str(prefix / 'lib')}
    if receipt.get('runtime_environment') != environment:
        raise ValueError('normal reference runtime library prefix mismatches')
    return {'source_state': current_state,
            'declared_inputs': {str(library): matches[0]['sha256'],
                                generated['path']: generated['sha256']},
            'library': str(library),
            'compile_commands_and_public_config':
                'fresh inputs only; not declared by the historical build receipt'}


def normal_reference(path, source):
    """Validate old receipt claims against actual source/native library inputs."""
    receipt = json.loads(pathlib.Path(path).read_text())
    return _validate_normal_reference_data(receipt, source, source_state(source))


def require_rust_fixture_success(row):
    """Rust fixtures must finish normally even when testing a refused input.

    A valid JSON observation written before a later panic/Drop abort is not a
    successful ownership test. Normal C refusal cases have different exit rules.
    """
    if (row.get('kind') != 'rust' or row.get('exit_code') != 0
            or not isinstance(row.get('observation'), dict)
            or not row['observation']):
        raise ValueError('Rust fixture did not complete with valid JSON and exit0')
    return row
