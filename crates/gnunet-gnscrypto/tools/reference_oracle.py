#!/usr/bin/env python3
"""Compile test drivers against normal, unmodified GNUnet v0.29.1 libraries.

This is test-only tooling. Production Rust never loads or links GNUnet C.
The caller supplies a configured Meson build and matching staged runtime prefix.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shlex
import subprocess

PIN = '346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
CASES = ('pkey_ascii', 'edkey_ascii', 'pkey_nfc', 'edkey_nfc')

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'build', 'prefix', 'output'):
        p.add_argument('--' + name, required=True, type=pathlib.Path)
    p.add_argument('--cc', default='cc')
    p.add_argument('--cflags', default='')
    p.add_argument('--ldflags', default='')
    p.add_argument('--cargo', default='cargo')
    p.add_argument('--unicode-data', type=pathlib.Path)
    a = p.parse_args()
    for name in ('source', 'build', 'prefix', 'output'):
        setattr(a, name, getattr(a, name).resolve())
    # A fresh explicit output root owns every emitted file; never overwrite a
    # previous receipt or use a shared temporary directory implicitly.
    a.output.mkdir(parents=True, exist_ok=False)
    root = pathlib.Path(__file__).resolve().parent.parent
    workspace = root.parent.parent
    commands = []
    result = {'schema': 1, 'status': 'failed', 'upstream_commit': PIN, 'commands': commands}
    env = os.environ.copy()
    env['GNUNET_PREFIX'] = str(a.prefix)
    env['LD_LIBRARY_PATH'] = str(a.prefix / 'lib') + os.pathsep + env.get('LD_LIBRARY_PATH', '')
    env['DYLD_LIBRARY_PATH'] = str(a.prefix / 'lib') + os.pathsep + env.get('DYLD_LIBRARY_PATH', '')
    rust_inputs = sorted(set([workspace / 'Cargo.toml', workspace / 'Cargo.lock'] +
        [v for package in ('gnunet-crypto', 'gnunet-gnscrypto')
         for v in (workspace / 'crates' / package).rglob('*')
         if v.is_file() and '__pycache__' not in v.parts]))
    result['rust_sha256'] = {str(v.relative_to(workspace)): digest(v) for v in rust_inputs}
    def run(argv, name, data=None, run_env=None):
        r = subprocess.run([str(v) for v in argv], input=data, capture_output=True,
                           cwd=workspace, env=run_env or env, timeout=180)
        (a.output / (name + '.stdout')).write_bytes(r.stdout)
        (a.output / (name + '.stderr')).write_bytes(r.stderr)
        commands.append({'argv': [str(v) for v in argv], 'exit_code': r.returncode,
                         'stdout_sha256': hashlib.sha256(r.stdout).hexdigest(),
                         'stderr_sha256': hashlib.sha256(r.stderr).hexdigest()})
        if r.returncode:
            raise RuntimeError(name + ' failed: ' + r.stderr.decode(errors='replace')[-3000:])
        return r.stdout
    try:
        head = run(['git', '-C', a.source, 'rev-parse', 'HEAD'], 'upstream-head').decode().strip()
        if head != PIN:
            raise RuntimeError('wrong upstream revision')
        if run(['git', '-C', a.source, 'status', '--porcelain', '--untracked-files=no'], 'upstream-clean').strip():
            raise RuntimeError('modified upstream source')
        if not (a.build / 'build.ninja').is_file():
            raise RuntimeError('normal configured Meson build required')
        result['compiler'] = run([a.cc, '--version'], 'compiler').decode(errors='replace')
        result['libraries'] = {}
        for name, directory in [('util', 'util'), ('gnsrecord', 'gnsrecord')]:
            candidates = sorted((a.build / 'src/lib' / directory).glob('libgnunet' + name + '.*'))
            candidates = [v for v in candidates if v.is_file() and (v.suffix in ('.so', '.dylib') or '.so.' in v.name)]
            if not candidates:
                raise RuntimeError('normal reference library missing: ' + name)
            actual = candidates[0].resolve()
            staged = (a.prefix / 'lib' / actual.name).resolve()
            if not staged.is_file() or digest(actual) != digest(staged):
                raise RuntimeError('staged library does not match normal build: ' + name)
            result['libraries'][name] = {'build_path': str(actual), 'staged_path': str(staged), 'sha256': digest(actual)}
        paths = ['src/lib/util/crypto_hkdf.c', 'src/lib/util/crypto_ecc_gnsrecord.c',
                 'src/lib/util/crypto_ecc.c', 'src/lib/util/crypto_symmetric.c',
                 'src/lib/gnsrecord/gnsrecord_crypto.c', 'src/lib/gnsrecord/gnsrecord_misc.c',
                 'src/include/gnunet_crypto_lib.h', 'src/include/gnunet_gnsrecord_lib.h']
        result['source_sha256'] = {v: digest(a.source / v) for v in paths}
        flags = [a.cc, '-DHAVE_CONFIG_H', '-D_GNU_SOURCE', '-I' + str(a.build),
                 '-I' + str(a.build / 'src/include'), '-I' + str(a.source / 'src/include'),
                 '-I' + str(a.source / 'src/lib/gnsrecord')] + shlex.split(a.cflags)
        links = ['-L' + str(a.prefix / 'lib'), '-Wl,-rpath,' + str(a.prefix / 'lib')]
        links += shlex.split(a.ldflags) + ['-lgnunetgnsrecord', '-lgnunetutil', '-lsodium']
        result['drivers_sha256'] = {}
        for name in ('gns_vectors', 'accept_block', 'nfc_oracle'):
            source = root / 'tests/reference' / (name + '.c')
            result['drivers_sha256'][name] = digest(source)
            extra = ['-lunistring'] if name == 'nfc_oracle' else []
            run(flags + [source] + links + extra + ['-o', a.output / name], 'compile-' + name)
        generated = run([a.output / 'gns_vectors'], 'c-vectors')
        if generated != (root / 'tests/fixtures/gns-v0291.txt').read_bytes():
            raise RuntimeError('normal C vectors differ from checked-in fixtures')
        blocks = a.output / 'rust-blocks'
        blocks.mkdir()
        rust_env = env.copy()
        rust_env['GNUNET_GNS_VECTOR_OUTPUT'] = str(blocks)
        run([a.cargo, 'test', '-p', 'gnunet-gnscrypto', '--test', 'conformance', '--locked', '--offline'], 'rust-vectors', run_env=rust_env)
        for case in CASES:
            run([a.output / 'accept_block', blocks / (case + '.zone'), blocks / (case + '.label'),
                 blocks / (case + '.block'), blocks / (case + '.records')], 'c-accept-' + case)
        result['c_to_rust_complete_blocks'] = len(CASES)
        result['rust_to_c_verified_and_opened_blocks'] = len(CASES)
        if a.unicode_data:
            source = a.unicode_data.resolve() / 'NormalizationTest.txt'
            raw = source.read_bytes()
            if hashlib.sha256(raw).hexdigest() != '25a50d816764b04abfb4a646d3eb2b2a803284c3873d9a06757b94fe4513dde3':
                raise RuntimeError('wrong Unicode 18 conformance source')
            inputs, expected = [], []
            for line in raw.decode().splitlines():
                line = line.split('#')[0].strip()
                if not line or line.startswith('@'):
                    continue
                columns = [''.join(chr(int(cp, 16)) for cp in v.split()).encode().hex() for v in line.split(';')[:5]]
                for i, j in ((0,1), (1,1), (2,1), (3,3), (4,3)):
                    inputs.append(columns[i]); expected.append(columns[j])
            actual = run([a.output / 'nfc_oracle'], 'c-nfc', ('\n'.join(inputs) + '\n').encode()).decode().splitlines()
            if actual != expected:
                raise RuntimeError('normal C Unicode18 conformance differs')
            result['unicode18_nfc_transformations'] = len(actual)
            result['unicode_runtime_profile'] = (a.output / 'c-nfc.stderr').read_text().strip()
            if 'Unicode=1200' not in result['unicode_runtime_profile']:
                raise RuntimeError('the selected normalization profile requires reference Unicode18')
        result['status'] = 'passed'
        result['rust_inputs_unchanged'] = result['rust_sha256'] == {str(v.relative_to(workspace)): digest(v) for v in rust_inputs}
        result['c_inputs_unchanged'] = result['source_sha256'] == {v: digest(a.source / v) for v in paths}
        result['reference_libraries_unchanged'] = all(digest(pathlib.Path(v['build_path'])) == v['sha256'] and digest(pathlib.Path(v['staged_path'])) == v['sha256'] for v in result['libraries'].values())
        if not all(result[v] for v in ('rust_inputs_unchanged', 'c_inputs_unchanged', 'reference_libraries_unchanged')):
            result['status'] = 'failed'
            raise RuntimeError('inputs changed during oracle execution')
    finally:
        (a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ('commands', 'rust_sha256', 'source_sha256', 'drivers_sha256', 'compiler')}, indent=2))

if __name__ == '__main__':
    main()
