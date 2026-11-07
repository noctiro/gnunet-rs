#!/usr/bin/env python3
"""Fresh source-bound CLOCK-MQ/IO evidence, with every generated file under --output."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
from comparison import compare

ROOT = Path(__file__).resolve().parent
TOOLCHAIN = '1.99.1'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def package_inputs():
    return {str(p): digest(p) for p in sorted(ROOT.rglob('*')) if p.is_file() and '__pycache__' not in p.parts}


def snapshot(repository):
    result = subprocess.run(['rg', '--files', '--hidden', '-g', '!.git', '-g', '!target', '-g', '!.agents', '-g', '!.codex'],
                            cwd=repository, check=True, capture_output=True, text=True)
    paths = sorted((repository/name for name in result.stdout.splitlines()), key=lambda p: str(p).encode())
    return {str(path): digest(path) for path in paths if path.is_file()}


def command(argv, output, env, record, name, repository):
    result = subprocess.run(argv, cwd=repository, env=env, capture_output=True, text=True, timeout=120)
    (output/(name+'.stdout')).write_text(result.stdout)
    (output/(name+'.stderr')).write_text(result.stderr)
    record['commands'].append({'name': name, 'argv': argv, 'cwd': str(repository), 'exit_code': result.returncode,
                               'stdout_sha256': digest(output/(name+'.stdout')), 'stderr_sha256': digest(output/(name+'.stderr'))})
    if result.returncode:
        raise RuntimeError(name+' failed: '+result.stderr[-4000:])
    return result.stdout


def registry_packages(lock):
    packages = set()
    for block in lock.read_text().split('[[package]]')[1:]:
        fields = dict(re.findall(r'^(name|version|source|checksum) = "([^"]*)"$', block, re.M))
        if fields.get('source', '').startswith('registry+'):
            packages.add(tuple(fields.get(field) for field in ['name', 'version', 'source', 'checksum']))
    return packages


def generate(repository, output):
    crate = output/'rust'
    (crate/'src').mkdir(parents=True)
    (crate/'tests').mkdir()
    manifest = (ROOT/'templates/Cargo.toml.in').read_text()
    for token, relative in [('CLIENT', 'crates/gnunet-client'), ('TYPES', 'crates/gnunet-types'),
                            ('WIRE', 'crates/gnunet-wire'), ('CONFIG', 'adapters/config-std'), ('IPC', 'adapters/ipc-unix'),
                            ('RUNTIME', 'adapters/service-runtime'), ('CLIENTHOST', 'adapters/client-std')]:
        manifest = manifest.replace('@'+token+'@', json.dumps(str(repository/relative)))
    if re.search(r'@[A-Z_]+@', manifest):
        raise ValueError('unexpanded Cargo template token')
    (crate/'Cargo.toml').write_text(manifest)
    # Seed the throwaway crate from the real dependency resolution. Cargo may add
    # this new package, but all registry package identities are checked below.
    shutil.copyfile(repository/'Cargo.lock', crate/'Cargo.lock')
    (crate/'rust-toolchain.toml').write_text('[toolchain]\nchannel = "'+TOOLCHAIN+'"\nprofile = "minimal"\n')
    for name in ['lib.rs', 'ports.rs', 'stream.rs', 'connection.rs']:
        shutil.copyfile(ROOT/'templates'/str(name+'.in'), crate/'src'/name)
    shutil.copyfile(ROOT/'templates/clock.rs.in', crate/'tests/clock.rs')
    source = repository/'adapters/ipc-unix/src/handle.rs'
    prefix = source.read_bytes()
    staged = crate/'src/staged_handle.rs'
    staged.write_bytes(prefix+b'\n'+(ROOT/'driver_tests.rs').read_bytes())
    docs = {}
    for relative in re.findall(r'include_str!\(\s*"([^"\n]+)"\s*\)', prefix.decode()):
        original = (source.parent/relative).resolve()
        target = (staged.parent/relative).resolve()
        if not original.is_relative_to(repository) or not target.is_relative_to(crate):
            raise ValueError('include_str path escapes repository or generated crate')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
        docs[str(original)] = {'copy': str(target), 'sha256': digest(original)}
    return crate, source, prefix, staged, docs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--rust-only', action='store_true', help='Generate/check real Rust owners and ports only; no C comparison or conformance credit')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.rust_only and (args.source is None or args.reference is None):
        parser.error('--source and --reference are required unless --rust-only is selected')
    repository = args.repository.resolve()
    output = args.output.resolve()
    if output.is_relative_to(ROOT):
        parser.error('--output must be outside this read-only tool package')
    if output.is_relative_to(repository) and not output.is_relative_to(repository/'target'):
        parser.error('an output inside the repository must be below target/')
    output.mkdir(parents=True, exist_ok=False)
    record = {'kind': 'statistics-clock-mq-io-source-bound-component', 'status': 'failed', 'toolchain': TOOLCHAIN,
              'mode': 'rust-only-generated' if args.rust_only else 'c-rust-component',
              'fresh_c_comparison': False, 'full_daemon_oracle': False, 'whole_statistics_complete': False, 'commands': [],
              'repository_inputs': snapshot(repository), 'tool_inputs': package_inputs()}
    env = {**os.environ, 'CARGO_TARGET_DIR': str(output/'target'), 'RUSTDOCFLAGS': '-Dwarnings',
           'RUSTUP_TOOLCHAIN': TOOLCHAIN, 'PYTHONDONTWRITEBYTECODE': '1', 'CARGO_BUILD_JOBS': '2'}
    try:
        crate, source, prefix, staged, docs = generate(repository, output)
        record['staged_driver'] = {'original': str(source), 'path': str(staged), 'byte_count': len(prefix),
                                    'original_sha256': digest(source), 'staged_sha256': digest(staged),
                                    'unchanged_entire_source_prefix': True, 'copied_include_str_files': docs,
                                    'only_replaced_capabilities': ['Connection finite OS-return provider in seven IO tests'],
                                    'real_ports': ['gnunet-client-host EndpointSource/Endpoint/attempt', 'SharedResolution', 'LiveConfiguration', 'RuntimeClock/Deadline'],
                                    'tool_aliases': ['gnunet_client_host aliases generated facade', 'gnunet_service_runtime aliases generated facade'],
                                    'alias_scope': 'Only generated type bindings; native CLIENT, resolver, clocks and leases execute in real packages. No production source hook.',
                                    'actual_dependencies': 'Unmodified gnunet-client core, gnunet-config, gnunet-types, gnunet-wire and IpcError from the real IPC package.'}
        assert staged.read_bytes() == prefix+b'\n'+(ROOT/'driver_tests.rs').read_bytes()
        if not args.rust_only:
            command([sys.executable, str(ROOT/'component.py'), '--repository', str(repository), '--source', str(args.source.resolve()),
                     '--reference', str(args.reference.resolve()), '--output', str(output/'c')], output, env, record, 'c-component', repository)
            c = json.loads((output/'c/result.json').read_text())
            assert c['status'] == 'passed' and c['trace_rows'] == 73 and c['source_unchanged'] and c['normal_reference_unchanged'] and c['dependencies_unchanged']
            record['c_result'] = {'path': str(output/'c/result.json'), 'sha256': digest(output/'c/result.json'), 'two_profiles_equal': True, 'trace_rows': 73}
        cargo = ['cargo', '+'+TOOLCHAIN]
        manifest = ['--manifest-path', str(crate/'Cargo.toml'), '--offline']
        command([*cargo, 'check', *manifest], output, env, record, 'rust-prepare', crate)
        assert registry_packages(crate/'Cargo.lock') <= registry_packages(repository/'Cargo.lock'), 'generated dependency identities differ from real workspace lock'
        record['generated_inputs'] = {str(p): digest(p) for p in crate.rglob('*') if p.is_file()}
        locked = [*manifest, '--locked']
        stdout = command([*cargo, 'test', *locked, '--', '--nocapture', '--test-threads=1'], output, env, record, 'rust-tests', crate)
        names = re.findall(r'test ([A-Za-z_][A-Za-z_0-9:]*) \.\.\. ', stdout)
        driver_modules = re.split(r'(?m)^#\[cfg\(test\)\]\nmod (\w+) \{', (ROOT/'driver_tests.rs').read_text())
        required = [*['staged_handle::'+module+'::'+name
                      for module, body in zip(driver_modules[1::2], driver_modules[2::2])
                      for name in re.findall(r'#\[test\]\s+fn (\w+)', body)],
                    *re.findall(r'#\[test\]\s+fn (\w+)', (ROOT/'templates/clock.rs.in').read_text())]
        assert len(required) == 17 and len(names) == len(required) and set(names) == set(required)
        record['actual_rust_tests'] = names
        if not args.rust_only:
            record['comparison'] = compare((output/'c/optimized.trace').read_text(), stdout)
            command([sys.executable, str(ROOT/'selftest.py'), '--c-trace', str(output/'c/optimized.trace'), '--rust-output', str(output/'rust-tests.stdout'),
                     '--output', str(output/'selftest-result.json')], output, env, record, 'comparator-selftest', repository)
            assert json.loads((output/'selftest-result.json').read_text())['rejected_mutations'] == 5
            record['fresh_c_comparison'] = True
        else:
            record['c_comparison_not_run'] = 'Rust-only interface/behavior checks supply no new C interoperability evidence.'
        command([*cargo, 'clippy', *locked, '--all-targets', '--', '-D', 'warnings'], output, env, record, 'rust-clippy', crate)
        command([*cargo, 'doc', *locked, '--no-deps'], output, env, record, 'rust-doc', crate)
        record['versions'] = {'rustc': subprocess.check_output(['rustc', '+'+TOOLCHAIN, '-vV'], cwd=repository, env=env, text=True),
                               'cargo': subprocess.check_output([*cargo, '-V'], cwd=repository, env=env, text=True)}
        record['repository_inputs_unchanged'] = snapshot(repository) == record['repository_inputs']
        record['tool_inputs_unchanged'] = package_inputs() == record['tool_inputs']
        record['generated_inputs_unchanged'] = all(digest(Path(path)) == expected for path, expected in record['generated_inputs'].items())
        record['staged_prefix_still_matches'] = source.read_bytes() == prefix and staged.read_bytes() == prefix+b'\n'+(ROOT/'driver_tests.rs').read_bytes()
        assert record['repository_inputs_unchanged'] and record['tool_inputs_unchanged'] and record['generated_inputs_unchanged'] and record['staged_prefix_still_matches']
        record['status'] = 'passed'
    except Exception as error:
        record['failure'] = repr(error)
    (output/'result.json').write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps({'status': record['status'], 'result': str(output/'result.json'), 'failure': record.get('failure')}))
    return int(record['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
