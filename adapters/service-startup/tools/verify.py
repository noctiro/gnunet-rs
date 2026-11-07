#!/usr/bin/env python3
"""Rebuild and verify the actual gnunet-service-startup workspace package.

All outputs are fresh/disjoint; Cargo is pinned, locked/offline and uses an
output-local target. Normal GNUnet libraries/source are read, never rebuilt.
"""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import time
from _common import local_snapshot, require_disjoint_output, sha, unchanged, normal_reference, require_rust_fixture_success

RUST_CHECKS = [
    'early::tests::native_hex_prefix_and_full_unsigned_profiles_are_distinct',
    'early::tests::full_count_preflight_rejects_missing_extra_and_preserves_empty_components',
    'privilege::tests::original_primary_success_conditional_groups_and_raw_name_do_not_normalize',
    'privilege::tests::original_primary_short_circuit_and_every_fallback_failure_position',
]
PROCESS_CHECKS = {
    'ready-46', 'ready-73', 'ready-83', 'ready-EPIPE', 'close-stdio-0',
    'close-stdio-1', 'close-stdio-2', 'close-stdio-128',
    'close-distinct-fds-same-pipe', 'original-CLOEXEC-refused', 'fd-reuse',
    'once-only', 'duplicate', 'missing', 'closed-second', 'control-alias-refused',
    'control-original-prefix-signed-byte', 'control-plus-close-separate-owners',
    'normal-C-box-pipe', 'rust-box-equivalent-pipe', 'rust-bind', 'normal-bind',
    'rust-bind-refusal', 'normal-bind-refusal', 'rust-user-absent',
    'normal-user-absent', 'rust-user-current-direct-native',
    'normal-user-current-config-refuses', 'rust-user-current-config-refuses',
    'rust-user-current-explicit-no-initgroups', 'rust-user-missing',
    'normal-user-missing', 'rust-CLOSE-before-user-failure',
    'normal-daemon-reference-only',
}
PAIR_CHECKS = {
    'normal box accepts actual pipe and closes it',
    'close-after-real-configured-bind',
    'failed-own-bind-closes-child-ownership-without-init',
    'no-USERNAME-keeps-identity',
    'normal-USERNAME-filename-expansion-preserves-current-name-refusal',
    'unknown-user-fails-with-original-identity',
    'CLOSE-EOF-is-not-full-startup-success',
}
NORMAL_C_LABELS = {
    'normal-C-box-pipe', 'normal-bind', 'normal-bind-refusal',
    'normal-user-absent', 'normal-user-current-config-refuses',
    'normal-user-missing', 'normal-daemon-reference-only',
}
COMPONENT_CHECK = 'original-set_user_id-current-native-sequence'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--package', type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument('--source', type=pathlib.Path, required=True)
    parser.add_argument('--build-receipt', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--cargo', default='cargo')
    parser.add_argument('--toolchain', default='1.99.1')
    args = parser.parse_args()
    package = args.package.resolve()
    manifest = package / 'Cargo.toml'
    tools = pathlib.Path(__file__).resolve().parent
    cargo = [args.cargo, '+' + args.toolchain]
    pinned = ['--manifest-path', str(manifest), '--offline', '--locked']
    # --locked prevents metadata from changing the shared workspace lockfile.
    initial_argv = cargo + ['metadata', *pinned, '--format-version', '1']
    meta_run = subprocess.run(initial_argv, cwd=package, capture_output=True,
                              timeout=180)
    if meta_run.returncode != 0:
        raise RuntimeError('locked metadata failed: ' + meta_run.stderr.decode())
    metadata = json.loads(meta_run.stdout)
    reference_validation = normal_reference(args.build_receipt, args.source)
    reference = json.loads(args.build_receipt.read_text())
    protected = [pathlib.Path(metadata['workspace_root']), package, tools,
                 args.source, args.build_receipt.resolve().parent,
                 pathlib.Path(reference['build'])]
    for name in ('DYLD_LIBRARY_PATH', 'LD_LIBRARY_PATH'):
        protected.extend(pathlib.Path(item).parent for item in
                         reference['runtime_environment'].get(name, '').split(':')
                         if item)
    output = require_disjoint_output(args.output, protected)
    output.mkdir()
    (output / 'metadata.stdout').write_bytes(meta_run.stdout)
    (output / 'metadata.stderr').write_bytes(meta_run.stderr)
    selected, inputs = local_snapshot(metadata, package, tools)
    if selected['name'] != 'gnunet-service-startup':
        raise ValueError('requires actual gnunet-service-startup package')
    result = {
        'status': 'failed', 'scope': 'generic startup primitives only',
        'package': str(package), 'workspace_root': metadata['workspace_root'],
        'commands': [{'label': 'metadata', 'argv': initial_argv, 'exit_code': 0}],
        'inputs': inputs, 'normal_reference_validation': reference_validation,
        'build_settings': {key: os.environ.get(key) for key in
            ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC', 'RUSTDOC',
             'RUSTUP_TOOLCHAIN', 'MACOSX_DEPLOYMENT_TARGET', 'SDKROOT')},
    }
    started = time.monotonic()

    def run(label, argv, timeout=240):
        completed = subprocess.run([str(item) for item in argv], cwd=package,
                                   capture_output=True, timeout=timeout)
        (output / (label + '.stdout')).write_bytes(completed.stdout)
        (output / (label + '.stderr')).write_bytes(completed.stderr)
        result['commands'].append({'label': label,
            'argv': [str(item) for item in argv], 'exit_code': completed.returncode})
        if completed.returncode != 0:
            raise RuntimeError(label + ' returned ' + str(completed.returncode))
        return completed.stdout

    try:
        run('tool-boundaries', ['python3', '-B', tools / 'test_tools.py'])
        boundary_output = (output / 'tool-boundaries.stderr').read_text()
        if 'Ran 10 tests' not in boundary_output or not boundary_output.rstrip().endswith('OK'):
            raise RuntimeError('ten exact tool-boundary tests did not execute')
        result['tool_boundary_checks'] = 10
        run('cargo-version', cargo + ['--version', '--verbose'])
        run('fmt', cargo + ['fmt', '--manifest-path', manifest, '--package',
                            selected['name'], '--check'])
        target = output / 'cargo-target'
        # --lib runs exactly this package's four unit witnesses, not the whole
        # workspace and not an empty name filter. Actual output is checked below.
        tests = run('rust-tests', cargo + ['test', *pinned, '--package',
            selected['name'], '--lib', '--target-dir', target, '--', '--nocapture'])
        decoded = tests.decode()
        if (not all('test ' + name + ' ... ok' in decoded for name in RUST_CHECKS)
                or 'test result: ok. 4 passed; 0 failed;' not in decoded):
            raise RuntimeError('four exact Rust witnesses did not execute')
        result['rust_named_checks'] = RUST_CHECKS
        run('clippy', cargo + ['clippy', *pinned, '--package', selected['name'],
            '--all-targets', '--target-dir', target, '--', '-D', 'warnings'])
        run('rust-probe', cargo + ['build', *pinned, '--package', selected['name'],
            '--example', 'primitive', '--target-dir', target])
        binary = target / 'debug/examples/primitive'
        rust_binary = {'path': str(binary), 'sha256': sha(binary)}
        result['fresh_rust_binary'] = rust_binary
        shared_args = ['--package', package, '--source', args.source]
        run('normal-C-build', ['python3', '-B', tools / 'build_probe.py',
            *shared_args, '--build-receipt', args.build_receipt,
            '--output', output / 'normal-C'])
        run('extract-original-component', ['python3', '-B', tools /
            'extract_component.py', *shared_args,
            '--output', output / 'component-source'])
        run('native-component-build', ['python3', '-B', tools / 'build_probe.py',
            *shared_args, '--build-receipt', args.build_receipt,
            '--component-source', output / 'component-source/credential-component.c',
            '--output', output / 'component-build'])
        run('exec-processes', ['python3', '-B', tools / 'process_cases.py',
            '--package', package, '--rust', binary,
            '--rust-sha256', rust_binary['sha256'],
            '--c-build', output / 'normal-C/result.json', '--component-build',
            output / 'component-build/result.json', '--output', output / 'processes'])
        processes = json.loads((output / 'processes/result.json').read_text())
        if (processes['status'] != 'passed'
                or len(processes['cases']) != 34
                or {row['label'] for row in processes['cases']} != PROCESS_CHECKS
                or len(processes['paired']) != 7
                or {row['label'] for row in processes['paired']} != PAIR_CHECKS
                or len(processes['components']) != 1
                or processes['components'][0]['label'] != COMPONENT_CHECK
                or not all(row['passed'] for row in
                           processes['paired'] + processes['components'])
                or not processes.get('binaries_unchanged')):
            raise RuntimeError('exact nonempty native witnesses did not execute')
        for row in processes['cases']:
            expected_kind = 'normal-C' if row['label'] in NORMAL_C_LABELS else 'rust'
            if row['kind'] != expected_kind:
                raise RuntimeError('native witness kind mismatches its fixed label')
            if expected_kind == 'rust':
                require_rust_fixture_success(row)
        result['process_observations'] = len(processes['cases'])
        result['paired_normal_C_checks'] = len(processes['paired'])
        result['source_component_checks'] = len(processes['components'])
        result['normal_reference_unchanged'] = normal_reference(args.build_receipt, args.source) == reference_validation
        if not result['normal_reference_unchanged']:
            raise RuntimeError('normal reference changed during verification')
        result['rust_binary_unchanged'] = sha(binary) == rust_binary['sha256']
        _, after_inputs = local_snapshot(metadata, package, tools)
        result['inputs_unchanged'] = after_inputs == inputs
        if not result['inputs_unchanged'] or not result['rust_binary_unchanged']:
            raise RuntimeError('source or binary changed during verification')
        result['receipts'] = {str(path): sha(path) for path in
                             output.rglob('result.json')}
        result['status'] = 'passed'
    except Exception as error:
        result['failure'] = type(error).__name__ + ': ' + str(error)
    result['elapsed_seconds'] = time.monotonic() - started
    receipt = output / 'result.json'
    receipt.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'result': str(receipt),
                      'failure': result.get('failure')}))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
