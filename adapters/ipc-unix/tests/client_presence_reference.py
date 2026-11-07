#!/usr/bin/env python3
"""Execute normal C/Rust GNUNET_CLIENT_test over owned paths/loopback sockets."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
BUILDER = ROOT / 'tools/reference/build_reference.py'
spec = importlib.util.spec_from_file_location('presence_reference_builder', BUILDER)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cc', default=os.environ.get('CC', 'cc'))
    args = parser.parse_args()
    reference = args.reference.resolve()
    rust = args.rust.resolve()
    receipt = json.loads(reference.read_text())
    source = Path(receipt['source']).resolve()
    out = args.output.resolve()
    for input_root in (ROOT, source, Path(receipt['build']), Path(receipt['prefix'])):
        if out == input_root or out in input_root.parents or input_root in out.parents:
            raise ValueError('output overlaps source/reference')
    out.mkdir(parents=True, exist_ok=False)
    report = {'status': 'failed', 'kind': 'normal-C-Rust-public-CLIENT-test',
              'scope': 'owned Unix and loopback presence; no application handshake, public network or resolver',
              'commands': [], 'cases': []}
    source_before = builder.source_state(source)
    if (receipt['kind'] != 'unmodified-official-c-reference-build' or
            receipt['status'] != 'passed' or not receipt['source_unchanged'] or
            source_before != receipt['upstream']):
        raise ValueError('normal unchanged official reference required')
    protected = [*receipt['libraries'], *receipt['artifacts'].values(), receipt['generated_config']]
    for item in protected:
        if sha(item['path']) != item['sha256']:
            raise ValueError('normal reference artifact changed')
    csource = Path(__file__).with_name('client_presence_api.c')
    binary = out / 'normal-c-presence'
    compile_inputs = [Path(__file__), csource, BUILDER, reference, rust]
    compile_before = {str(p.resolve()): sha(p) for p in compile_inputs}
    save(out / 'caller-inputs-before-compile.json', compile_before)
    argv = [args.cc, '-std=c11', '-D_DARWIN_C_SOURCE', '-D_GNU_SOURCE', '-Wall', '-Wextra', '-Werror',
            '-I' + str(source / 'src/include'), '-I' + str(Path(receipt['build']) / 'src/include')]
    argv += shlex.split(receipt['build_environment']['CPPFLAGS']) + [str(csource)]
    argv += shlex.split(receipt['build_environment']['LDFLAGS'])
    argv += ['-L' + str(Path(receipt['prefix']) / 'lib'), '-Wl,-rpath,' + str(Path(receipt['prefix']) / 'lib'),
             '-lgnunetutil', '-o', str(binary)]
    compiled = subprocess.run(argv, capture_output=True, timeout=120)
    save(out / 'compile.json', {'argv': argv, 'exit_code': compiled.returncode,
                              'stdout': compiled.stdout.decode(errors='replace'),
                              'stderr': compiled.stderr.decode(errors='replace')})
    if compiled.returncode:
        raise ValueError('normal public caller failed to compile')
    compile_after = {str(p.resolve()): sha(p) for p in compile_inputs}
    if compile_before != compile_after or source_before != builder.source_state(source):
        raise ValueError('caller/tool/reference/source changed during compilation')
    save(out / 'caller-inputs-after-compile.json', compile_after)
    report['caller_inputs_unchanged_during_compile'] = True
    fingerprint_spec = importlib.util.spec_from_file_location('presence_inputs', ROOT / 'tools/interop/run_reference.py')
    fingerprints = importlib.util.module_from_spec(fingerprint_spec)
    fingerprint_spec.loader.exec_module(fingerprints)

    def inputs():
        paths = [Path(__file__), csource, BUILDER, reference, binary, rust,
                 Path(receipt['build']) / 'compile_commands.json']
        paths += [Path(item['path']) for item in protected]
        paths += [p for p in (ROOT / 'adapters/ipc-unix').rglob('*')
                  if p.is_file() and p.suffix in ('.rs', '.c', '.py', '.toml', '.md')]
        return {'workspace': fingerprints.fingerprints(ROOT),
                'files': {str(p.resolve()): sha(p) for p in paths}}

    before = inputs()
    save(out / 'inputs-before.json', before)
    env = os.environ.copy()
    env.update(receipt['runtime_environment'])
    env['LC_ALL'] = 'C'
    for name in ('LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'DYLD_FORCE_FLAT_NAMESPACE'):
        env.pop(name, None)
    sockets = []
    owned = tempfile.TemporaryDirectory(prefix='gcptest-', dir='/tmp')
    runtime = Path(owned.name)
    cases = out / 'cases'
    cases.mkdir()

    def listener(name):
        active = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sockets.append(active)
        path = runtime / name
        active.bind(str(path))
        active.listen(5)
        active.setblocking(False)
        return active, path

    def bound(family):
        active = socket.socket(family, socket.SOCK_STREAM)
        sockets.append(active)
        if family == socket.AF_INET6:
            active.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        active.bind(('127.0.0.1' if family == socket.AF_INET else '::1', 0))
        return active, active.getsockname()[1]

    def case(name, values, expected, active=None, connects=False):
        path = cases / (name + '.conf')
        content = b'[presence]\n' + b''.join(k.encode() + b' = ' + (str(v).encode() if not isinstance(v, bytes) else v) + b'\n' for k, v in values.items())
        path.write_bytes(content)
        observations = []
        for side, executable in (('c', binary), ('rust', rust)):
            command = [str(executable), str(path), 'presence']
            completed = subprocess.run(command, cwd=runtime, env=env, capture_output=True, timeout=5)
            stem = out / (name + '-' + side)
            stdout = stem.with_suffix('.stdout')
            stderr = stem.with_suffix('.stderr')
            stdout.write_bytes(completed.stdout)
            stderr.write_bytes(completed.stderr)
            report['commands'].append({'argv': command, 'cwd': str(runtime), 'exit_code': completed.returncode,
                                       'stdout': str(stdout), 'stdout_sha256': sha(stdout),
                                       'stderr': str(stderr), 'stderr_sha256': sha(stderr)})
            if completed.returncode or completed.stdout != (str(expected) + '\n').encode():
                raise AssertionError((name, side, completed.returncode, completed.stdout, expected))
            accepted = 0
            if active is not None:
                while True:
                    try:
                        child, _ = active.accept()
                    except BlockingIOError:
                        break
                    with child:
                        child.settimeout(1)
                        if child.recv(1) != b'':
                            raise AssertionError('presence test sent application bytes')
                    accepted += 1
                if accepted != int(connects):
                    raise AssertionError((name, side, 'actual connection count', accepted, connects))
            observations.append({'side': side, 'result': expected, 'accepted_connections': accepted})
        report['cases'].append({'name': name, 'expected': expected, 'observations': observations})

    try:
        direct, direct_path = listener('direct')
        demand, demand_path = listener('demand')
        v4, v4_port = bound(socket.AF_INET)
        v6, v6_port = bound(socket.AF_INET6)
        stale_path = runtime / 'stale'
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stale:
            stale.bind(str(stale_path))
        ordinary = runtime / 'ordinary'
        ordinary.write_bytes(b'owned non-socket marker')
        long_path = runtime / ('long-' + 'x' * 110)
        long_path.write_bytes(b'owned long path marker')
        marker_before = {str(p): sha(p) for p in (ordinary, long_path)}
        missing = runtime / 'missing'
        case('no-configuration', {}, -1)
        # Official filename expansion turns the empty value into cwd. The
        # ensuing ENOTSOCK is source weak LikelyUp, not the raw-empty branch.
        case('empty-unixpath-expands-cwd', {'UNIXPATH': ''}, 1)
        case('missing-unix-only', {'UNIXPATH': missing}, 0)
        case('missing-unix-invalid-port', {'UNIXPATH': missing, 'PORT': 'invalid'}, -1)
        case('port-zero', {'PORT': 0, 'HOSTNAME': 'remote.invalid'}, -1)
        case('port-overflow', {'PORT': 65536, 'HOSTNAME': 'remote.invalid'}, -1)
        case('remote-assumption', {'PORT': v4_port, 'HOSTNAME': 'not-resolved.invalid'}, 1)
        case('numeric-loopback-assumption', {'PORT': v4_port, 'HOSTNAME': '127.0.0.1'}, 1)
        case('empty-host-assumption', {'PORT': v4_port, 'HOSTNAME': ''}, 1)
        case('v4-bound-no-host', {'PORT': v4_port}, 1)
        case('v4-bound-localhost', {'PORT': v4_port, 'HOSTNAME': 'LOCALhost'}, 1)
        case('v6-bound-ip6-localnet', {'PORT': v6_port, 'HOSTNAME': 'ip6-localnet'}, 1)
        # The source probes bind, not listen/connect. The retained TCP sockets
        # have never called listen and still establish source LikelyUp.
        case('unix-direct', {'UNIXPATH': direct_path}, 1, direct, True)
        case('unix-stale', {'UNIXPATH': stale_path}, 0)
        case('ordinary-file-source-assumption', {'UNIXPATH': ordinary}, 1)
        case('on-demand-no-connect', {'UNIXPATH': demand_path, 'START_ON_DEMAND': 'YES'}, 1, demand)
        case('immediate-no-connect', {'UNIXPATH': demand_path, 'IMMEDIATE_START': 'YES', 'START_ON_DEMAND': 'NO'}, 1, demand)
        case('noarmbind-overrides-demand', {'UNIXPATH': demand_path, 'IMMEDIATE_START': 'YES', 'NOARMBIND': 'YES', 'START_ON_DEMAND': 'YES'}, 1, demand, True)
        case('invalid-immediate-demand', {'UNIXPATH': demand_path, 'IMMEDIATE_START': 'invalid', 'START_ON_DEMAND': 'YES'}, 1, demand)
        case('invalid-noarmbind-immediate', {'UNIXPATH': demand_path, 'IMMEDIATE_START': 'YES', 'NOARMBIND': 'invalid'}, 1, demand)
        case('stale-unix-tcp-fallback', {'UNIXPATH': stale_path, 'PORT': v4_port, 'HOSTNAME': 'localhost'}, 1)
        case('missing-unix-remote-fallback', {'UNIXPATH': missing, 'PORT': v4_port, 'HOSTNAME': 'remote.invalid'}, 1)
        case('empty-unix-precedes-invalid-tcp', {'UNIXPATH': '', 'PORT': 'invalid', 'HOSTNAME': 'remote.invalid'}, 1)
        case('long-existing-direct', {'UNIXPATH': long_path}, -1)
        case('long-existing-arm-bound', {'UNIXPATH': long_path, 'START_ON_DEMAND': 'YES'}, 1)
        case('regular-file-arm-bound', {'UNIXPATH': ordinary, 'START_ON_DEMAND': 'YES'}, 1)
        # Pick one just-released port with both loopback families confirmed free.
        for attempt in range(10):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as free4:
                free4.bind(('127.0.0.1', 0))
                port = free4.getsockname()[1]
                with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as free6:
                    free6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    try:
                        free6.bind(('::1', port))
                    except OSError:
                        continue
            case('free-loopback-port', {'PORT': port, 'HOSTNAME': 'localhost'}, 0)
            case('free-no-host-loopback', {'PORT': port}, 0)
            case('free-ip6-localnet-loopback', {'PORT': port, 'HOSTNAME': 'IP6-LOCALNET'}, 0)
            case('free-numeric-loopback-is-assumed-remote', {'PORT': port, 'HOSTNAME': '127.0.0.1'}, 1)
            case('free-empty-host-is-assumed-remote', {'PORT': port, 'HOSTNAME': ''}, 1)
            case('free-remote-assumption', {'PORT': port, 'HOSTNAME': 'not-resolved.invalid'}, 1)
            break
        else:
            raise AssertionError('no free owned loopback port found')
        if marker_before != {str(p): sha(p) for p in (ordinary, long_path)}:
            raise AssertionError('owned ordinary marker changed')
        report['owned_markers_unchanged'] = True
        report['status'] = 'passed'
    except Exception as error:
        report['failure'] = repr(error)
        raise
    finally:
        for active in sockets:
            active.close()
        owned.cleanup()
        after = inputs()
        save(out / 'inputs-after.json', after)
        report.update(actual_case_count=len(report['cases']), actual_public_calls=len(report['commands']),
                      inputs_unchanged=before == after,
                      official_sources_unchanged=source_before == builder.source_state(source),
                      owned_runtime_removed=not runtime.exists(),
                      reference={'path': str(reference), 'sha256': sha(reference)})
        if before != after or not report['official_sources_unchanged']:
            report['status'] = 'failed'
        for item in protected:
            if sha(item['path']) != item['sha256']:
                report['status'] = 'failed'
        save(out / 'result.json', report)
    if report['status'] != 'passed':
        raise ValueError('source/reference changed')
    print(json.dumps({'status': report['status'], 'cases': report['actual_case_count'],
                      'public_calls': report['actual_public_calls'], 'result': str(out / 'result.json')}))


if __name__ == '__main__':
    main()
