#!/usr/bin/env python3
"""Run the real Rust resolver owner against an unchanged normal C daemon.

This macOS reference profile denies every IPv4/IPv6 output syscall before any
lookup. It exercises real hosts-only service results, numeric fast paths,
cancellation and client-side reverse timeout. Positive recursive DNS/CNAME/PTR
coverage requires the separately planned contained Linux DNS environment.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools/reference'))
from build_reference import REVISION, source_state

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def host_fixture(hosts_bytes=None):
    rows = []
    raw = Path('/etc/hosts').read_bytes() if hosts_bytes is None else hosts_bytes
    for line in raw.splitlines():
        fields = line.rsplit(b'#', 1)[0].split()
        if len(fields) < 2:
            continue
        try:
            address = ipaddress.ip_address(fields[0].decode('ascii'))
        except (ValueError, UnicodeError):
            continue
        for alias in fields[1:]:
            rows.append((alias, str(address)))
    for alias, address in reversed(rows):
        if alias.lower() in (b'localhost', b'ip6-localnet'):
            continue
        try:
            ipaddress.ip_address(alias.decode('ascii'))
        except (ValueError, UnicodeError):
            return alias.decode('utf-8'), address
    raise ValueError('no actual non-fast hosts alias exists; no daemon-path credit')

def selftest():
    # Parser output is explicit and no network/process is created in selftest.
    assert REVISION == '346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
    assert ipaddress.ip_address('::1').packed == bytes(15) + b'\1'
    assert host_fixture(b'127.0.0.1 localhost\n::1 audit\n127.0.0.7 audit\n') == ('audit', '127.0.0.7')
    try:
        host_fixture(b'127.0.0.1 localhost\n::1 IP6-LOCALNET\n')
    except ValueError:
        pass
    else:
        raise AssertionError('fast-only aliases cannot prove daemon lookup')
    print('resolver oracle selftest passed')
    return 0

def main():
    if sys.argv[1:] == ['--selftest']:
        return selftest()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', required=True, type=Path, help='resolver-build-result.json from normal unchanged Meson targets')
    parser.add_argument('--rust', required=True, type=Path, help='actual built resolver example')
    parser.add_argument('--output', required=True, type=Path, help='new evidence directory')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'kind': 'normal-c-resolver-rust-owner', 'status': 'failed', 'commands': [], 'cases': [],
              'scope': 'Actual Rust owner -> unchanged normal C resolver over owned Unix IPC. No full DNS/cache/service or native FQDN certificate.'}
    process = None
    owned = None
    streams = []
    def run(name, argv, env, expected):
        result = subprocess.run([str(v) for v in argv], env=env, capture_output=True, timeout=10)
        stdout = output / (name + '.stdout')
        stderr = output / (name + '.stderr')
        stdout.write_bytes(result.stdout)
        stderr.write_bytes(result.stderr)
        report['commands'].append({'name': name, 'argv': [str(v) for v in argv], 'exit_code': result.returncode,
                                   'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr)})
        if result.returncode or result.stdout.decode().splitlines() != expected:
            raise ValueError(name + ' differed: ' + repr((result.returncode, result.stdout, result.stderr)))
        return result
    try:
        if platform.system() != 'Darwin' or not Path('/usr/bin/sandbox-exec').is_file():
            raise ValueError('this oracle requires the actual macOS IP-denial profile; no uncontained DNS fallback')
        reference = json.loads(args.reference.read_text())
        if reference.get('status') != 'passed' or reference.get('kind') != 'normal-c-resolver-reference':
            raise ValueError('normal resolver build receipt required')
        base_path = Path(reference['base_receipt'])
        if sha(base_path) != reference['base_receipt_sha256']:
            raise ValueError('base receipt changed')
        base = json.loads(base_path.read_text())
        before = source_state(Path(base['source']))
        if before != reference['upstream'] or before['revision'] != REVISION:
            raise ValueError('normal source differs from pinned build')
        refs = [*base['artifacts'].values(), *base['libraries'], *base['default_configurations'], *reference['artifacts'].values()]
        if any(sha(v['path']) != v['sha256'] for v in refs):
            raise ValueError('normal reference file changed')
        build_libraries = []
        for row in base['libraries']:
            name = Path(row['path']).name
            directory = 'src/lib/util' if name.startswith('libgnunetutil') else 'src/service/statistics'
            original = Path(base['build']) / directory / name
            if sha(original) != row['sha256']:
                raise ValueError('normal build-tree library changed: ' + str(original))
            build_libraries.append({'path': str(original), 'sha256': row['sha256']})
        report['reference_build_libraries'] = build_libraries
        service = Path(reference['artifacts']['service']['built_path'])
        if sha(service) != reference['artifacts']['service']['sha256']:
            raise ValueError('build-tree daemon differs from staged receipt')
        inputs = [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', ROOT / 'rust-toolchain.toml',
                  ROOT / 'adapters/ipc-unix/examples/resolver.rs', Path(__file__).resolve()]
        for package in ['crates/gnunet-types', 'crates/gnunet-wire', 'crates/gnunet-client',
                        'crates/gnunet-crypto', 'crates/gnunet-statistics', 'adapters/config-std',
                        'adapters/native-std', 'adapters/ipc-unix']:
            inputs.append(ROOT / package / 'Cargo.toml')
            inputs.extend(sorted((ROOT / package / 'src').rglob('*.rs')))
        report['input_sha256'] = {str(p): sha(p) for p in inputs}
        report['rust_binary'] = {'path': str(args.rust.resolve()), 'sha256': sha(args.rust)}
        report['reference'] = {'path': str(args.reference.resolve()), 'sha256': sha(args.reference), 'upstream': before}
        report['host_files_sha256'] = {p: sha(p) for p in ['/etc/hosts', '/etc/resolv.conf']}
        alias, address = host_fixture()
        report['actual_hosts_fixture'] = {'alias': alias, 'address': address, 'fast_path_excluded': True}
        owned = Path(tempfile.mkdtemp(prefix='grsv-owner-'))
        owned.chmod(0o700)
        profile = output / 'no_ip.sb'
        profile.write_text('(version 1)\n(allow default)\n(deny network-outbound (remote ip))\n')
        prefix = ['/usr/bin/sandbox-exec', '-f', str(profile)]
        env = {k: v for k, v in os.environ.items() if not k.startswith('GNUNET_')}
        env.update(base['runtime_environment'], LC_ALL='C')
        verify = "import socket\nfor family,address in [(socket.AF_INET,('127.0.0.1',9)),(socket.AF_INET6,('::1',9))]:\n s=socket.socket(family,socket.SOCK_DGRAM)\n try:s.sendto(b'resolver-owner-denial',address)\n except PermissionError:print('denied',int(family))\n else:raise SystemExit(3)\n s.close()\n"
        run('ip-output-denial', prefix + [sys.executable, '-c', verify], env, ['denied 2', 'denied 30'])
        report['ip_output_denial_verified'] = True
        sock = owned / 'r.sock'
        config = owned / 'resolver.conf'
        config.write_text('[resolver]\nUNIXPATH = ' + str(sock) + '\nHOSTNAME = localhost\nPORT = 0\nSTART_ON_DEMAND = NO\nUNIX_MATCH_UID = NO\nUNIX_MATCH_GID = NO\n')
        (output / 'config.txt').write_bytes(config.read_bytes())
        streams = [(output / ('daemon.' + suffix)).open('wb') for suffix in ['stdout', 'stderr']]
        argv = prefix + [str(service), '-c', str(config), '-L', 'DEBUG']
        process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=streams[0], stderr=streams[1])
        report['daemon'] = {'argv': argv, 'pid': process.pid}
        until = time.monotonic() + 8
        while not sock.exists():
            if process.poll() is not None:
                raise ValueError('normal daemon exited before socket readiness')
            if time.monotonic() >= until:
                raise ValueError('normal daemon readiness expired')
            time.sleep(.025)
        report['daemon']['socket_ready'] = True
        cases = [
            ('actual-hosts-forward', 'forward', alias, ['connected', 'address|' + address, 'end|end', 'summary|1|1|1']),
            ('actual-hosts-cancel', 'cancel-first', alias, ['connected', 'address|' + address, 'cancel|value', 'summary|1|1|0']),
            ('numeric-v4', 'forward', '127.0.0.1', ['address|127.0.0.1', 'end|end', 'summary|0|1|1']),
            ('numeric-v6', 'forward', '::1', ['address|::1', 'end|end', 'summary|0|1|1']),
            ('loopback-order', 'forward', 'LoCaLhOsT', ['address|::1', 'address|127.0.0.1', 'end|end', 'summary|0|2|1']),
            ('numeric-reverse', 'numeric-reverse', '127.0.0.1', ['numeric|127.0.0.1', 'end|end', 'summary|0|1|1']),
            ('actual-reverse-client-timeout', 'reverse', '127.0.0.1', ['connected', 'numeric|127.0.0.1', 'end|timeout', 'summary|1|1|1']),
            ('cancel-before-submit', 'cancel-before', alias, ['cancel|before', 'summary|0|0|0']),
        ]
        for name, mode, value, expected in cases:
            before_log = (output / 'daemon.stderr').read_bytes()
            run(name, prefix + [args.rust.resolve(), config, mode, value], env, expected)
            after_log = (output / 'daemon.stderr').read_bytes()
            added = after_log[len(before_log):]
            if name.startswith('actual-hosts-') and b'Client asks to resolve `' + alias.encode() + b"'" not in added:
                raise ValueError('ordinary host result did not actually traverse normal daemon')
            if name == 'actual-reverse-client-timeout' and b'Resolving 1.0.0.127.in-addr.arpa' not in added:
                raise ValueError('reverse request did not traverse actual normal daemon')
            report['cases'].append({'name': name, 'mode': mode, 'expected_stdout': expected,
                                    'actual_daemon_path': name.startswith('actual-')})
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=5)
        report['daemon']['exit_code'] = process.returncode
        if process.returncode:
            raise ValueError('normal daemon did not shut down cleanly')
        report['source_unchanged'] = source_state(Path(base['source'])) == before
        report['reference_files_unchanged'] = all(sha(v['path']) == v['sha256'] for v in [*refs, *build_libraries]) and sha(service) == reference['artifacts']['service']['sha256']
        report['inputs_unchanged'] = all(sha(p) == value for p, value in report['input_sha256'].items())
        report['rust_binary_unchanged'] = sha(args.rust) == report['rust_binary']['sha256']
        report['host_files_unchanged'] = all(sha(p) == value for p, value in report['host_files_sha256'].items())
        if not all(report[k] for k in ['source_unchanged', 'reference_files_unchanged', 'inputs_unchanged', 'rust_binary_unchanged', 'host_files_unchanged']):
            raise ValueError('oracle input changed during execution')
        report['status'] = 'passed'
    except Exception as error:
        report['failure'] = type(error).__name__ + ': ' + str(error)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                report['forced_kill_cleanup'] = True
        for stream in streams:
            stream.close()
        if owned is not None:
            shutil.rmtree(owned)
            report['owned_runtime_removed'] = not owned.exists()
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'cases': len(report['cases']), 'report': str(output / 'result.json'), 'failure': report.get('failure')}))
    return 0 if report['status'] == 'passed' else 1

if __name__ == '__main__':
    raise SystemExit(main())
