#!/usr/bin/env python3
"""Fresh actual production Resolver app smoke, separate from the C-client fixture.

Only real literal /etc/hosts data is queried over raw official4/5 Unix IPC.
No test file/upstream/config extensions are supplied to production. MacOS also
runs the app under an explicit outbound-IP denial policy. If the exact native
hosts parser cannot establish a loopback localhost alias, fail as an unavailable
profile before starting a service or making a lookup; never substitute DNS.

All build artifacts, snapshots and receipts live in --output; source is read-only.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def native_hosts(data):
    """Match frozen files.rs: LF only, first NUL stops, last '#', SP/HT tokens."""
    aliases = []
    remaining = data
    while True:
        end = next((i for i, b in enumerate(remaining) if b in (0, 10)), None)
        if end is None or remaining[end] == 0:
            return aliases
        line, remaining = remaining[:end], remaining[end + 1:]
        if b'#' in line:
            line = line[:line.rfind(b'#')]
        line = line.lstrip(b' \t\n\v\f\r')
        tokens = [x for x in re.split(b'[ \t]+', line) if x]
        if len(tokens) < 2:
            continue
        try:
            address = ipaddress.ip_address(tokens[0].decode('ascii'))
        except (ValueError, UnicodeDecodeError):
            continue
        for alias in tokens[1:]:
            aliases.append((alias, address))


def receive_exact(stream, n):
    data = bytearray()
    while len(data) != n:
        block = stream.recv(n - len(data))
        if not block:
            raise RuntimeError('EOF before complete official response')
        data.extend(block)
    return bytes(data)


def response(stream, wire_id):
    header = receive_exact(stream, 4)
    length, kind = struct.unpack('!HH', header)
    assert kind == 5 and 8 <= length <= 65535, (length, kind)
    payload = receive_exact(stream, length - 4)
    assert payload[:4] == wire_id, (payload[:4].hex(), wire_id.hex())
    return header + payload, payload[4:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    repo, output = args.repository.resolve(), args.output.resolve()
    for source in [repo, Path(__file__).resolve().parent]:
        if output.is_relative_to(source) or source.is_relative_to(output):
            parser.error('output overlaps source')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {'status': 'failed', 'scope': 'Fresh actual production Resolver app: literal hosts-only raw IPC, SIGTERM, inherited descriptor bypass and parent path ownership; separate from normal C-client fixture proof', 'commands': [], 'checks': []}
    env = dict(os.environ, CARGO_TARGET_DIR=str(output / 'target'))
    cargo = ['cargo', '+1.99.1']
    before = {}
    owned = None
    def run(label, argv, timeout=180):
        p = subprocess.run(list(map(str, argv)), cwd=repo, env=env, capture_output=True, timeout=timeout)
        (output / (label + '.stdout')).write_bytes(p.stdout)
        (output / (label + '.stderr')).write_bytes(p.stderr)
        report['commands'].append({'label': label, 'argv': list(map(str, argv)), 'exit_code': p.returncode})
        if p.returncode:
            raise RuntimeError(label + ' failed: ' + str(output / (label + '.stderr')))
        return p.stdout
    def check(name, value, details=None):
        row = {'name': name, 'passed': bool(value)}
        if details is not None:
            row['observed'] = details
        report['checks'].append(row)
        assert value, row
    try:
        hosts = Path('/etc/hosts').read_bytes()
        aliases = native_hosts(hosts)
        selected = [address for alias, address in aliases if alias == b'localhost']
        if not selected or not selected[-1].is_loopback or len(aliases) > 1024 or len(hosts) > 16 * 1024 * 1024:
            report['status'] = 'profile-unavailable'
            report['reason'] = 'Native literal hosts parse cannot prove an in-capacity loopback localhost cache hit; no lookup or service started'
            return 2
        expected = selected[-1].packed
        report['literal_hosts_profile'] = {'file': '/etc/hosts', 'sha256': sha('/etc/hosts'), 'alias_hex': b'localhost'.hex(), 'expected_latest_address': str(selected[-1]), 'alias_count': len(aliases), 'rule': 'source parser prepends entries, Any returns first matching native row'}
        metadata = json.loads(run('metadata', cargo + ['metadata', '--manifest-path', repo / 'Cargo.toml', '--offline', '--locked', '--format-version', '1']))
        paths = [Path(__file__).resolve(), repo / 'Cargo.toml', repo / 'Cargo.lock', repo / 'rust-toolchain.toml', Path('/etc/hosts'), Path('/etc/resolv.conf')]
        paths += [p for p in (repo / '.cargo').rglob('*') if p.is_file()]
        for package in metadata['packages']:
            if package['source'] is not None:
                continue
            manifest = Path(package['manifest_path'])
            paths.append(manifest)
            paths.extend(p for p in (manifest.parent / 'src').rglob('*') if p.is_file())
            for name in ['README.md', 'build.rs']:
                if (manifest.parent / name).is_file():
                    paths.append(manifest.parent / name)
        before = {str(p): sha(p) for p in sorted(set(paths))}
        report['source_inputs_before_build'] = before
        run('fresh-app-build', cargo + ['build', '--manifest-path', repo / 'Cargo.toml', '--offline', '--locked', '-p', 'gnunet-service-resolver'])
        built = output / 'target/debug/gnunet-service-resolver'
        snapshot = output / 'production-app'
        shutil.copy2(built, snapshot)
        snapshot.chmod(0o500)
        digest = sha(built)
        check('fresh-app-equals-executed-snapshot', sha(snapshot) == digest)
        report['fresh_app'] = {'built': str(built), 'executed': str(snapshot), 'sha256': digest}
        owned = Path(tempfile.mkdtemp(prefix='gn-r-app-', dir='/private/tmp' if Path('/private/tmp').is_dir() else '/tmp'))
        owned.chmod(0o700)
        report['owned_runtime_directory'] = str(owned)
        base = {k: v for k, v in os.environ.items() if not k.startswith(('LISTEN_', 'GNUNET_'))}
        defaults = owned / 'empty-defaults'
        defaults.mkdir()
        base['GNUNET_BASE_CONFIG'] = str(defaults)
        for key in ['XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_RUNTIME_DIR']:
            path = owned / key.lower()
            path.mkdir(mode=0o700)
            base[key] = str(path)
        # The profile is additional containment, not a replacement for proving
        # that this actual raw daemon request hits the literal hosts cache.
        if sys.platform == 'darwin' and Path('/usr/bin/sandbox-exec').is_file():
            policy = output / 'deny-outbound-ip.sb'
            policy.write_text('(version 1)\n(allow default)\n(deny network-outbound (remote ip))\n')
            prefix = ['/usr/bin/sandbox-exec', '-f', str(policy)]
            report['ip_network_containment'] = {'kind': 'macos-sandbox-outbound-ip-denial', 'policy_sha256': sha(policy)}
        else:
            prefix = []
            report['ip_network_containment'] = {'kind': 'no-general-IP-sandbox-available', 'boundary': 'Only source-proven real literal-hosts cache hit is requested; no external lookup is submitted'}
        def one(label, inherited=False):
            directory = output / label
            directory.mkdir()
            path = owned / (label + '.sock')
            configured = owned / (label + '-unused.sock') if inherited else path
            cfg = directory / 'official.conf'
            cfg.write_text('[resolver]\nUNIXPATH = ' + str(configured) + '\nPORT = ' + ('70000' if inherited else '0') + '\nBINDTO = ' + ('invalid configured endpoint bypass' if inherited else '127.0.0.1') + '\nDISABLEV6 = YES\nUNIX_MATCH_UID = NO\nUNIX_MATCH_GID = NO\nSTART_ON_DEMAND = NO\n')
            parent = None
            stream = None
            process = None
            stdout = (directory / 'app.stdout').open('wb')
            stderr = (directory / 'app.stderr').open('wb')
            declaration = dict(base)
            pass_fds = ()
            if inherited:
                parent = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                parent.bind(str(path))
                parent.listen(5)
                declaration.update(LISTEN_FDS='1', LISTEN_FDNAMES=str(parent.fileno()))
                pass_fds = (parent.fileno(),)
            argv = prefix + [str(snapshot), '-c', str(cfg)]
            report['commands'].append({'label': label, 'argv': argv, 'inherited_numeric_fd': pass_fds[0] if inherited else None})
            try:
                process = subprocess.Popen(argv, env=declaration, pass_fds=pass_fds, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
                until = time.monotonic() + 10
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(label + ' exited before request: ' + str(process.returncode))
                    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    stream.settimeout(3)
                    try:
                        stream.connect(str(path))
                        break
                    except (FileNotFoundError, ConnectionRefusedError):
                        stream.close()
                        stream = None
                        if time.monotonic() >= until:
                            raise TimeoutError(label + ' readiness')
                        time.sleep(.005)
                # Exact official request4: direction0, AF_UNSPEC0, opaque raw ID.
                wire_id = bytes.fromhex('9a0080ff') if inherited else bytes.fromhex('ff80009a')
                name = b'localhost\0'
                query = struct.pack('!HHii', 16 + len(name), 4, 0, 0) + wire_id + name
                stream.sendall(query)
                address_frame, address = response(stream, wire_id)
                end_frame, end = response(stream, wire_id)
                check(label + '-raw-request4-response5-and-opaque-id', address == expected and end == b'', {'request_hex': query.hex(), 'address_frame_hex': address_frame.hex(), 'end_frame_hex': end_frame.hex()})
                check(label + '-configured-unused-path-absent', not configured.exists() if inherited else path.exists())
                # Preserve a real connected session with an incomplete frame;
                # immediate signal shutdown must revoke it without completing RX.
                stream.sendall(query[:3])
                process.send_signal(signal.SIGTERM)
                process.wait(timeout=5)
                check(label + '-SIGTERM-success', process.returncode == 0, process.returncode)
                check(label + '-existing-stream-EOF', stream.recv(1) == b'')
                if inherited:
                    check(label + '-inherited-path-retained', path.exists())
                    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    probe.settimeout(2)
                    parent.settimeout(2)
                    try:
                        probe.connect(str(path))
                        accepted, _ = parent.accept()
                        accepted.close()
                        check(label + '-parent-listener-still-accepts', True)
                    finally:
                        probe.close()
                    check(label + '-invalid-config-path-never-created', not configured.exists())
                else:
                    check(label + '-created-path-removed', not path.exists())
            finally:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        report['cleanup_forced_kill'] = True
                if stream is not None:
                    stream.close()
                if parent is not None:
                    parent.close()
                    path.unlink(missing_ok=True)
                stdout.close()
                stderr.close()
        one('configured')
        one('inherited', True)
        check('fresh-and-executed-binaries-unchanged', sha(built) == digest and sha(snapshot) == digest)
        check('all-source-and-real-machine-file-inputs-unchanged', all(sha(p) == h for p, h in before.items()))
        report['status'] = 'passed'
        report['inputs_unchanged'] = True
    except Exception as exc:
        report['failure'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        if owned is not None:
            shutil.rmtree(owned)
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'status': report['status'], 'checks': len(report['checks']), 'result': str(output / 'result.json'), 'failure': report.get('failure')}))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
