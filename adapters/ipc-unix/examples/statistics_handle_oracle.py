#!/usr/bin/env python3
"""Run the high-level Rust handle against an unchanged normal C daemon.

The restart case injects SIGKILL into one explicitly owned daemon after a PID
ready file. It is a crash/reconnect test, not a graceful-exit or durability claim.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sys
import tempfile
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools/reference'))
from statistics_daemons import Harness, REVISION, config, digest, save, signal_owned, snapshot, source_state


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--reference', required=True, type=Path)
    p.add_argument('--rust', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    output = a.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema': 1, 'kind': 'official-c-statistics-high-level-rust-handle',
              'status': 'failed', 'scope': 'Queued Rust STATISTICS handle against actual normal C service and CLI. Explicit injected daemon crash; no whole peer or crash durability claim.'}
    h = None
    owned = None
    try:
        receipt = json.loads(a.reference.read_text())
        if receipt.get('status') != 'passed' or receipt.get('kind') != 'unmodified-official-c-reference-build' or receipt['upstream']['revision'] != REVISION:
            raise ValueError('normal pinned reference receipt required')
        source_before = source_state(Path(receipt['source']))
        if source_before != receipt['upstream']:
            raise ValueError('reference source changed since normal build')
        reference_inputs = [*receipt['artifacts'].values(), *receipt['libraries'], *receipt['default_configurations']]
        for row in reference_inputs:
            if digest(row['path']) != row['sha256']:
                raise ValueError('reference file changed: ' + row['path'])
        names = ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
                 'adapters/ipc-unix/examples/statistics_handle_oracle.py',
                 'tools/reference/statistics_daemons.py', 'tools/reference/build_reference.py']
        for directory in ['adapters/ipc-unix', 'adapters/config-std', 'crates/gnunet-client',
                          'crates/gnunet-statistics', 'crates/gnunet-crypto',
                          'crates/gnunet-types', 'crates/gnunet-wire']:
            for path in (ROOT / directory).rglob('*'):
                if path.is_symlink():
                    raise ValueError('proof input contains a symbolic link: ' + str(path))
                if path.is_file() and path.suffix in {'.rs', '.toml'} and not {'target', '__pycache__'} & set(path.relative_to(ROOT).parts):
                    names.append(str(path.relative_to(ROOT)))
        names = sorted(set(names))
        report['rust_sources_sha256'] = {name: digest(ROOT / name) for name in names}
        report['reference_receipt'] = {'path': str(a.reference.resolve()), 'sha256': digest(a.reference)}
        report['upstream'] = receipt['upstream']
        binaries = output / 'binaries'
        binaries.mkdir()
        participants = {'rust_handle': a.rust.resolve(), 'c_service': Path(receipt['artifacts']['service']['path']), 'c_client': Path(receipt['artifacts']['client']['path'])}
        active = {name: snapshot(path, binaries, name) for name, path in participants.items()}
        report['participants'] = {name: {'original': str(path), 'snapshot': str(active[name]), 'sha256': digest(path)} for name, path in participants.items()}
        env = {name: value for name, value in os.environ.items() if not name.startswith('GNUNET_')}
        env.update(receipt['runtime_environment'], LC_ALL='C')
        owned = Path(tempfile.mkdtemp(prefix='ghnd-', dir='/private/tmp'))
        owned.chmod(0o700)
        report['owned_runtime'] = str(owned)
        for name, relative in [('XDG_CONFIG_HOME', 'config'), ('XDG_DATA_HOME', 'data'), ('XDG_CACHE_HOME', 'cache'), ('XDG_RUNTIME_DIR', 'runtime')]:
            directory = owned / relative
            directory.mkdir(mode=0o700)
            env[name] = str(directory)
        h = Harness(output, env)
        report['commands'], report['checks'] = h.commands, h.checks
        conf, sock, database = owned / 'service.conf', owned / 's.sock', owned / 'stats.dat'
        config(conf, sock, database)
        shutil.copy2(conf, output / 'service.conf')
        service = h.start('c-service-roundtrip', [str(active['c_service']), '-c', str(conf), '-L', 'ERROR'])
        h.ready(service, sock)
        raw = h.command('rust-handle-roundtrip', [str(active['rust_handle']), 'roundtrip', str(conf)])
        rows = [json.loads(v) for v in raw.splitlines()]
        h.check('rust-roundtrip-high-level-lifecycle', rows == [{'case': 'roundtrip', 'passed': True, 'value': 43, 'cancelled_rows': 1, 'abort_rows': 1, 'destroy': 'ProcessingConfirmed', 'unconfirmed': 0}], rows)
        for name, value in [('counter', 43), ('barrier', 99)]:
            raw = h.command('c-observe-' + name, [str(active['c_client']), '-c', str(conf), '-L', 'ERROR', '-q', '-s', 'rust-handle-v0291', '-n', name])
            h.check('c-observe-' + name + '-exact-value', raw.strip() == str(value).encode(), raw.decode())
        raw = h.command('c-observe-zero-noop', [str(active['c_client']), '-c', str(conf), '-L', 'ERROR', '-q', '-s', 'rust-handle-v0291', '-n', 'zero-noop'])
        h.check('zero-update-created-no-row', raw == b'')
        h.finish(service)
        h.check('initial-graceful-dump-exists', database.is_file())
        # A prior graceful daemon saved these fixtures. The subsequent injected
        # crash does not claim that new mutations were flushed or durable.
        service = h.start('c-service-before-injected-crash', [str(active['c_service']), '-c', str(conf), '-L', 'ERROR'])
        h.ready(service, sock)
        ready = owned / 'restart.ready'
        probe = h.start('rust-handle-restart', [str(active['rust_handle']), 'restart', str(conf), str(ready)])
        limit = time.monotonic() + 5
        while not ready.exists():
            if probe['process'].poll() is not None:
                raise ValueError('restart probe exited before ready: ' + probe['err_path'].read_text())
            if time.monotonic() >= limit:
                raise TimeoutError('restart ready file')
            time.sleep(0.005)
        h.check('restart-ready-owned-pid', ready.read_text().strip() == str(probe['process'].pid))
        signal_owned(service['process'], signal.SIGKILL)
        code = service['process'].wait(timeout=5)
        service['row'].update(exit_code=code, injected_fault='SIGKILL only this owned daemon', expected_fault_exit=-signal.SIGKILL)
        h.close_logs(service)
        h.check('owned-daemon-crash-injected-and-reaped', code == -signal.SIGKILL)
        if sock.exists():
            sock.unlink()
        restarted = h.start('c-service-after-injected-crash', [str(active['c_service']), '-c', str(conf), '-L', 'ERROR'])
        h.ready(restarted, sock)
        probe['process'].wait(timeout=10)
        h.finish(probe)
        rows = [json.loads(v) for v in probe['out_path'].read_bytes().splitlines()]
        h.check('reconnect-watch-holes-remapped', rows == [
            {'case': 'restart-watch', 'name': 'b', 'wid': 0, 'value': 20},
            {'case': 'restart-watch', 'name': 'c', 'wid': 1, 'value': 30},
            {'case': 'restart', 'passed': True, 'cancelled_watch_suppressed': True, 'survivor_wid': 0, 'replacement_wid': 1}], rows)
        h.finish(restarted)
        # The Rust client config deliberately contains no UNIXPATH. The normal
        # C service still has its own Unix socket for the independent C CLI;
        # only the queued Rust owner must traverse the actual TCP endpoint.
        tcp_conf, tcp_sock, tcp_database = owned / 'tcp-service.conf', owned / 'tcp.sock', owned / 'tcp.dat'
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
            reserved.bind(('127.0.0.1', 0))
            tcp_port = reserved.getsockname()[1]
        config(tcp_conf, tcp_sock, tcp_database)
        tcp_conf.write_text(tcp_conf.read_text().replace('PORT = 0\n', f'PORT = {tcp_port}\n') + '\nBINDTO = 127.0.0.1\nDISABLEV6 = YES\n')
        tcp_client_conf = owned / 'tcp-client.conf'
        tcp_client_conf.write_text(f'[statistics]\nHOSTNAME = 127.0.0.1\nPORT = {tcp_port}\n')
        shutil.copy2(tcp_conf, output / 'tcp-service.conf')
        shutil.copy2(tcp_client_conf, output / 'tcp-client.conf')
        tcp_service = h.start('c-service-tcp-roundtrip', [str(active['c_service']), '-c', str(tcp_conf), '-L', 'ERROR'])
        h.ready(tcp_service, tcp_sock)
        raw = h.command('rust-handle-tcp-roundtrip', [str(active['rust_handle']), 'roundtrip', str(tcp_client_conf)])
        rows = [json.loads(value) for value in raw.splitlines()]
        h.check('rust-tcp-high-level-lifecycle', rows == [{'case': 'roundtrip', 'passed': True, 'value': 43, 'cancelled_rows': 1, 'abort_rows': 1, 'destroy': 'ProcessingConfirmed', 'unconfirmed': 0}], rows)
        for name, value in [('counter', 43), ('barrier', 99)]:
            raw = h.command('c-observe-tcp-' + name, [str(active['c_client']), '-c', str(tcp_conf), '-L', 'ERROR', '-q', '-s', 'rust-handle-v0291', '-n', name])
            h.check('c-observe-tcp-' + name + '-exact-value', raw.strip() == str(value).encode(), raw.decode())
        h.finish(tcp_service)
        h.check('tcp-graceful-dump-exists', tcp_database.is_file())
        report['rust_sources_unchanged'] = report['rust_sources_sha256'] == {name: digest(ROOT / name) for name in names}
        report['reference_source_unchanged'] = source_state(Path(receipt['source'])) == source_before
        report['reference_files_unchanged'] = all(digest(row['path']) == row['sha256'] for row in reference_inputs)
        report['participants_unchanged'] = all(digest(participants[name]) == digest(active[name]) == row['sha256'] for name, row in report['participants'].items())
        h.check('all-participants-and-proof-inputs-unchanged', all(report[k] for k in ('rust_sources_unchanged', 'reference_source_unchanged', 'reference_files_unchanged', 'participants_unchanged')))
        report['status'] = 'passed'
    except Exception as error:
        report['failure'] = type(error).__name__ + ': ' + str(error)
    finally:
        if h is not None:
            h.cleanup()
            report['executed_checks'] = len(h.checks)
            report['owned_processes_reaped'] = all(v['process'].poll() is not None for v in h.services)
        if owned is not None:
            shutil.rmtree(owned)
            report['owned_runtime_removed'] = not owned.exists()
        save(output / 'result.json', report)
    print(json.dumps({'status': report['status'], 'checks': report.get('executed_checks'), 'report': str(output / 'result.json'), 'failure': report.get('failure')}))
    return 0 if report['status'] == 'passed' else 1

if __name__ == '__main__':
    raise SystemExit(main())
