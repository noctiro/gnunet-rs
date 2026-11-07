#!/usr/bin/env python3
"""Exec-only process-local FD/credential observations, with unchanged C service.
Every fd belongs to this runner or its new child. No system account, host DNS or
external service is changed. Distinguish paired C/Rust from Rust safety cases.
"""
import argparse, hashlib, json, os, pathlib, pwd, subprocess
from _common import require_disjoint_output, workspace_root, validated_build, unchanged, normal_reference, require_rust_fixture_success

def sha(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--package', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    ap.add_argument('--rust', type=pathlib.Path, required=True)
    ap.add_argument('--rust-sha256', required=True)
    ap.add_argument('--c-build', type=pathlib.Path, required=True)
    ap.add_argument('--component-build', type=pathlib.Path, required=True)
    ap.add_argument('--output', type=pathlib.Path, required=True)
    a = ap.parse_args()
    require_disjoint_output(a.output, [workspace_root(a.package), a.c_build.resolve().parent, a.component_build.resolve().parent, pathlib.Path(__file__).resolve().parent])
    a.output.mkdir(exist_ok=False)
    out = a.output
    build = validated_build(a.c_build)
    component = validated_build(a.component_build)
    assert sha(a.rust) == a.rust_sha256, 'Rust binary mismatch before processes'
    references_before = [normal_reference(row['normal_reference_receipt'], row['normal_reference_source']) for row in (build, component)]
    component_binary = pathlib.Path(component['binary']['path'])
    c = pathlib.Path(build['binary']['path'])
    env = {k: v for (k, v) in os.environ.items() if not k.startswith(('GNUNET_', 'LISTEN_'))}
    env.update(build['runtime_environment'], LC_ALL='C')
    base = out / 'base'
    base.mkdir()
    env['GNUNET_BASE_CONFIG'] = str(base)
    r = {'status': 'failed', 'scope': 'exec-child primitive receipts, not a completed generic service CLI/daemonizer', 'cases': [], 'paired': [], 'runtime_environment': build['runtime_environment'], 'c_build': {'path': str(a.c_build), 'sha256': sha(a.c_build)}, 'binaries': {str(p): sha(p) for p in (a.rust, c, component_binary)}, 'component_build': {'path': str(a.component_build), 'sha256': sha(a.component_build)}, 'components': [], 'parent_identity': [os.getuid(), os.geteuid(), os.getgid(), os.getegid()]}
    before = {str(p): sha(p) for p in list((a.package / 'src').rglob('*.rs')) + list((a.package / 'tools').glob('*.*')) + list((a.package / 'examples').glob('*.rs')) + [a.package / 'Cargo.toml', a.package / 'Cargo.lock'] if p.is_file()}
    r['inputs'] = before

    def call(label, kind, argv, fdmode=None, extra_env=None, control=False, control_alias=False, alias_fd=None):
        proc = None
        directory = out / label
        directory.mkdir()
        result = directory / 'observation.json'
        parent_read = None
        created = []
        passfds = []
        kwargs = {'stdin': subprocess.DEVNULL, 'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE}
        environment = env.copy()
        offered = []
        try:
            if fdmode is not None:
                (parent_read, w) = os.pipe()
                created.extend([parent_read, w])
                target = fdmode if isinstance(fdmode, int) else 128
                if target < 3:
                    kwargs[['stdin', 'stdout', 'stderr'][target]] = w
                    offered = [target]
                else:
                    try:
                        os.fstat(target)
                    except OSError:
                        pass
                    else:
                        raise RuntimeError('refuse replacing an existing runner fd')
                    os.dup2(w, target, inheritable=True)
                    created.append(target)
                    passfds.append(target)
                    offered = [target]
                environment.update(LISTEN_FDS='1', LISTEN_FDNAMES=str(target))
            if alias_fd is not None:
                try:
                    os.fstat(alias_fd)
                except OSError:
                    pass
                else:
                    raise RuntimeError('refuse replacing existing alias fd')
                assert offered and offered[0] >= 3
                os.dup2(offered[0], alias_fd, inheritable=True)
                created.append(alias_fd)
                passfds.append(alias_fd)
                offered.append(alias_fd)
                environment.update(LISTEN_FDS='2', LISTEN_FDNAMES=':'.join(map(str, offered)))
            if control:
                (read, write) = os.pipe()
                created.extend([read, write])
                target = 160
                try:
                    os.fstat(target)
                except OSError:
                    pass
                else:
                    raise RuntimeError('control target already open')
                os.dup2(read, target, inheritable=True)
                created.append(target)
                passfds.append(target)
                os.write(write, b'\xff')
                environment['GNUNET_OS_CONTROL_PIPE'] = 'a0zz'
            if control_alias:
                environment['GNUNET_OS_CONTROL_PIPE'] = '80'
            if extra_env:
                environment.update(extra_env)
            assert unchanged(r['binaries']), 'binary changed before child'
            command = [str(x).replace('{OUTPUT}', str(result)) for x in argv]
            proc = subprocess.Popen(command, env=environment, pass_fds=tuple(passfds), **kwargs)
            for fd in created.copy():
                if fd != parent_read:
                    os.close(fd)
                    created.remove(fd)
            (stdout, stderr) = proc.communicate(timeout=8)
            assert unchanged(r['binaries']), 'binary changed after child'
            (directory / 'stdout').write_bytes(stdout or b'')
            (directory / 'stderr').write_bytes(stderr or b'')
            eof = None
            pipe_data = b''
            if parent_read is not None:
                os.set_blocking(parent_read, False)
                while True:
                    try:
                        data = os.read(parent_read, 65536)
                    except BlockingIOError:
                        break
                    if not data:
                        eof = True
                        break
                    pipe_data += data
            if kind == 'rust':
                observation = json.loads(result.read_text())
            else:
                observation = [json.loads(line) for line in result.read_text().splitlines()]
            row = {'label': label, 'kind': kind, 'argv': command, 'exit_code': proc.returncode, 'observation': observation, 'actual_pipe_eof': eof, 'pipe_bytes_hex': pipe_data.hex(), 'offered': offered}
            r['cases'].append(row)
            return row
        finally:
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=5)
            for fd in created:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def rust(label, action, *args, **kw):
        return require_rust_fixture_success(call(label, 'rust', [a.rust, action, '{OUTPUT}', *args], **kw))

    def normal(label, mode, config, **kw):
        return call(label, 'normal-C', [c, '{OUTPUT}', mode, config], **kw)

    def cfg(name, user=None, bad=False):
        directory = out / name
        directory.mkdir()
        p = directory / 'probe.conf'
        p.write_text('[probe]\nUNIXPATH = ' + str(directory / 's.sock') + '\nPORT = ' + ('70000' if bad else '0') + '\nUNIX_MATCH_UID = NO\nUNIX_MATCH_GID = NO\n' + ('USERNAME = ' + user + '\n' if user is not None else ''))
        return p

    def pair(label, rustrow, crow, check):
        assert check(rustrow, crow), (rustrow, crow)
        r['paired'].append({'label': label, 'rust': rustrow['label'], 'normal_C': crow['label'], 'passed': True})
    try:
        good = cfg('configured-good')
        bad = cfg('configured-bad', bad=True)
        for status in ('.', 'I', 'S'):
            row = rust('ready-' + str(ord(status)), 'ready', status)
            assert row['observation'] == {'ok': True, 'bytes': [ord(status)], 'released_fd_closed': True}
        row = rust('ready-EPIPE', 'ready-error', '.')
        assert not row['observation']['ok'] and row['observation']['released_fd_closed'] and (row['observation']['errno'] != 0)
        for fd in (0, 1, 2, 128):
            row = rust('close-stdio-' + str(fd), 'abort', fdmode=fd)
            assert row['observation']['released'] == 1 and row['observation']['stdio_open'] == [True, True, True] and (fd >= 3 or row['observation']['stdio_null'][fd]) and row['actual_pipe_eof'] and (not row['pipe_bytes_hex'])
        row = rust('close-distinct-fds-same-pipe', 'abort', fdmode=128, alias_fd=192)
        assert row['observation']['released'] == 2 and row['actual_pipe_eof']
        row = rust('original-CLOEXEC-refused', 'original-cloexec', fdmode=128)
        assert not row['observation']['ok'] and row['observation']['original_128_still_open'] and row['actual_pipe_eof']
        row = rust('fd-reuse', 'reuse', '128', fdmode=128)
        assert row['observation']['reused'] and row['observation']['replacement_open']
        row = rust('once-only', 'twice', fdmode=128)
        assert row['observation']['second_rejected'] and row['actual_pipe_eof']
        for (label, extra) in [('duplicate', {'LISTEN_FDS': '2', 'LISTEN_FDNAMES': '128:128'}), ('missing', {'LISTEN_FDS': '2', 'LISTEN_FDNAMES': '128'}), ('closed-second', {'LISTEN_FDS': '2', 'LISTEN_FDNAMES': '128:192'})]:
            row = rust(label, 'abort', fdmode=128, extra_env=extra)
            assert not row['observation']['ok'] and row['observation']['original_128_still_open'] and row['actual_pipe_eof']
        row = rust('control-alias-refused', 'abort', fdmode=128, control_alias=True)
        assert not row['observation']['ok'] and row['observation']['original_128_still_open'] and row['actual_pipe_eof']
        row = rust('control-original-prefix-signed-byte', 'control', control=True)
        assert row['observation'] == {'ok': True, 'signal': -1}
        row = rust('control-plus-close-separate-owners', 'control', fdmode=128, control=True)
        assert row['observation']['signal'] == -1 and row['actual_pipe_eof']
        box = call('normal-C-box-pipe', 'normal-C', [c, '{OUTPUT}', 'box', '128'], fdmode=128)
        abort = rust('rust-box-equivalent-pipe', 'abort', fdmode=128)
        pair('normal box accepts actual pipe and closes it', abort, box, lambda x, y: x['actual_pipe_eof'] and y['actual_pipe_eof'] and (y['exit_code'] == 0) and (y['observation'][0]['event'] == 'box-closed'))
        rb = rust('rust-bind', 'bind', good, fdmode=128)
        cb = normal('normal-bind', 'close', good, fdmode=128)
        pair('close-after-real-configured-bind', rb, cb, lambda x, y: x['observation']['ok'] and x['observation']['phase'] == 'OwnListenersBound' and (y['exit_code'] == 0) and any((t['event'] == 'init' and (not t['tracked_fd_open']) for t in y['observation'])) and x['actual_pipe_eof'] and y['actual_pipe_eof'])
        rb = rust('rust-bind-refusal', 'bind', bad, fdmode=128)
        cb = normal('normal-bind-refusal', 'close', bad, fdmode=128)
        pair('failed-own-bind-closes-child-ownership-without-init', rb, cb, lambda x, y: not x['observation']['ok'] and x['observation']['phase'] == 'Aborted' and (y['exit_code'] != 0) and (not any((t['event'] == 'init' and (not t['tracked_fd_open']) for t in y['observation']))) and x['actual_pipe_eof'] and y['actual_pipe_eof'])
        absent = rust('rust-user-absent', 'privilege', '-')
        native_absent = normal('normal-user-absent', 'close', good, fdmode=128)
        pair('no-USERNAME-keeps-identity', absent, native_absent, lambda x, y: x['observation']['route'] == 'unchanged' and x['observation']['before'] == x['observation']['after'] == y['observation'][-1]['ids'] and (y['exit_code'] == 0))
        account = pwd.getpwuid(os.getuid())
        assert account.pw_uid == os.getuid() and account.pw_gid == os.getgid(), 'only the current uid/gid may be applied in these tests'
        username = account.pw_name
        usercfg = cfg('configured-current-user', username)
        current = rust('rust-user-current-direct-native', 'privilege', username)
        native_current = normal('normal-user-current-config-refuses', 'close', usercfg, fdmode=128)
        assert current['observation']['ok'] and current['observation']['after'] == r['parent_identity']
        configured = rust('rust-user-current-config-refuses', 'bind-user', usercfg, fdmode=128)
        pair('normal-USERNAME-filename-expansion-preserves-current-name-refusal', configured, native_current, lambda x, y: not x['observation']['ok'] and x['observation']['user_failed'] and (x['observation']['ids'] == r['parent_identity'] == y['observation'][-1]['ids']) and (y['exit_code'] != 0) and (not any((t['event'] == 'init' for t in y['observation']))))
        observed = subprocess.run([str(component_binary), username], env=env, capture_output=True, timeout=8)
        (out / 'component-current.stdout').write_bytes(observed.stdout)
        (out / 'component-current.stderr').write_bytes(observed.stderr)
        assert unchanged(r['binaries']), 'binary changed around original-C component'
        native = json.loads(observed.stdout)
        assert observed.returncode == 0 and native['result'] == 1 and (native['ids'] == r['parent_identity'])
        primary = ['SetGid', 'SetEffectiveGid', 'InitGroups', 'SetUid', 'SetEffectiveUid']
        route = current['observation']['route']
        failed = current['observation']['primary_failed']
        expected = primary if route == 'primary' else primary[:primary.index(failed) + 1] + ['SetBothGid', 'SetBothUid']
        assert native['calls'] == expected, (native, current)
        r['components'].append({'label': 'original-set_user_id-current-native-sequence', 'kind': 'extracted-full-function-body-with-one-declared-name-port', 'normal_configuration_success': False, 'argv': [str(component_binary), username], 'exit_code': observed.returncode, 'observation': native, 'rust': current['label'], 'expected_sequence': expected, 'passed': True})
        no_groups = rust('rust-user-current-explicit-no-initgroups', 'privilege', username, 'no-initgroups')
        assert no_groups['observation']['ok'] and no_groups['observation']['after'] == r['parent_identity'] and (not no_groups['observation']['groups_initialized'])
        no_groups['alternate_profile_not_normal_C'] = True
        missing = 'gnunet-startup-audit-no-such-user-' + str(os.getpid())
        missingcfg = cfg('configured-missing-user', missing)
        missing_r = rust('rust-user-missing', 'privilege', missing)
        missing_c = normal('normal-user-missing', 'close', missingcfg, fdmode=128)
        pair('unknown-user-fails-with-original-identity', missing_r, missing_c, lambda x, y: not x['observation']['ok'] and x['observation']['lookup_failed'] and (x['observation']['after'] == r['parent_identity'] == y['observation'][-1]['ids']) and (y['exit_code'] != 0))
        rb = rust('rust-CLOSE-before-user-failure', 'bind-user', missingcfg, fdmode=128)
        pair('CLOSE-EOF-is-not-full-startup-success', rb, missing_c, lambda x, y: not x['observation']['ok'] and x['observation']['phase'] == 'OwnListenersBound' and x['observation']['user_failed'] and x['actual_pipe_eof'] and y['actual_pipe_eof'] and (not any((t['event'] == 'init' for t in y['observation']))))
        daemon = call('normal-daemon-reference-only', 'normal-C', [c, '{OUTPUT}', 'close', good, 'daemon'], fdmode=128)
        assert daemon['exit_code'] == 0
        daemon['reference_only_not_Rust_daemonization'] = True
        r['parent_identity_unchanged'] = [os.getuid(), os.geteuid(), os.getgid(), os.getegid()] == r['parent_identity']
        r['inputs_unchanged'] = all((sha(p) == h for (p, h) in before.items()))
        r['normal_C_inputs_unchanged'] = all((sha(p) == h for (p, h) in build['inputs'].items()))
        r['component_inputs_unchanged'] = all((sha(p) == h for (p, h) in component['inputs'].items()))
        assert r['parent_identity_unchanged'] and r['inputs_unchanged'] and r['normal_C_inputs_unchanged'] and r['component_inputs_unchanged']
        references_after = [normal_reference(row['normal_reference_receipt'], row['normal_reference_source']) for row in (build, component)]
        r['normal_reference_unchanged'] = references_after == references_before
        assert r['normal_reference_unchanged']
        r['binaries_unchanged'] = unchanged(r['binaries'])
        assert r['binaries_unchanged']
        assert len(r['cases']) == 34 and len({row['label'] for row in r['cases']}) == 34 and (len(r['paired']) == 7) and (len(r['components']) == 1) and all((row['passed'] for row in r['paired'] + r['components']))
        r['status'] = 'passed'
    except Exception as e:
        r['failure'] = type(e).__name__ + ': ' + str(e)
    (out / 'result.json').write_text(json.dumps(r, indent=2) + '\n')
    print(json.dumps({'status': r['status'], 'exec_cases': len(r['cases']), 'paired_normal_C': len(r['paired']), 'source_components': len(r['components']), 'result': str(out / 'result.json'), 'failure': r.get('failure')}))
    return 0 if r['status'] == 'passed' else 1
if __name__ == '__main__':
    raise SystemExit(main())
