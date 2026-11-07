#!/usr/bin/env python3
"""Fresh C/R broker actors versus an unmodified, IP-sandboxed normal C Resolver."""
import argparse, hashlib, json, os, pathlib, shutil, signal, subprocess, sys, tempfile, time
from paired import sha

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--c-build', type=pathlib.Path, required=True)
    p.add_argument('--rust-binary', type=pathlib.Path, required=True)
    p.add_argument('--normal-base', type=pathlib.Path, required=True)
    p.add_argument('--normal-resolver', type=pathlib.Path, required=True)
    p.add_argument('--source', type=pathlib.Path, required=True)
    p.add_argument('--reference-helper', type=pathlib.Path, required=True)
    p.add_argument('--sandbox', type=pathlib.Path, required=True)
    p.add_argument('--output', type=pathlib.Path, required=True)
    a = p.parse_args()
    a.output = a.output.resolve()
    a.output.mkdir(exist_ok=False, parents=True)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(a.reference_helper.resolve().parent))
    from build_reference import source_state
    c = json.loads(a.c_build.read_text())
    client = json.loads(pathlib.Path(c['normal_receipt']).read_text())
    base = json.loads(a.normal_base.read_text())
    ref = json.loads(a.normal_resolver.read_text())
    if not c['status'] == base['status'] == ref['status'] == 'passed':
        raise ValueError('required condition failed at original line 8')
    if not (ref['source_unchanged'] and base['source_unchanged'] and ref['base_files_unchanged']):
        raise ValueError('required condition failed at original line 8')
    if not sha(a.normal_base) == ref['base_receipt_sha256']:
        raise ValueError('required condition failed at original line 8')
    if not source_state(a.source) == ref['upstream'] == base['upstream'] == c['upstream']:
        raise ValueError('required condition failed at original line 8')
    if not ref['upstream']['revision'] == '346358e26d4dcc2dc4f51bef5d52dca29c7d8165':
        raise ValueError('required condition failed at original line 8')
    if not pathlib.Path(base['source']).resolve() == a.source.resolve():
        raise ValueError('required condition failed at original line 8')
    inputs = dict(c['inputs'])
    inputs.update({c['binary']['path']: c['binary']['sha256']})
    rows = [*base['artifacts'].values(), *base['libraries'], *base['default_configurations'], *ref['artifacts'].values(), base['generated_config']]
    for row in rows:
        if not sha(row['path']) == row['sha256']:
            raise ValueError(row['path'])
        inputs[row['path']] = row['sha256']
    for path in [a.c_build, a.rust_binary, a.normal_base, a.normal_resolver, a.sandbox, a.reference_helper, pathlib.Path(__file__).resolve(), pathlib.Path(__file__).with_name('paired.py'), pathlib.Path('/etc/hosts')]:
        inputs[str(path.resolve())] = sha(path)
    if not any((line.split('#', 1)[0].split()[:2] == ['255.255.255.255', 'broadcasthost'] for line in pathlib.Path('/etc/hosts').read_text().splitlines())):
        raise ValueError('expected local hosts fixture absent')
    for (path, digest) in inputs.items():
        if not sha(path) == digest:
            raise ValueError(path)
    run = pathlib.Path(tempfile.mkdtemp(prefix='rbreal-'))
    run.chmod(448)
    config = run / 'c'
    sock = run / 'r'
    empty = run / 'base'
    empty.mkdir()
    config.write_text('[resolver]\nUNIXPATH = ' + str(sock) + '\nHOSTNAME = localhost\nPORT = 0\nSTART_ON_DEMAND = NO\nUNIX_MATCH_UID = NO\nUNIX_MATCH_GID = NO\n')
    result = {'status': 'failed', 'scope': 'Two concurrent shared forward requests through actual unmodified normal C Resolver, local hosts-only broadcasthost, IP output denied; no full owner completion', 'inputs': inputs, 'upstream': base['upstream'], 'cases': []}
    daemon = None
    logs = []
    try:
        clean = {k: v for (k, v) in os.environ.items() if not k.startswith('GNUNET_')}
        clean.update(GNUNET_BASE_CONFIG=str(empty), LC_ALL='C')
        denial = "import socket,errno\nfor f,a in [(socket.AF_INET,('127.0.0.1',9)),(socket.AF_INET6,('::1',9))]:\n s=socket.socket(f,socket.SOCK_DGRAM)\n try:s.sendto(b'owned-denial-check',a)\n except OSError as e:\n  if e.errno!=errno.EPERM:raise SystemExit(4)\n  print(f,e.errno)\n else:raise SystemExit(3)\n s.close()\n"
        probe = subprocess.run(['/usr/bin/sandbox-exec', '-f', str(a.sandbox), sys.executable, '-c', denial], env=clean, capture_output=True, timeout=5)
        if not probe.returncode == 0:
            raise ValueError(probe.stderr)
        result['ip_denial'] = {'exit_code': probe.returncode, 'stdout': probe.stdout.decode()}
        service = ref['artifacts']['service']
        if not sha(service['built_path']) == service['sha256']:
            raise ValueError('required condition failed at original line 20')
        inputs[service['built_path']] = service['sha256']
        daemon_env = clean.copy()
        daemon_env.update(base['runtime_environment'])
        restore = [k + '=' + v for (k, v) in base['runtime_environment'].items()]
        argv = ['/usr/bin/sandbox-exec', '-f', str(a.sandbox), '/usr/bin/env', *restore, service['built_path'], '-c', str(config), '-L', 'DEBUG']
        for kind in ['stdout', 'stderr']:
            logs.append((a.output / ('daemon.' + kind)).open('wb'))
        daemon = subprocess.Popen(argv, env=daemon_env, stdin=subprocess.DEVNULL, stdout=logs[0], stderr=logs[1])
        result['daemon'] = {'argv': argv, 'pid': daemon.pid}
        until = time.monotonic() + 6
        while not sock.exists():
            if not daemon.poll() is None:
                raise ValueError('normal daemon exited before readiness')
            if not time.monotonic() < until:
                raise ValueError('readiness timeout')
            time.sleep(0.01)
        result['daemon']['ready'] = True
        for (language, binary) in [('c', pathlib.Path(c['binary']['path'])), ('rust', a.rust_binary)]:
            env = clean.copy()
            env.update(client['runtime_environment'])
            argv = ['/usr/bin/sandbox-exec', '-f', str(a.sandbox), str(binary), str(config), 'hosts']
            actor = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                (stdout, stderr) = actor.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                actor.kill()
                actor.communicate()
                raise
            (a.output / (language + '.stdout')).write_bytes(stdout)
            (a.output / (language + '.stderr')).write_bytes(stderr)
            lines = stdout.decode().splitlines()
            row = {'language': language, 'argv': argv, 'pid': actor.pid, 'exit_code': actor.returncode, 'trace': lines}
            result['cases'].append(row)
            if not actor.returncode == 0:
                raise ValueError((language, actor.returncode, stderr.decode(errors='replace')[-3000:]))
            if not lines == ['ADDR|1|255.255.255.255', 'END|1', 'ADDR|2|255.255.255.255', 'END|2']:
                raise ValueError((language, lines))
        daemon.send_signal(signal.SIGTERM)
        daemon.wait(timeout=5)
        result['daemon']['exit_code'] = daemon.returncode
        if not daemon.returncode == 0:
            raise ValueError('required condition failed at original line 32')
        result['inputs_unchanged'] = all((sha(path) == digest for (path, digest) in inputs.items()))
        result['source_unchanged'] = source_state(a.source) == base['upstream']
        if not (result['inputs_unchanged'] and result['source_unchanged']):
            raise ValueError('required condition failed at original line 33')
        result.update(status='passed', paired_profiles=1, actual_client_actors=2, actual_normal_daemons=1)
    except Exception as e:
        result['failure'] = type(e).__name__ + ': ' + str(e)
        raise
    finally:
        if daemon is not None and daemon.poll() is None:
            daemon.terminate()
            try:
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()
                result['forced_kill_cleanup'] = True
        for f in logs:
            f.close()
        shutil.rmtree(run)
        result['runtime_removed'] = not run.exists()
        (a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'result': str(a.output / 'result.json')}))
if __name__ == '__main__':
    main()
