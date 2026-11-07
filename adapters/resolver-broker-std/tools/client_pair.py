#!/usr/bin/env python3
"""Actual generic CLIENT -> shared Resolver -> owned TCP service lifecycle pair."""
import argparse, asyncio, json, os, pathlib, shutil, socket, struct, tempfile
from paired import sha, frame, decode, reply

async def actor(binary, language, env, out):
    runtime = pathlib.Path(tempfile.mkdtemp(prefix='rbclient-'))
    runtime.chmod(448)
    path = runtime / 'r'
    config = runtime / 'c'
    base = runtime / 'base'
    base.mkdir()
    trace = []
    dns = []
    tcp = []
    tasks = []
    errors = []
    first = asyncio.Event()
    dns_end = asyncio.Event()

    async def dns_connection(reader, writer):
        rows = []
        dns.append(rows)
        try:
            request = decode(await asyncio.wait_for(frame(reader), 3))
            if not bytes.fromhex(request['data']) == b'owned-service\x00':
                raise ValueError('required condition failed at original line 10')
            rows.append({'request': request})
            writer.write(reply(request['id'], socket.inet_pton(socket.AF_INET, '127.0.0.1')))
            await writer.drain()
            rows.append({'send': 'address-127.0.0.1'})
            await asyncio.wait_for(first.wait(), 3)
            writer.write(reply(request['id'], socket.inet_pton(socket.AF_INET, '127.0.0.1')))
            await writer.drain()
            rows.append({'send': 'duplicate-address-after-TCP-success'})
            await asyncio.sleep(0.03)
            if not len(tcp) == 1:
                raise ValueError('unexpected second TCP probe after success')
            writer.write(reply(request['id']))
            await writer.drain()
            rows.append({'send': 'actual-end'})
            if not await asyncio.wait_for(reader.read(), 3) == b'':
                raise ValueError('required condition failed at original line 16')
            rows.append({'eof': True})
            dns_end.set()
        except Exception as e:
            errors.append('dns ' + type(e).__name__ + ': ' + str(e))
            dns_end.set()
        finally:
            writer.close()
            await writer.wait_closed()

    async def tcp_connection(reader, writer):
        rows = []
        tcp.append(rows)
        try:
            if not len(tcp) == 1:
                raise ValueError('additional TCP connection after successful probe')
            data = await asyncio.wait_for(frame(reader), 3)
            if not data == b'\x00\x04\x00\x00':
                raise ValueError('required condition failed at original line 23')
            rows.append({'received': data.hex()})
            writer.write(data)
            await writer.drain()
            rows.append({'send': data.hex()})
            first.set()
            await asyncio.wait_for(dns_end.wait(), 4)
            if not not errors:
                raise ValueError(errors)
            writer.write(data)
            await writer.drain()
            rows.append({'send-after-DNS-END': data.hex()})
            if not await asyncio.wait_for(reader.read(), 3) == b'':
                raise ValueError('required condition failed at original line 26')
            rows.append({'eof': True})
        except Exception as e:
            errors.append('tcp ' + type(e).__name__ + ': ' + str(e))
            first.set()
        finally:
            writer.close()
            await writer.wait_closed()

    def spawn(fn):

        def accept(r, w):
            tasks.append(asyncio.create_task(fn(r, w)))
        return accept
    resolver = await asyncio.start_unix_server(spawn(dns_connection), path=str(path))
    service = await asyncio.start_server(spawn(tcp_connection), '127.0.0.1', 0)
    port = service.sockets[0].getsockname()[1]
    config.write_text('[resolver]\nUNIXPATH = ' + str(path) + '\nHOSTNAME = localhost\nPORT = 0\n[owned]\nHOSTNAME = owned-service\nPORT = ' + str(port) + '\n')
    child_env = {k: v for (k, v) in env.items() if not k.startswith('GNUNET_')}
    child_env['GNUNET_PREFIX'] = env['GNUNET_PREFIX']
    child_env.update(GNUNET_BASE_CONFIG=str(base), LC_ALL='C')
    argv = [str(binary), str(config), 'client']
    proc = await asyncio.create_subprocess_exec(*argv, env=child_env, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        (stdout, stderr) = await asyncio.wait_for(proc.communicate(), 9)
        await asyncio.wait_for(asyncio.gather(*tasks), 4)
        trace = stdout.decode().splitlines()
        (out / (language + '.stdout')).write_bytes(stdout)
        (out / (language + '.stderr')).write_bytes(stderr)
        (out / (language + '.graphs.json')).write_text(json.dumps({'trace': trace, 'dns': dns, 'tcp': tcp, 'errors': errors}, indent=2) + '\n')
        if not proc.returncode == 0:
            raise ValueError((language, proc.returncode, stderr.decode(errors='replace')[-2500:]))
        if not not errors:
            raise ValueError(errors)
        if not trace == ['SERVICE|1', 'SERVICE|2']:
            raise ValueError('required condition failed at original line 37')
        if not len(dns) == len(tcp) == 1:
            raise ValueError('required condition failed at original line 37')
        return {'language': language, 'argv': argv, 'pid': proc.pid, 'exit_code': proc.returncode, 'trace': trace, 'dns_connections': dns, 'tcp_connections': tcp, 'semantic_checks': ['service-connected-before-DNS-END', 'post-success-address-ignored', 'one-shared-resolver-MQ', 'actual-DNS-END-before-resolver-EOF', 'service-stream-usable-after-DNS-END', 'independent-service-Drop-EOF']}
    finally:
        if proc.returncode is None:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), 3)
        resolver.close()
        service.close()
        await resolver.wait_closed()
        await service.wait_closed()
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        shutil.rmtree(runtime)

async def main(a):
    a.output = a.output.resolve()
    a.output.mkdir(exist_ok=False, parents=True)
    c = json.loads(a.c_build.read_text())
    r = json.loads(pathlib.Path(c['normal_receipt']).read_text())
    if not c['status'] == 'passed':
        raise ValueError('required condition failed at original line 46')
    inputs = dict(c['inputs'])
    inputs.update({str(a.c_build.resolve()): sha(a.c_build), str(a.rust_binary.resolve()): sha(a.rust_binary), str(pathlib.Path(c['binary']['path'])): c['binary']['sha256']})
    for p in [pathlib.Path(__file__).resolve(), pathlib.Path(__file__).with_name('paired.py')]:
        inputs[str(p)] = sha(p)
    for (p, h) in inputs.items():
        if not sha(p) == h:
            raise ValueError(p)
    env = os.environ.copy()
    env.update(r['runtime_environment'])
    result = {'status': 'failed', 'scope': 'Actual normal C GNUNET_CLIENT_connect and Rust shared broker against owned Unix resolver peer plus loopback TCP service; literal peer, not daemon', 'inputs': inputs, 'cases': []}
    try:
        for (language, binary) in [('c', pathlib.Path(c['binary']['path'])), ('rust', a.rust_binary)]:
            result['cases'].append(await actor(binary, language, env, a.output))
        (left, right) = result['cases']
        if not (left['trace'] == right['trace'] and left['dns_connections'] == right['dns_connections'] and (left['tcp_connections'] == right['tcp_connections'])):
            raise ValueError('required condition failed at original line 52')
        result['inputs_unchanged'] = all((sha(p) == h for (p, h) in inputs.items()))
        if not result['inputs_unchanged']:
            raise ValueError('required condition failed at original line 52')
        result.update(status='passed', paired_profiles=1, actual_actors=2)
    except Exception as e:
        result['failure'] = type(e).__name__ + ': ' + str(e)
        raise
    finally:
        (a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'result': str(a.output / 'result.json')}))
if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--c-build', type=pathlib.Path, required=True)
    p.add_argument('--rust-binary', type=pathlib.Path, required=True)
    p.add_argument('--output', type=pathlib.Path, required=True)
    asyncio.run(main(p.parse_args()))
