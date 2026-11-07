#!/usr/bin/env python3
"""Actual C/R public broker actors against finite owned literal Unix peers."""
import argparse, asyncio, hashlib, json, os, pathlib, shutil, socket, struct, tempfile, time

def sha(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

async def frame(reader):
    h = await reader.readexactly(4)
    (size, kind) = struct.unpack('!HH', h)
    if not size >= 4:
        raise ValueError('required condition failed at original line 7')
    return h + await reader.readexactly(size - 4)

def decode(data):
    (size, kind, direction, af) = struct.unpack('!HHII', data[:12])
    if not (size == len(data) and kind == 4):
        raise ValueError('required condition failed at original line 9')
    return {'hex': data.hex(), 'id': data[12:16].hex(), 'direction': direction, 'af': af, 'data': data[16:].hex()}

def reply(id, data=b'', kind=5):
    return struct.pack('!HH', 8 + len(data), kind) + bytes.fromhex(id) + data

async def case(binary, language, mode, env, out, sandbox):
    run = pathlib.Path(tempfile.mkdtemp(prefix='rbpair-'))
    run.chmod(448)
    sock = run / 'r'
    cfg = run / 'c'
    base = run / 'base'
    base.mkdir()
    cfg.write_text('[resolver]\nUNIXPATH = ' + str(sock) + '\nHOSTNAME = localhost\nPORT = 0\n')
    trace = []
    connections = []
    server = None
    errors = []
    tasks = []
    done = asyncio.Event()

    async def connection(reader, writer):
        index = len(connections)
        rows = []
        connections.append(rows)
        try:
            if mode in ('retry', 'reverse'):
                raw = await asyncio.wait_for(frame(reader), 3)
                row = decode(raw)
                rows.append({'request': row})
                if index == 0:
                    writer.write(struct.pack('!HH', 4, 65500))
                    await writer.drain()
                    rows.append({'send': 'unregistered-type-65500'})
                    writer.write(reply(row['id'], socket.inet_pton(socket.AF_INET, '192.0.2.1') if mode == 'retry' else bytes.fromhex('ff006100')))
                    await writer.drain()
                    rows.append({'send': 'address-192.0.2.1' if mode == 'retry' else 'raw-hostname-ff006100'})
                    writer.write(reply('78563412'))
                    await writer.drain()
                    rows.append({'send': 'unknown-id-78563412'})
                else:
                    writer.write((reply(row['id'], socket.inet_pton(socket.AF_INET6, '2001:db8::1')) if mode == 'retry' else b'') + reply(row['id']))
                    await writer.drain()
                    rows.extend(([{'send': 'address-2001:db8::1'}] if mode == 'retry' else []) + [{'send': 'end'}])
            else:
                names = [b'warm', b'instant-cancel', b'kept'] if mode == 'instant' else [b'expired', b'canceled', b'kept']
                for name in names:
                    raw = await asyncio.wait_for(frame(reader), 3)
                    row = decode(raw)
                    if not bytes.fromhex(row['data']) == name + b'\x00':
                        raise ValueError((mode, row))
                    rows.append({'request': row})
                    if name != b'expired':
                        writer.write(reply(row['id']))
                        await writer.drain()
                        rows.append({'send': 'end'})
            tail = await asyncio.wait_for(reader.read(), 3)
            if not tail == b'':
                raise ValueError('required condition failed at original line 30')
            rows.append({'eof': True})
        except Exception as e:
            errors.append(type(e).__name__ + ': ' + str(e))
        finally:
            writer.close()
            await writer.wait_closed()
            done.set()

    def accept(r, w):
        tasks.append(asyncio.create_task(connection(r, w)))

    async def listen():
        return await asyncio.start_unix_server(accept, path=str(sock))
    if mode not in ('orphan', 'stack'):
        server = await listen()
    child_env = {k: v for (k, v) in env.items() if not k.startswith('GNUNET_')}
    child_env.update({k: v for (k, v) in env.items() if k in ('GNUNET_PREFIX',)})
    child_env.update(GNUNET_BASE_CONFIG=str(base), LC_ALL='C')
    argv = [str(binary), str(cfg), mode]
    if sandbox:
        argv = ['/usr/bin/sandbox-exec', '-f', str(sandbox), *argv]
    started = time.monotonic()
    proc = await asyncio.create_subprocess_exec(*argv, env=child_env, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stderr_task = asyncio.create_task(proc.stderr.read())
    try:

        async def stdout():
            nonlocal server
            while True:
                data = await proc.stdout.readline()
                if not data:
                    return
                line = data.decode().rstrip('\n')
                trace.append(line)
                if mode == 'orphan' and line == 'CANCEL|2':
                    if not server is None:
                        raise ValueError('required condition failed at original line 48')
                    server = await listen()
        await asyncio.wait_for(stdout(), 8)
        code = await asyncio.wait_for(proc.wait(), 3)
        stderr = await stderr_task
        if tasks:
            await asyncio.wait_for(asyncio.gather(*tasks), 4)
        if not code == 0:
            raise ValueError((language, mode, code, stderr.decode(errors='replace')[-2000:]))
        if not not errors:
            raise ValueError(errors)
        expected = {'stack': ['ADDR|1|::1', 'ADDR|1|127.0.0.1', 'END|1', 'END|2'], 'instant': ['END|1', 'CANCEL|2', 'END|3'], 'orphan': ['END|1', 'CANCEL|2', 'END|3'], 'retry': ['ADDR|1|192.0.2.1', 'ADDR|1|2001:db8::1', 'END|1'], 'reverse': ['NAME|1|ff', 'END|1']}[mode]
        if not trace == expected:
            raise ValueError((language, mode, trace))
        if not len(connections) == {'stack': 0, 'instant': 1, 'orphan': 1, 'retry': 2, 'reverse': 2}[mode]:
            raise ValueError(connections)
        if mode in ('retry', 'reverse'):
            if not connections[0][0]['request']['id'] == connections[1][0]['request']['id']:
                raise ValueError('required condition failed at original line 54')
        (out / (language + '-' + mode + '.stdout')).write_text('\n'.join(trace) + '\n')
        (out / (language + '-' + mode + '.stderr')).write_bytes(stderr)
        return {'language': language, 'mode': mode, 'argv': argv, 'exit_code': code, 'trace': trace, 'connections': connections, 'elapsed': time.monotonic() - started, 'pid': proc.pid, 'runtime_config': cfg.read_text(), 'scope': 'Actual public client versus owned literal Unix peer; not daemon evidence'}
    finally:
        if proc.returncode is None:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), 3)
        if server:
            server.close()
            await server.wait_closed()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        shutil.rmtree(run)

async def main(a):
    a.output = a.output.resolve()
    a.output.mkdir(parents=True, exist_ok=False)
    build = json.loads(a.c_build.read_text())
    receipt = json.loads(pathlib.Path(build['normal_receipt']).read_text())
    if not (build['status'] == 'passed' and build['inputs_unchanged']):
        raise ValueError('required condition failed at original line 64')
    inputs = dict(build['inputs'])
    inputs.update({str(a.c_build.resolve()): sha(a.c_build), str(a.rust_binary.resolve()): sha(a.rust_binary), str(pathlib.Path(build['binary']['path'])): build['binary']['sha256'], str(pathlib.Path(__file__).resolve()): sha(__file__)})
    if a.sandbox:
        inputs[str(a.sandbox.resolve())] = sha(a.sandbox)
    for (path, digest) in inputs.items():
        if not sha(path) == digest:
            raise ValueError(path)
    env = os.environ.copy()
    env.update(receipt['runtime_environment'])
    rows = []
    result = {'status': 'failed', 'scope': 'Five actual C/R public broker pair profiles; owned literal Unix peer graphs, not normal daemon or whole owner completion', 'inputs': inputs, 'cases': rows}
    try:
        for mode in ['stack', 'instant', 'orphan', 'retry', 'reverse']:
            c = await case(pathlib.Path(build['binary']['path']), 'c', mode, env, a.output, a.sandbox)
            rows.append(c)
            r = await case(a.rust_binary, 'rust', mode, env, a.output, a.sandbox)
            rows.append(r)
            if not (c['trace'] == r['trace'] and c['connections'] == r['connections']):
                raise ValueError(mode)
        result['inputs_unchanged'] = all((sha(p) == h for (p, h) in inputs.items()))
        if not result['inputs_unchanged']:
            raise ValueError('required condition failed at original line 72')
        result.update(status='passed', paired_profiles=5, actual_actors=10)
    except Exception as e:
        result['failure'] = type(e).__name__ + ': ' + str(e)
        raise
    finally:
        (a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'paired_profiles': 5, 'result': str(a.output / 'result.json')}))
if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--c-build', type=pathlib.Path, required=True)
    p.add_argument('--rust-binary', type=pathlib.Path, required=True)
    p.add_argument('--sandbox', type=pathlib.Path)
    p.add_argument('--output', type=pathlib.Path, required=True)
    asyncio.run(main(p.parse_args()))
