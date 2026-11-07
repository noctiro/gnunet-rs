#!/usr/bin/env python3
"""Normal C and actual Rust ARM/STATISTICS hosts share one owned Resolver peer."""
import argparse, asyncio, json, os, pathlib, shutil, socket, struct, tempfile
from common import sha, disjoint
from paired import frame, decode, reply

async def actor(binary, language, build, out):
    run = pathlib.Path(tempfile.mkdtemp(prefix='shared-arm-stats-', dir='/private/tmp'))
    run.chmod(448)
    sock = run / 'r'
    cfg = run / 'c'
    base = run / 'base'
    base.mkdir()
    events = []
    stderr_lines = []
    tasks = []
    errors = []
    graphs = {'resolver': [], 'arm': [], 'statistics': []}
    arm_list = asyncio.Event()
    stats_lookup = asyncio.Event()
    stats_get = asyncio.Event()
    dns_done = asyncio.Event()

    async def dns_connection(reader, writer):
        rows = []
        graphs['resolver'].append(rows)
        try:
            if not len(graphs['resolver']) == 1:
                raise ValueError('more than one shared Resolver MQ')
            a = decode(await asyncio.wait_for(frame(reader), 3))
            if not bytes.fromhex(a['data']) == b'arm-owned.invalid\x00':
                raise ValueError('required condition failed at original line 12')
            rows.append({'request': a})
            writer.write(reply(a['id'], socket.inet_pton(socket.AF_INET, '127.0.0.1')))
            await writer.drain()
            rows.append({'send': 'arm-address'})
            await asyncio.wait_for(arm_list.wait(), 3)
            await asyncio.wait_for(stats_lookup.wait(), 3)
            try:
                byte = await asyncio.wait_for(reader.readexactly(1), 0.03)
            except asyncio.TimeoutError:
                pass
            else:
                raise AssertionError('tail transmitted before original head END: ' + byte.hex())
            rows.append({'tail-blocked-after-arm-test-and-list': True})
            writer.write(reply(a['id']))
            await writer.drain()
            rows.append({'send': 'arm-end'})
            b = decode(await asyncio.wait_for(frame(reader), 3))
            if not bytes.fromhex(b['data']) == b'stats-owned.invalid\x00':
                raise ValueError('required condition failed at original line 18')
            if not b['id'] != a['id']:
                raise ValueError('required condition failed at original line 18')
            rows.append({'request': b})
            writer.write(reply(b['id'], socket.inet_pton(socket.AF_INET, '127.0.0.1')))
            await writer.drain()
            rows.append({'send': 'statistics-address'})
            await asyncio.wait_for(stats_get.wait(), 3)
            writer.write(reply(b['id']))
            await writer.drain()
            rows.append({'send': 'statistics-end'})
            if not await asyncio.wait_for(reader.read(), 3) == b'':
                raise ValueError('required condition failed at original line 20')
            rows.append({'eof': True})
            dns_done.set()
        except Exception as e:
            errors.append('resolver ' + type(e).__name__ + ': ' + str(e))
            dns_done.set()
        finally:
            writer.close()
            await writer.wait_closed()

    async def arm_connection(reader, writer):
        rows = []
        graphs['arm'].append(rows)
        try:
            if not len(graphs['arm']) == 1:
                raise ValueError('required condition failed at original line 26')
            first = await asyncio.wait_for(frame(reader), 3)
            if not first == b'\x00\x04\x00\x0f':
                raise ValueError('required condition failed at original line 27')
            rows.append({'request': first.hex()})
            writer.write(first)
            await writer.drain()
            rows.append({'send': first.hex()})
            request = await asyncio.wait_for(frame(reader), 3)
            if not request[:4] == b'\x00\x10\x00\x0c':
                raise ValueError('required condition failed at original line 28')
            rows.append({'request': request.hex()})
            data = bytearray(24)
            data[:4] = b'\x00\x18\x00\r'
            data[8:16] = request[8:16]
            writer.write(data)
            await writer.drain()
            rows.append({'send': data.hex()})
            if not await asyncio.wait_for(reader.read(), 4) == b'':
                raise ValueError('required condition failed at original line 29')
            rows.append({'eof': True})
        except Exception as e:
            errors.append('arm ' + type(e).__name__ + ': ' + str(e))
        finally:
            writer.close()
            await writer.wait_closed()

    async def statistics_connection(reader, writer):
        rows = []
        graphs['statistics'].append(rows)
        try:
            if not len(graphs['statistics']) == 1:
                raise ValueError('required condition failed at original line 35')
            request = await asyncio.wait_for(frame(reader), 3)
            if not request == b'\x00\x08\x00\xa9s\x00n\x00':
                raise ValueError('required condition failed at original line 36')
            rows.append({'request': request.hex()})
            stats_get.set()
            await asyncio.wait_for(dns_done.wait(), 3)
            if not not errors:
                raise ValueError(errors)
            writer.write(b'\x00\x04\x00\xab')
            await writer.drain()
            rows.append({'send': '000400ab'})
            if not await asyncio.wait_for(reader.read(), 3) == b'':
                raise ValueError('required condition failed at original line 37')
            rows.append({'eof': True})
        except Exception as e:
            errors.append('statistics ' + type(e).__name__ + ': ' + str(e))
            stats_get.set()
        finally:
            writer.close()
            await writer.wait_closed()

    def accept(fn):

        def start(r, w):
            tasks.append(asyncio.create_task(fn(r, w)))
        return start
    resolver = await asyncio.start_unix_server(accept(dns_connection), path=str(sock))
    arm = await asyncio.start_server(accept(arm_connection), '127.0.0.1', 0)
    stats = await asyncio.start_server(accept(statistics_connection), '127.0.0.1', 0)
    cfg.write_text('[resolver]\nUNIXPATH = ' + str(sock) + '\nHOSTNAME = localhost\nPORT = 0\n[arm]\nHOSTNAME = arm-owned.invalid\nPORT = ' + str(arm.sockets[0].getsockname()[1]) + '\n[statistics]\nHOSTNAME = stats-owned.invalid\nPORT = ' + str(stats.sockets[0].getsockname()[1]) + '\nDISABLE = NO\n')
    env = {k: v for (k, v) in os.environ.items() if not k.startswith('GNUNET_')}
    env.update(build['runtime_environment'])
    env.update(GNUNET_BASE_CONFIG=str(base), LC_ALL='C')
    argv = [str(binary), str(cfg)] + ([build['specified_util']['path']] if language == 'c' else [])
    proc = await asyncio.create_subprocess_exec(*argv, env=env, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

    async def output():
        while True:
            line = await proc.stdout.readline()
            if not line:
                return
            line = line.decode().rstrip('\n')
            events.append(line)
            if line == 'ARM_LIST|0':
                arm_list.set()
            if language == 'rust' and line == 'SHARED_PENDING|2':
                stats_lookup.set()

    async def diagnostics():
        while True:
            line = await proc.stderr.readline()
            if not line:
                return
            stderr_lines.append(line)
            if language == 'c' and b'Trying to resolve hostname `stats-owned.invalid' in line:
                stats_lookup.set()
    try:
        await asyncio.wait_for(asyncio.gather(output(), diagnostics()), 8)
        code = await asyncio.wait_for(proc.wait(), 3)
        await asyncio.wait_for(asyncio.gather(*tasks), 4)
        (out / (language + '.stdout')).write_text('\n'.join(events) + '\n')
        (out / (language + '.stderr')).write_bytes(b''.join(stderr_lines))
        (out / (language + '.graphs.json')).write_text(json.dumps({'graphs': graphs, 'errors': errors}, indent=2) + '\n')
        if not code == 0:
            raise ValueError((language, code, b''.join(stderr_lines)[-3000:]))
        if not not errors:
            raise ValueError(errors)
        if not all((len(v) == 1 for v in graphs.values())):
            raise ValueError('required condition failed at original line 60')
        trace = [x for x in events if x != 'SHARED_PENDING|2']
        if not trace == ['ARM_UP|1', 'ARM_LIST|0', 'STATS_END|1']:
            raise ValueError(trace)
        if not stats_lookup.is_set():
            raise ValueError('required condition failed at original line 60')
        actual_util = []
        if language == 'c':
            lines = b''.join(stderr_lines).decode(errors='replace').splitlines()
            actual_util = [line[len('DYLD_UTIL|'):] for line in lines if line.startswith('DYLD_UTIL|')]
            if not len(actual_util) == 1:
                raise ValueError('required condition failed at original line 63')
            if not pathlib.Path(actual_util[0]).resolve() == pathlib.Path(build['specified_util']['path']).resolve():
                raise ValueError('required condition failed at original line 63')
            if not 'BOUND_UTIL|' + str(pathlib.Path(build['specified_util']['path']).resolve()) in lines:
                raise ValueError('required condition failed at original line 63')
        return {'language': language, 'argv': argv, 'pid': proc.pid, 'exit_code': code, 'callback_trace': trace, 'raw_events': events, 'connections': graphs, 'lookup_admission_observer': 'C native DEBUG exact stats ip_get readpoint after current cfg acceptance (cfg has private Unix path)' if language == 'c' else 'actual shared Context.pending_requests()==2', 'actual_loaded_util': actual_util, 'scope': 'Public normal library combination or actual Rust hosts; owned literal service/Resolver peers, not normal daemon.'}
    finally:
        if proc.returncode is None:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), 3)
        for server in [resolver, arm, stats]:
            server.close()
            await server.wait_closed()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        shutil.rmtree(run)

async def main(a):
    a.output = a.output.resolve()
    disjoint(a.output, a.package, a.c_build.parent, a.rust_binary.parent)
    a.output.mkdir(exist_ok=False, parents=True)
    build = json.loads(a.c_build.read_text())
    if not build['status'] == 'passed':
        raise ValueError('required condition failed at original line 72')
    inputs = dict(build['inputs'])
    inputs.update({build['binary']['path']: build['binary']['sha256']})
    for p in [a.c_build, a.rust_binary, pathlib.Path(__file__).resolve(), pathlib.Path(__file__).with_name('paired.py'), pathlib.Path(__file__).with_name('common.py')]:
        inputs[str(p.resolve())] = sha(p)
    for (p, h) in inputs.items():
        if not sha(p) == h:
            raise ValueError(p)
    result = {'status': 'failed', 'inputs': inputs, 'cases': [], 'scope': 'Actual public ARM+STATISTICS C/R shared Resolver single-MQ pair over owned Unix/127.0.0.1. Immutable original normal libraries combined with single specified util verified at runtime; not unified C build, daemon or owner acceptance.'}
    try:
        for (language, binary) in [('c', pathlib.Path(build['binary']['path'])), ('rust', a.rust_binary)]:
            result['cases'].append(await actor(binary, language, build, a.output))
        (left, right) = result['cases']
        if not (left['callback_trace'] == right['callback_trace'] and left['connections'] == right['connections']):
            raise ValueError('required condition failed at original line 78')
        result['inputs_unchanged'] = all((sha(p) == h for (p, h) in inputs.items()))
        if not result['inputs_unchanged']:
            raise ValueError('required condition failed at original line 78')
        result.update(status='passed', paired_profiles=1, actual_actors=2)
    except Exception as e:
        result['failure'] = type(e).__name__ + ': ' + str(e)
        raise
    finally:
        (a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'result': str(a.output / 'result.json')}))
if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--package', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    p.add_argument('--c-build', type=pathlib.Path, required=True)
    p.add_argument('--rust-binary', type=pathlib.Path, required=True)
    p.add_argument('--output', type=pathlib.Path, required=True)
    asyncio.run(main(p.parse_args()))
