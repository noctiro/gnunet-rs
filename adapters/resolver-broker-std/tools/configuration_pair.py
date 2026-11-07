#!/usr/bin/env python3
"""Actual public Resolver selection: old MQ's live cfg identity vs new MQ cfg."""
import argparse, asyncio, json, os, pathlib, shutil, tempfile
from paired import sha, frame, decode, reply

async def actor(binary, language, env, out, sandbox):
    run = pathlib.Path(tempfile.mkdtemp(prefix='rbcfg-', dir='/private/tmp'))
    run.chmod(448)
    base = run / 'base'
    base.mkdir()
    old = run / 'a'
    new = run / 'b'
    ca = run / 'ca'
    cb = run / 'cb'

    def config(path):
        return '[resolver]\nUNIXPATH = ' + str(path) + '\nHOSTNAME = localhost\nPORT = 0\n'
    ca.write_text(config(run / 'missing'))
    cb.write_text(config(new))
    graphs = {'a': [], 'b': []}
    errors = []
    tasks = []

    async def connection(reader, writer, name):
        rows = []
        graphs[name].append(rows)
        try:
            if not len(graphs[name]) == 1:
                raise ValueError('extra logical MQ connection')
            for expected in [b'first', b'second'] if name == 'a' else [b'third']:
                q = decode(await asyncio.wait_for(frame(reader), 4))
                if not bytes.fromhex(q['data']) == expected + b'\x00':
                    raise ValueError('required condition failed at original line 14')
                rows.append({'request': q})
                writer.write(reply(q['id']))
                await writer.drain()
                rows.append({'send': 'end'})
            if not await asyncio.wait_for(reader.read(), 3) == b'':
                raise ValueError('required condition failed at original line 15')
            rows.append({'eof': True})
        except Exception as e:
            errors.append(name + ' ' + type(e).__name__ + ': ' + str(e))
        finally:
            writer.close()
            await writer.wait_closed()

    def accept(name):

        def start(r, w):
            tasks.append(asyncio.create_task(connection(r, w, name)))
        return start
    a = await asyncio.start_unix_server(accept('a'), path=str(old))
    b = await asyncio.start_unix_server(accept('b'), path=str(new))
    child_env = {k: v for (k, v) in env.items() if not k.startswith('GNUNET_')}
    child_env['GNUNET_PREFIX'] = env['GNUNET_PREFIX']
    child_env.update(GNUNET_BASE_CONFIG=str(base), LC_ALL='C')
    argv = ['/usr/bin/sandbox-exec', '-f', str(sandbox), str(binary), str(ca), str(cb), str(old)]
    proc = await asyncio.create_subprocess_exec(*argv, env=child_env, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        (stdout, stderr) = await asyncio.wait_for(proc.communicate(), 9)
        await asyncio.wait_for(asyncio.gather(*tasks), 4)
        (out / (language + '.stdout')).write_bytes(stdout)
        (out / (language + '.stderr')).write_bytes(stderr)
        trace = stdout.decode().splitlines()
        (out / (language + '.graphs.json')).write_text(json.dumps({'graphs': graphs, 'errors': errors}, indent=2) + '\n')
        if not proc.returncode == 0:
            raise ValueError((language, proc.returncode, stderr.decode(errors='replace')[-2000:]))
        if not not errors:
            raise ValueError(errors)
        if not trace == ['SELECT', 'MUTATE', 'END|1', 'END|2', 'THIRD', 'END|3']:
            raise ValueError(trace)
        guard = None
        if language == 'c':
            first = stderr.find(b'Transmitting DNS resolution request (ID 1)')
            selected = stderr.find(b'BROKER_SELECT')
            if not 0 <= first < selected:
                raise ValueError('initial actual logical MQ was not created before selected cfg replacement')
            guard = {'initial_MQ_submission_precedes_selection': True, 'submission_stderr_offset': first, 'select_stderr_offset': selected}
        return {'language': language, 'pid': proc.pid, 'exit_code': proc.returncode, 'argv': argv, 'trace': trace, 'graphs': graphs, 'native_readpoint_guard': guard, 'checks': ['old-MQ-survives-selected-cfg-replacement', 'old-cfg-Unix-live-update-controls-old-MQ-retry', 'second-request-still-old-MQ', 'new-MQ-third-request-uses-new-selection', 'original-cfg-owners-live-until-after-MQ-close']}
    finally:
        if proc.returncode is None:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), 3)
        a.close()
        b.close()
        await a.wait_closed()
        await b.wait_closed()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        shutil.rmtree(run)

async def main(a):
    a.output = a.output.resolve()
    a.output.mkdir(exist_ok=False, parents=True)
    c = json.loads(a.c_build.read_text())
    normal = json.loads(pathlib.Path(c['normal_receipt']).read_text())
    if not c['status'] == 'passed':
        raise ValueError('required condition failed at original line 35')
    inputs = dict(c['inputs'])
    inputs.update({c['binary']['path']: c['binary']['sha256']})
    for p in [a.c_build, a.rust_binary, a.sandbox, pathlib.Path(__file__).resolve(), pathlib.Path(__file__).with_name('paired.py')]:
        inputs[str(p.resolve())] = sha(p)
    for (p, h) in inputs.items():
        if not sha(p) == h:
            raise ValueError(p)
    env = os.environ.copy()
    env.update(normal['runtime_environment'])
    result = {'status': 'failed', 'scope': 'Normal public Resolver connect/reselection against owned literal Unix peers, IP denied; no daemon/whole-owner promotion', 'inputs': inputs, 'cases': []}
    try:
        for (lang, binary) in [('c', pathlib.Path(c['binary']['path'])), ('rust', a.rust_binary)]:
            result['cases'].append(await actor(binary, lang, env, a.output, a.sandbox))
        (left, right) = result['cases']
        if not (left['trace'] == right['trace'] and left['graphs'] == right['graphs']):
            raise ValueError('required condition failed at original line 41')
        result['inputs_unchanged'] = all((sha(p) == h for (p, h) in inputs.items()))
        if not result['inputs_unchanged']:
            raise ValueError('required condition failed at original line 41')
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
    p.add_argument('--sandbox', type=pathlib.Path, required=True)
    p.add_argument('--output', type=pathlib.Path, required=True)
    asyncio.run(main(p.parse_args()))
