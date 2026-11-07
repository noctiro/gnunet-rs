#!/usr/bin/env python3
"""Compile a small caller against a hash-validated, unchanged normal C util build."""
import argparse, hashlib, json, pathlib, shlex, subprocess, sys
from common import compile_source

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--receipt', type=pathlib.Path, required=True)
    p.add_argument('--source', type=pathlib.Path, required=True)
    p.add_argument('--reference-helper', type=pathlib.Path, required=True)
    p.add_argument('--package', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    p.add_argument('--caller', default='tools/public_broker.c')
    p.add_argument('--output', type=pathlib.Path, required=True)
    a = p.parse_args()
    a.package = a.package.resolve()
    a.output = a.output.resolve()
    a.source = a.source.resolve()
    for location in [a.package, a.source, a.receipt.resolve().parent]:
        if not (not a.output.is_relative_to(location) and (not location.is_relative_to(a.output))):
            raise ValueError('output must be disjoint')
    a.output.mkdir(exist_ok=False, parents=True)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(a.reference_helper.resolve().parent))
    from build_reference import source_state
    receipt = json.loads(a.receipt.read_text())
    if not (receipt['status'] == 'passed' and receipt['source_unchanged']):
        raise ValueError('required condition failed at original line 11')
    if not receipt['upstream']['revision'] == '346358e26d4dcc2dc4f51bef5d52dca29c7d8165':
        raise ValueError('required condition failed at original line 12')
    if not source_state(a.source) == receipt['upstream']:
        raise ValueError('required condition failed at original line 12')
    inputs = {}
    rows = [*receipt['artifacts'].values(), *receipt['libraries'], *receipt['default_configurations']]
    for row in rows:
        if not sha(row['path']) == row['sha256']:
            raise ValueError(row['path'])
        inputs[row['path']] = row['sha256']
    build = pathlib.Path(receipt['build'])
    commands = pathlib.Path(receipt['compile_commands']['path']).resolve()
    if commands!=(build/'compile_commands.json').resolve():raise ValueError('declared normal compile config is not the actual build file')
    if not sha(receipt['compile_commands']['path']) == receipt['compile_commands']['sha256']:
        raise ValueError('required condition failed at original line 15')
    for row in [receipt['generated_config']]:
        if not sha(row['path']) == row['sha256']:
            raise ValueError(row['path'])
        inputs[row['path']] = row['sha256']
    entries = json.loads(commands.read_text())
    entry = next((e for e in entries if e['file'].endswith('/resolver_api.c')))
    args = entry.get('arguments') or shlex.split(entry['command'])
    cwd = pathlib.Path(entry['directory'])
    compile_source(entry, cwd, a.source)
    flags = []
    i = 1
    while i < len(args):
        x = args[i]
        if x in ('-o', '-MF', '-MQ', '-MT'):
            i += 2
            continue
        if x in ('-c', '-MD', '-MMD'):
            i += 1
            continue
        if not x.startswith('-') and x.endswith('.c'):
            i += 1
            continue
        if x.startswith('-I') and len(x) > 2:
            path = pathlib.Path(x[2:])
            x = '-I' + str(path if path.is_absolute() else cwd / path)
        flags.append(x)
        i += 1
    lib = pathlib.Path(receipt['runtime_environment']['DYLD_LIBRARY_PATH'].split(':')[0]) / 'libgnunetutil.23.dylib'
    if not str(lib) in inputs:
        raise ValueError('required condition failed at original line 26')
    caller = (a.package / a.caller).resolve()
    if not caller.is_relative_to(a.package):
        raise ValueError('required condition failed at original line 27')
    binary = a.output / 'public-broker'
    for path in [caller, pathlib.Path(__file__).resolve(), a.receipt.resolve(), a.reference_helper.resolve(), pathlib.Path(__file__).with_name('common.py').resolve(), commands, build / 'src/include/gnunet_config.h', build / 'gnunet_private_config.h']:
        inputs[str(path)] = sha(path)
    argv = [args[0], *flags, str(caller), str(lib), '-Wl,-rpath,' + str(lib.parent), '-o', str(binary)]
    proc = subprocess.run(argv, cwd=cwd, capture_output=True)
    (a.output / 'stdout').write_bytes(proc.stdout)
    (a.output / 'stderr').write_bytes(proc.stderr)
    unchanged = all((sha(k) == v for (k, v) in inputs.items())) and source_state(a.source) == receipt['upstream']
    result = {'status': 'passed' if proc.returncode == 0 and unchanged else 'failed', 'argv': argv, 'cwd': str(cwd), 'exit_code': proc.returncode, 'inputs': inputs, 'upstream': receipt['upstream'], 'inputs_unchanged': unchanged, 'normal_receipt': str(a.receipt.resolve()), 'binary': {'path': str(binary), 'sha256': sha(binary)} if proc.returncode == 0 else None}
    (a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'result': str(a.output / 'result.json')}))
    return 0 if result['status'] == 'passed' else 1
if __name__ == '__main__':
    raise SystemExit(main())
