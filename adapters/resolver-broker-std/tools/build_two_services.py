#!/usr/bin/env python3
"""Link unchanged normal ARM/statistics libraries with an explicitly single util."""
import argparse, importlib.util, json, os, pathlib, shlex, subprocess, sys
from common import sha, disjoint, compile_source

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--arm-receipt', type=pathlib.Path, required=True)
    p.add_argument('--statistics-receipt', type=pathlib.Path, required=True)
    p.add_argument('--upstream', type=pathlib.Path, required=True)
    p.add_argument('--reference-helper', type=pathlib.Path, required=True)
    p.add_argument('--package', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    p.add_argument('--output', type=pathlib.Path, required=True)
    a = p.parse_args()
    a.package = a.package.resolve()
    a.output = a.output.resolve()
    disjoint(a.output, a.package, a.upstream, a.arm_receipt.parent, a.statistics_receipt.parent)
    a.output.mkdir(exist_ok=False, parents=True)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(a.reference_helper.resolve().parent))
    from build_reference import source_state
    receipts = [json.loads(p.read_text()) for p in [a.arm_receipt, a.statistics_receipt]]
    actual = source_state(a.upstream)
    inputs = {}
    for receipt in receipts:
        if not (receipt['status'] == 'passed' and receipt['source_unchanged'] and (receipt['upstream'] == actual)):
            raise ValueError('required condition failed at original line 10')
        if not actual['revision'] == '346358e26d4dcc2dc4f51bef5d52dca29c7d8165':
            raise ValueError('required condition failed at original line 10')
        for row in [*receipt['artifacts'].values(), *receipt['libraries'], *receipt.get('default_configurations', []), receipt['generated_config'], receipt['compile_commands']]:
            if not sha(row['path']) == row['sha256']:
                raise ValueError(row['path'])
            inputs[row['path']] = row['sha256']
    (arm, stats) = receipts

    def library(receipt, name):
        return pathlib.Path(next((row['path'] for row in receipt['libraries'] if pathlib.Path(row['path']).name == name)))
    util = library(arm, 'libgnunetutil.23.dylib')
    arm_lib = library(arm, 'libgnunetarm.2.dylib')
    stats_lib = library(stats, 'libgnunetstatistics.2.dylib')
    commands = pathlib.Path(arm['compile_commands']['path'])
    entry = next((e for e in json.loads(commands.read_text()) if e['file'].endswith('/resolver_api.c')))
    cwd = pathlib.Path(entry['directory'])
    compile_source(entry, cwd, a.upstream)
    args = entry.get('arguments') or shlex.split(entry['command'])
    flags = []
    i = 1
    while i < len(args):
        value = args[i]
        if value in ('-o', '-MF', '-MQ', '-MT'):
            i += 2
            continue
        if value in ('-c', '-MD', '-MMD'):
            i += 1
            continue
        if not value.startswith('-') and value.endswith('.c'):
            i += 1
            continue
        if value.startswith('-I') and len(value) > 2:
            path = pathlib.Path(value[2:])
            value = '-I' + str(path if path.is_absolute() else cwd / path)
        flags.append(value)
        i += 1
    caller = a.package / 'tools/two_services.c'
    binary = a.output / 'two-services-c'
    for path in [a.arm_receipt, a.statistics_receipt, a.reference_helper, caller, pathlib.Path(__file__).resolve(), pathlib.Path(__file__).with_name('common.py'), pathlib.Path(arm['build']) / 'src/include/gnunet_config.h']:
        inputs[str(path.resolve())] = sha(path)
    argv = [args[0], *flags, str(caller), str(arm_lib), str(stats_lib), str(util), '-Wl,-rpath,' + str(util.parent), '-Wl,-rpath,' + str(stats_lib.parent), '-o', str(binary)]
    proc = subprocess.run(argv, cwd=cwd, capture_output=True)
    (a.output / 'stdout').write_bytes(proc.stdout)
    (a.output / 'stderr').write_bytes(proc.stderr)
    if not proc.returncode == 0:
        raise ValueError(proc.stderr.decode(errors='replace')[-3000:])
    env = {k: v for (k, v) in os.environ.items() if not k.startswith('GNUNET_')}
    env.update(arm['runtime_environment'])
    env['DYLD_LIBRARY_PATH'] = str(util.parent) + ':' + str(stats_lib.parent)
    env['LD_LIBRARY_PATH'] = env['DYLD_LIBRARY_PATH']
    unchanged = all((sha(k) == v for (k, v) in inputs.items())) and source_state(a.upstream) == actual
    if not unchanged:
        raise ValueError('required condition failed at original line 27')
    result = {'status': 'passed', 'scope': 'Combination of normal unmodified ARM/statistics libraries using exactly one specified normal ARM util; not a unified Meson build receipt. Actor must prove dladdr/dyld actual single util at runtime.', 'argv': argv, 'cwd': str(cwd), 'inputs': inputs, 'inputs_unchanged': unchanged, 'upstream': actual, 'binary': {'path': str(binary), 'sha256': sha(binary)}, 'specified_util': {'path': str(util), 'sha256': sha(util)}, 'runtime_environment': {k: env[k] for k in ['DYLD_LIBRARY_PATH', 'LD_LIBRARY_PATH', 'GNUNET_PREFIX']}, 'library_receipts': [{'path': str(path.resolve()), 'sha256': sha(path)} for path in [a.arm_receipt, a.statistics_receipt]]}
    (a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': 'passed', 'result': str(a.output / 'result.json')}))
if __name__ == '__main__':
    main()
