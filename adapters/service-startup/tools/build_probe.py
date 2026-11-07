#!/usr/bin/env python3
"""Compile a public caller against unchanged normal Meson headers/library."""
import argparse
import hashlib
import json
import pathlib
import shlex
import subprocess
from _common import require_disjoint_output, workspace_root, normal_reference


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-receipt', type=pathlib.Path, required=True)
    parser.add_argument('--package', type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument('--source', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--component-source', type=pathlib.Path)
    args = parser.parse_args()
    validated_reference = normal_reference(args.build_receipt, args.source)
    receipt = json.loads(args.build_receipt.read_text())
    build = pathlib.Path(receipt['build'])
    entries = json.loads((build / 'compile_commands.json').read_text())
    entry = next(row for row in entries if row['file'].endswith('/service.c'))
    command = entry.get('arguments') or shlex.split(entry['command'])
    directory = pathlib.Path(entry['directory'])
    source_path = pathlib.Path(entry['file'])
    if not source_path.is_absolute():
        source_path = directory / source_path
    upstream = source_path.resolve().parents[3]
    flags = []
    index = 1
    while index < len(command):
        value = command[index]
        if value in ('-o', '-MF', '-MQ', '-MT'):
            index += 2
            continue
        if value in ('-c', '-MD', '-MMD'):
            index += 1
            continue
        if not value.startswith('-') and value.endswith('.c'):
            index += 1
            continue
        if value.startswith('-I') and len(value) > 2:
            path = pathlib.Path(value[2:])
            value = '-I' + str(path if path.is_absolute() else directory / path)
        flags.append(value)
        index += 1
    # This oracle explicitly targets the already-built normal Darwin profile.
    library = pathlib.Path(receipt['runtime_environment']['DYLD_LIBRARY_PATH']
                           .split(':')[0]) / 'libgnunetutil.23.dylib'
    if source_path.resolve() != (args.source / 'src/lib/util/service.c').resolve():
        raise ValueError('build receipt uses a different upstream source tree')
    require_disjoint_output(args.output, [workspace_root(args.package), args.source,
        args.build_receipt.resolve().parent, build, library.parent.parent,
        pathlib.Path(__file__).resolve().parent])
    args.output.mkdir(exist_ok=False)
    source = args.component_source or pathlib.Path(__file__).with_name('service_probe.c')
    binary = args.output / ('credential-component' if args.component_source
                            else 'service-probe')
    argv = [command[0], *flags, str(source), str(library),
            '-Wl,-rpath,' + str(library.parent), '-o', str(binary)]
    tracked = [source, library, args.build_receipt, build / 'compile_commands.json',
               build / 'gnunet_private_config.h',
               build / 'src/include/gnunet_config.h', pathlib.Path(__file__).resolve(), pathlib.Path(__file__).with_name('_common.py'),
               *(upstream / 'src/include').rglob('*.h'),
               *(upstream / 'src/lib/util').glob('*.h'),
               *[upstream / 'src/lib/util' / name for name in
                 ['service.c', 'os_process.c', 'network.c', 'configuration.c',
                  'strings.c']]]
    inputs = {str(path): sha(path) for path in tracked}
    completed = subprocess.run(argv, capture_output=True, cwd=directory)
    (args.output / 'stdout').write_bytes(completed.stdout)
    (args.output / 'stderr').write_bytes(completed.stderr)
    reference_after = normal_reference(args.build_receipt, args.source)
    if reference_after != validated_reference:
        raise ValueError('normal reference changed during probe compilation')
    result = {
        'normal_reference_validation': validated_reference,
        'argv': argv, 'cwd': str(directory), 'exit_code': completed.returncode,
        'inputs': inputs,
        'inputs_unchanged': all(sha(path) == value for path, value in inputs.items()),
        'binary': {'path': str(binary), 'sha256': sha(binary)}
                  if completed.returncode == 0 else None,
        'runtime_environment': receipt['runtime_environment'],
        'normal_reference_receipt': str(args.build_receipt.resolve()),
        'normal_reference_source': str(args.source.resolve()),
        'normal_library_not_rebuilt': True,
    }
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'exit_code': completed.returncode,
                      'result': str(args.output / 'result.json')}))
    return completed.returncode


if __name__ == '__main__':
    raise SystemExit(main())
