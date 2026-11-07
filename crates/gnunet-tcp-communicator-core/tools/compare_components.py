#!/usr/bin/env python3
"""Actual selected Root tests and finite exact-source C functions, separately scoped."""
import argparse
import hashlib
import json
import re
import shlex
import sys
from pathlib import Path
from session_inputs import (CORE, CORE_PATH, PACKAGES, TOOLS, Commands, Inputs, require, same, sha)

sys.dont_write_bytecode = True
SOURCE = 'src/service/transport/gnunet-communicator-tcp.c'


def main():
    parser = argparse.ArgumentParser()
    for key in ('repository', 'source', 'reference', 'output'):
        parser.add_argument('--' + key, type=Path, required=True)
    args = parser.parse_args()
    repo, source, out = args.repository.resolve(), args.source.resolve(), args.output.resolve()
    guard = Inputs(repo, source, args.reference, out, 'unmodified-official-c-tcp-communicator-reference-build')
    normal = guard.reference.normal
    out.mkdir(mode=0o700, exist_ok=False)
    cmd = Commands(out, repo, normal['runtime_environment'])
    try:
        before = guard.discover()
        (out / 'inputs-before.json').write_text(json.dumps(before, indent=2) + '\n')
        inventory = json.loads((repo / CORE_PATH / 'inventory.json').read_text())
        require(inventory['source_revision'] == normal['upstream']['revision']
                and inventory['tcp_function_count'] == 61
                and len(inventory['sources'][SOURCE]['functions']) == 61,
                'complete61 source obligations must be retained')
        for name, row in inventory['sources'].items():
            same(sha(source / name), row['sha256'], 'original inventoried source ' + name)
        text = (source / SOURCE).read_text()
        start = text.index('GNUNET_NETWORK_STRUCT_BEGIN')
        end = text.index('GNUNET_NETWORK_STRUCT_END', start) + len('GNUNET_NETWORK_STRUCT_END')
        chunks, extracted = [text[start:end]], []
        for name in ('setup_cipher', 'calculate_hmac'):
            match = re.search(r'static void\s+' + name + r'\s*\(', text)
            require(match is not None, 'exact source function absent')
            start, brace = match.start(), text.index('{', match.end())
            index, depth = brace + 1, 1
            while depth:
                depth += (text[index] == '{') - (text[index] == '}')
                index += 1
            body = text[start:index]
            chunks.append(body)
            extracted.append({'name': name, 'sha256': hashlib.sha256(body.encode()).hexdigest()})
        header = out / 'tcp_source.inc'
        header.write_text('/* Original GNUnet AGPL-3.0-or-later test-only functions. */\n' + '\n\n'.join(chunks) + '\n')
        selected = [piece for name in PACKAGES for piece in ('-p', name)]
        cmd.run('format', ['cargo', '+1.99.1', 'fmt', '--manifest-path', repo / 'Cargo.toml', *selected, '--check'])
        tests = cmd.tests()
        cmd.run('clippy', ['cargo', '+1.99.1', 'clippy', '--manifest-path', repo / 'Cargo.toml',
                           '--locked', '--offline', *selected, '--all-targets', '-j', '1', '--', '-D', 'warnings'])
        binary = cmd.example(CORE, 'components')
        rust = json.loads(cmd.run('rust-observer', [binary]))
        rust.pop('kind')
        fields = {'initial_kx', 'initial_following_ack', 'confirmation', 'ack', 'rekey', 'box1', 'box2',
                  'finish', 'encrypted_ack', 'after_ack', 'encrypted_rekey', 'after_rekey', 'sizes'}
        same(set(rust), fields, 'exact13 nonempty component fields')
        require(all(v for v in rust.values()), 'empty component observation')
        row = next(r for r in json.loads(Path(normal['compile_commands']['path']).read_text())
                   if r['file'].endswith('/gnunet-communicator-tcp.c'))
        original = row.get('arguments') or shlex.split(row['command'])
        flags, index = [], 1
        while index < len(original):
            value = original[index]
            if value in ('-o', '-MF', '-MT', '-MQ'):
                index += 2
                continue
            if value in ('-c', '-MD', '-MMD') or value.endswith('/gnunet-communicator-tcp.c') or re.fullmatch('-O[0-9sgz]', value):
                index += 1
                continue
            flags.append(value)
            index += 1
        profiles = []
        prefix = Path(normal['prefix'])
        for opt in ('O0', 'O2'):
            native = out / ('normal-component-' + opt)
            cmd.compile_c('compile-' + opt, [original[0], *flags, '-' + opt, '-I' + str(out), TOOLS / 'components.c',
                    *shlex.split(normal['build_environment']['LDFLAGS']), '-L' + str(prefix / 'lib'),
                    '-lgnunetutil', '-lgcrypt', '-Wl,-rpath,' + str(prefix / 'lib'), '-o', native], cwd=row['directory'])
            cmd.bind(native)
            actual = json.loads(cmd.run('observe-' + opt, [native]))
            actual.pop('kind')
            same(actual, rust, 'actual normal C/Rust bytes ' + opt)
            profiles.append({'optimization': opt, 'matched_fields': sorted(fields), 'observation': actual,
                             'binary': str(native), 'sha256': sha(native)})
        after = guard.discover()
        (out / 'inputs-after.json').write_text(json.dumps(after, indent=2) + '\n')
        same(after, before, 'complete workspace/tools/reference file sets')
        cmd.check_artifacts()
        result = {'status': 'passed-components-only', 'inputs_unchanged': True,
                  'runtime_count': len(tests['runtime']), 'doc_count': len(tests['docs']), 'tests': tests,
                  'source_functions': extracted, 'source_sha256': sha(source / SOURCE),
                  'generated_header_sha256': sha(header), 'profiles': profiles, 'commands': cmd.rows,
                  'artifacts': cmd.artifacts, 'actual_c_header_inputs':cmd.headers, 'actual_daemon_or_peer_interoperation': False,
                  'scope': 'Three actual integrated Root packages; finite exact-source functions plus normal util/gcrypt. '
                           'No whole TCP communicator or CORE promotion; all61 source obligations retained.'}
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'status': result['status'], 'receipt': str(out / 'result.json')}))
    except BaseException as error:
        (out / 'failure.json').write_text(json.dumps({'error': str(error), 'commands': cmd.rows}, indent=2) + '\n')
        raise


if __name__ == '__main__':
    main()
