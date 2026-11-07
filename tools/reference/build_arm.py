#!/usr/bin/env python3
"""Build unchanged official ARM CLI/service and their normal Meson libraries.

This is an external interoperability reference. No production Rust code links
libgnunet and no installed system tree, existing reference or C input is changed.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import sys

import build_reference as common

ROOT = Path(__file__).resolve().parents[2]


def stage(build, prefix):
    prefix.mkdir(parents=True, exist_ok=False)
    artifacts = {}
    for name, source, destination in [
        ('client', 'src/cli/arm/gnunet-arm', 'bin/gnunet-arm'),
        ('service', 'src/service/arm/gnunet-service-arm', 'lib/gnunet/libexec/gnunet-service-arm'),
    ]:
        original, target = build/source, prefix/destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, target)
        artifacts[name] = {'built_path': str(original), 'path': str(target), 'sha256': common.sha256(target)}
    libraries = []
    for directory, basename in [('src/lib/util', 'libgnunetutil'), ('src/service/arm', 'libgnunetarm')]:
        found = []
        for original in sorted((build/directory).glob(basename+'*')):
            if not original.is_file() or not any(marker in original.name for marker in ['.dylib', '.so']):
                continue
            target = prefix/'lib'/original.name
            if original.is_symlink():
                target.symlink_to(os.readlink(original))
            else:
                shutil.copy2(original, target)
            found.append(original)
            libraries.append({'path': str(target), 'sha256': common.sha256(target), 'symlink': target.is_symlink()})
        if not found:
            raise RuntimeError('normal Meson library missing: '+basename)
    configurations = []
    for relative in ['src/lib/util/util.conf', 'src/service/arm/arm.conf']:
        original = build/relative
        target = prefix/'share/gnunet/config.d'/original.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, target)
        configurations.append({'path': str(target), 'sha256': common.sha256(target)})
    return artifacts, libraries, configurations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source', 'output', 'prefix', 'deps-prefix', 'meson', 'ninja']:
        parser.add_argument('--'+name, required=True, type=Path)
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    source, output, prefix = args.source.resolve(), args.output.resolve(), args.prefix.resolve()
    if args.jobs < 1:
        parser.error('jobs must be positive')
    for immutable in [source, ROOT, args.deps_prefix.resolve()]:
        for writable in [output, prefix]:
            if writable.is_relative_to(immutable) or immutable.is_relative_to(writable):
                parser.error('output/prefix and source/repository/dependencies must be disjoint')
    if output.is_relative_to(prefix) or prefix.is_relative_to(output) or output.exists() or prefix.exists():
        parser.error('output and prefix must be fresh disjoint paths')
    output.mkdir(parents=True)
    build = output/'build'
    report = {'kind': 'unmodified-official-c-arm-reference-build', 'status': 'failed',
              'scope': 'Normal Meson ARM CLI/service/util/arm libraries; does not certify a Rust implementation or whole GNUnet',
              'builder_sha256': common.sha256(Path(__file__)),
              'shared_builder_sha256': common.sha256(Path(common.__file__)),
              'host': {'system': platform.system(), 'machine': platform.machine()},
              'build': str(build), 'prefix': str(prefix), 'commands': []}
    try:
        report['upstream'] = common.source_state(source)
        env = dict(os.environ)
        deps = args.deps_prefix.resolve()
        # Match the existing successful normal profile; caller supplies platform
        # includes/link paths, while the pinned dependency prefix takes priority.
        for key, lead in [('PKG_CONFIG_PATH', str(deps/'lib/pkgconfig')),
                          ('CPPFLAGS', '-I'+str(deps/'include')),
                          ('LDFLAGS', '-L'+str(deps/'lib'))]:
            separator = os.pathsep if key == 'PKG_CONFIG_PATH' else ' '
            env[key] = lead+(separator+env[key] if env.get(key) else '')
        env['NINJA'] = str(args.ninja.resolve())
        report['build_environment'] = {k:env[k] for k in ['CC','CFLAGS','CPPFLAGS','LDFLAGS','PKG_CONFIG_PATH'] if k in env}
        commands = [
            ('meson-version', [str(args.meson), '--version']),
            ('compiler-version', [*shlex.split(env.get('CC','cc')), '--version']),
            ('meson-setup', [str(args.meson), 'setup', str(build), str(source), '--prefix='+str(prefix), '--libdir=lib', '--buildtype=debugoptimized', '-Ddisable-autostart=true', '-Dexclude-manpages=true', '-Dinstall-rpath=true', '-Dtestbed=false', '-Dexperimental=false']),
            ('meson-build', [str(args.meson), 'compile', '-C', str(build), '-j', str(args.jobs), 'gnunet-arm', 'gnunet-service-arm']),
        ]
        for name, argv in commands:
            row = common.run_logged(output, name, argv, env)
            report['commands'].append(row)
            if row['exit_code']:
                raise RuntimeError(name+' failed: '+row['log'])
        report['artifacts'], report['libraries'], report['default_configurations'] = stage(build,prefix)
        report['generated_config'] = {'path':str(build/'gnunet_private_config.h'),'sha256':common.sha256(build/'gnunet_private_config.h')}
        report['compile_commands'] = {'path':str(build/'compile_commands.json'),'sha256':common.sha256(build/'compile_commands.json')}
        report['source_unchanged'] = common.source_state(source) == report['upstream']
        if not report['source_unchanged']:
            raise RuntimeError('fixed C source changed')
        report['runtime_environment'] = {'GNUNET_PREFIX':str(prefix), 'DYLD_LIBRARY_PATH':str(prefix/'lib'), 'LD_LIBRARY_PATH':str(prefix/'lib')}
        report['status'] = 'passed'
    except Exception as error:
        report['failure'] = type(error).__name__+': '+str(error)
    common.save(output/'build-result.json',report)
    print(json.dumps({'status':report['status'],'receipt':str(output/'build-result.json'),'failure':report.get('failure')}))
    return 0 if report['status']=='passed' else 1


if __name__ == '__main__':
    sys.exit(main())
