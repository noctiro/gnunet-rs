#!/usr/bin/env python3
"""Future explicitly approved private selected C Conversation build, never a node.

Import defines code only. No compiler, Meson, product, network, dependency
bootstrap, device, helper, codec or target runs without main and exact approval.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import shutil
import signal
import subprocess
import sys
import time

from conversation_build_stage import Blocked, Stager, digest, inside, metadata, target_index

REVISION = '346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
HANDBOOK = 'cede13d10fb1ca0c1b33d8ed8a21507eda41d03b'
PROFILE = 'conversation-selected-c-build'
SERVICES = ('resolver', 'statistics', 'peerstore', 'pils', 'nat', 'transport',
            'core', 'dht', 'cadet', 'identity', 'namestore', 'namecache', 'zonemaster', 'gns', 'conversation')
CLIENTS = ('pils', 'hello', 'identity', 'namestore', 'transport', 'conversation')
TARGETS = {'c.service.' + n: 'gnunet-service-' + n for n in SERVICES}
TARGETS.update({'c.cli.' + n: 'gnunet-' + n for n in CLIENTS})
TARGETS['c.communicator.tcp'] = 'gnunet-communicator-tcp'
PLUGINS = ('peerstore_sqlite', 'namestore_sqlite', 'namecache_sqlite', 'datacache_heap',
           'block_dht', 'block_gns', 'gnsrecord_gns', 'gnsrecord_dns', 'gnsrecord_conversation')
PLUGIN_TARGETS = tuple('gnunet_plugin_' + n for n in PLUGINS)
PERMISSIONS = {'private-source-copy', 'native-configure-probes', 'selected-31-target-compile-link',
               'readonly-dependencies-static-inspection', 'private-selected-staging', 'owned-build-process-groups'}


class ToolFailure(RuntimeError):
    pass


def reason(error):
    return {'type': type(error).__name__, 'message': str(error)}


def save(path, value):
    # Only the caller's new output tree is written; no old attempt is resumed.
    with Path(path).open('w', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()


def reference(path):
    value, size = digest(path)
    return {'path': str(path), 'sha256': value, 'bytes': size}


def checked(row):
    path = Path(row['path'])
    if not path.is_absolute() or reference(path)['sha256'] != row['sha256']:
        raise Blocked('explicit prerequisite path/hash mismatch: ' + str(path))
    return path.resolve()


class Runner:
    """One sequential actual compiler/Git/inspector owner, never a target run."""
    def __init__(self, root, env, seconds):
        if not isinstance(seconds, (int, float)) or not 1 <= seconds <= 14400:
            raise Blocked('build target must be finite, between1 and14400 seconds')
        self.root, self.env = root, env
        self.hard = time.monotonic() + seconds
        self.rows, self.cleanup_errors = [], []
        self.current = None
        self.cleaning = False
        self.total_output = 0
        self.signals = {int(signal.SIGINT): 0, int(signal.SIGTERM): 0}

    def interruption(self, signum):
        self.signals[int(signum)] = min(65535, self.signals[int(signum)] + 1)

    def remaining(self):
        left = self.hard - time.monotonic()
        if left <= 0:
            raise TimeoutError('original private build target elapsed')
        return left

    def acquire(self, row, function):
        previous, pending = {}, {}
        original = None
        def defer(signum, frame):
            pending.setdefault(signum, frame)
        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                handler = signal.getsignal(sig)
                if callable(handler):
                    previous[sig] = handler
                    signal.signal(sig, defer)
            function()
        except BaseException as error:
            original = error
        finally:
            row['deferred_signals'] = [int(v) for v in pending]
            for sig, handler in previous.items():
                try:
                    signal.signal(sig, handler)
                except BaseException as error:
                    self.cleanup_errors.append({'stage': 'acquire-handler-restore', 'error': reason(error)})
                    if original is None:
                        original = error
        if original is not None:
            raise original
        for sig, frame in pending.items():
            previous[sig](sig, frame)

    def retire(self, owner):
        previous = self.cleaning
        self.cleaning = True
        try:
            process = owner.get('process')
            # No wait/poll consumed this child before error cleanup. Its actual
            # unreaped PID reserves this newly created session/group identifier.
            # Never signal a numeric group after consuming that original wait.
            owner['retirement_attempted'] = True
            if process is not None and process.returncode is None and not owner.get('group_reservation_uncertain'):
                for sig in (signal.SIGTERM, signal.SIGKILL):
                    try:
                        os.killpg(process.pid, sig)
                        owner['row']['cleanup'].append({'owned_group_signal': int(sig), 'native_returned': True})
                    except ProcessLookupError as error:
                        owner['row']['cleanup'].append({'owned_group_signal': int(sig), 'race': reason(error)})
                    except BaseException as error:
                        self.cleanup_errors.append({'stage': 'owned-build-group-signal', 'error': reason(error)})
                    if sig == signal.SIGTERM:
                        # No waitpid here: keep the original PID unreaped even
                        # if the leader exits, then KILL its owned group once.
                        try:
                            select.select([], [], [], 0.25)
                        except BaseException as error:
                            self.cleanup_errors.append({'stage': 'owned-build-grace', 'error': reason(error)})
                try:
                    owner['row']['exit_code'] = process.wait(timeout=3)
                    owner['row']['reaped'] = True
                except BaseException as error:
                    self.cleanup_errors.append({'stage': 'owned-build-wait', 'error': reason(error)})
            for label in ('stdout_pipe', 'stderr_pipe', 'stdout_log', 'stderr_log'):
                stream = owner.get(label)
                if stream is not None:
                    try:
                        stream.close()
                    except BaseException as error:
                        self.cleanup_errors.append({'stage': label + '-close', 'error': reason(error)})
        finally:
            self.cleaning = previous

    def wait(self, owner, hard):
        # Protect waitpid return -> Popen/row registration with handled-signal
        # deferral, but only for short slices so cancellation is not delayed by
        # a whole compiler target. A timed-out slice did not consume the child.
        while not owner['row']['reaped']:
            left = min(self.remaining(), hard - time.monotonic())
            if left <= 0:
                raise TimeoutError('original command wait target elapsed')
            def one_slice():
                try:
                    code = owner['process'].wait(timeout=min(left, 0.1))
                except subprocess.TimeoutExpired:
                    return
                except BaseException:
                    owner['group_reservation_uncertain'] = True
                    raise
                owner['row'].update(exit_code=code, reaped=True)
            self.acquire(owner['row'], one_slice)
        return owner['row']['exit_code']

    def run(self, name, argv, timeout=1200):
        self.remaining()
        if len(self.rows) >= 4096 or not Path(argv[0]).is_absolute():
            raise Blocked('bounded command table/absolute tool requirement failed')
        hard = min(self.hard, time.monotonic() + timeout)
        serial = len(self.rows)
        row = {'name': name, 'argv': [str(x) for x in argv], 'pid': None,
               'reaped': False, 'exit_code': None, 'cleanup': [], 'deadline_monotonic': hard}
        owner = {'row': row, 'process': None}
        self.current = owner
        self.rows.append(row)
        streams = {}
        try:
            def launch():
                for label in ('stdout', 'stderr'):
                    path = self.root / f'{serial:04d}-{name}.{label}'
                    owner[label + '_log'] = path.open('xb', buffering=0)
                    row[label] = str(path)
                self.remaining()
                if time.monotonic() >= hard:
                    raise TimeoutError('original command expired before Popen')
                owner['process'] = subprocess.Popen(
                    [str(v) for v in argv], env=self.env, cwd=self.root,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    close_fds=True, pass_fds=(), start_new_session=True, shell=False)
                process = owner['process']
                row['pid'] = process.pid
                for label in ('stdout', 'stderr'):
                    pipe = getattr(process, label)
                    owner[label + '_pipe'] = pipe
                    os.set_blocking(pipe.fileno(), False)
                    streams[pipe.fileno()] = (label, pipe)
            self.acquire(row, launch)
            seen = 0
            while streams:
                left = min(self.remaining(), hard - time.monotonic())
                if left <= 0:
                    raise TimeoutError('original command output target elapsed')
                for fd in select.select(list(streams), [], [], min(left, 0.1))[0]:
                    try:
                        block = os.read(fd, 16384)
                    except BlockingIOError:
                        continue
                    label, _ = streams[fd]
                    if not block:
                        streams.pop(fd)
                        continue
                    seen += len(block)
                    self.total_output += len(block)
                    if seen > 64 << 20 or self.total_output > 512 << 20:
                        raise Blocked('actual build/inspection logs exceed finite capture bounds')
                    if owner[label + '_log'].write(block) != len(block):
                        raise OSError('incomplete original build log write')
            code = self.wait(owner, hard)
            if code:
                raise ToolFailure('actual tool/build command failed: ' + name + ' exit=' + str(code))
        except BaseException as error:
            self.cleaning = True
            row['failure'] = reason(error)
            raise
        finally:
            self.retire(owner)
            for label in ('stdout', 'stderr'):
                if label in row:
                    try:
                        row[label + '_sha256'], row[label + '_bytes'] = digest(row[label], 64 << 20)
                    except BaseException as error:
                        self.cleanup_errors.append({'stage': 'build-log-final-hash', 'error': reason(error)})
            if owner['process'] is None or row['reaped']:
                self.current = None
        if self.cleanup_errors:
            raise Blocked('actual command retirement/log capture failed; no subsequent build step is admitted')
        return row

    def git(self, git, source, name, args):
        row = self.run(name, [git, '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                              '-c', 'core.autocrlf=false', '-c', 'submodule.recurse=false',
                              '-C', source] + args, timeout=60)
        data = Path(row['stdout']).read_bytes()
        if len(data) > 16 << 20:
            raise Blocked('Git public source metadata exceeds bound')
        return data


def tree_state(runner, git, source, label, expected, tag=None):
    head = runner.git(git, source, label + '-head', ['rev-parse', 'HEAD']).decode().strip()
    if head != expected:
        raise Blocked('actual source HEAD differs from required pinned commit')
    if tag is not None:
        found = runner.git(git, source, label + '-tag', ['rev-parse', tag + '^{}']).decode().strip()
        if found != expected:
            raise Blocked('actual release tag differs from the required commit')
    runner.git(git, source, label + '-clean', ['diff', '--quiet', '--no-ext-diff', '--no-textconv', '--ignore-submodules=all', 'HEAD', '--'])
    status = runner.git(git, source, label + '-status', ['status', '--porcelain', '--untracked-files=all', '--ignore-submodules=all'])
    if status:
        raise Blocked('source worktree has tracked/untracked modifications')
    entries = runner.git(git, source, label + '-entries', ['ls-files', '--stage', '-z'])
    table = []
    for entry in entries.split(b'\0'):
        if not entry:
            continue
        fields, name = entry.split(b'\t', 1)
        mode, obj, stage = fields.decode('ascii').split()
        relative = Path(os.fsdecode(name))
        if stage != '0' or relative.is_absolute() or '..' in relative.parts:
            raise Blocked('unmerged/escaping official source entry')
        table.append((name, mode, obj, source / relative))
    if not 1 <= len(table) <= 10000:
        raise Blocked('actual tracked source entry count is outside bounds')
    h = hashlib.sha256()
    total, links = 0, []
    for name, mode, obj, path in sorted(table):
        runner.remaining()
        if mode == '160000':
            data = ('gitlink:' + obj).encode()
            links.append({'path': os.fsdecode(name), 'commit': obj})
        elif path.is_symlink():
            data = os.fsencode(os.readlink(path))
        else:
            size = path.stat().st_size
            if not path.is_file() or size > 64 << 20:
                raise Blocked('tracked public source is missing/too large')
            h.update(len(name).to_bytes(8, 'big') + name + size.to_bytes(8, 'big'))
            count = 0
            with path.open('rb') as stream:
                while True:
                    block = stream.read(65536)
                    if not block:
                        break
                    h.update(block);count += len(block)
            if count != size:
                raise Blocked('tracked source changed while fingerprinting')
            total += size
            if total > 1 << 30:
                raise Blocked('tracked public source exceeds1GiB')
            continue
        h.update(len(name).to_bytes(8, 'big') + name + len(data).to_bytes(8, 'big') + data)
    return {'revision': head, 'tag': tag, 'tracked_files': len(table),
            'tracked_input_sha256': h.hexdigest(), 'gitlinks': links,
            'tracked_sources_clean': True, 'tracked_bytes': total}


def source_state(runner, git, source, label):
    main = tree_state(runner, git, source, label, REVISION, 'v0.29.1')
    if main['gitlinks'] != [{'path': 'doc/handbook', 'commit': HANDBOOK}]:
        raise Blocked('fixed source gitlink inventory differs from reviewed handbook')
    book = tree_state(runner, git, source / 'doc/handbook', label + '-handbook', HANDBOOK)
    if book['gitlinks']:
        raise Blocked('unexpected recursive handbook gitlinks require explicit source preparation')
    return {'main': main, 'handbook': book}


def build(request_path, approval_path, output):
    if output.exists() or not inside(output, '/private/tmp'):
        raise Blocked('output must be a fresh private /private/tmp root')
    output.mkdir(mode=0o700)
    report = {'schema': 1, 'kind': 'selected-unmodified-official-c-conversation-build',
              'status': 'blocked', 'commands': [], 'runtime_closure_staged': False,
              'generated_defaults_complete': False, 'phone_plugin_present': False,
              'build_executed': False, 'normal_products_executed': False,
              'audio_helpers_built': False, 'audio_helpers_executed': False,
              'download_or_dependency_install': False, 'runtime_verified': False,
              'source_unchanged': None,
              'product_execution_qualification': 'No selected GNUnet daemon, CLI or helper is launched; normal Meson compiler/configure probes are separately authorized.'}
    runner, previous = None, {}
    stager = None
    bindings, original_state, copied_state = [], None, None
    source = original = None
    tools = {}
    try:
        request = metadata(request_path)
        approve = metadata(approval_path)
        module = Path(__file__).with_name('conversation_build_stage.py')
        if approve.get('schema') != 1 or approve.get('authorized') is not True or approve.get('profile') != PROFILE or set(approve.get('permissions', [])) != PERMISSIONS:
            raise Blocked('new explicit private C build authorization is absent or scope differs')
        if approve.get('request_sha256') != digest(request_path)[0] or approve.get('builder_sha256') != digest(__file__)[0] or approve.get('stager_sha256') != digest(module)[0]:
            raise Blocked('approval does not bind the exact reviewed tools/request')
        if not isinstance(approve.get('human_authorization_reference'), str) or not approve['human_authorization_reference'].strip() or not time.time() < approve.get('expires_unix', 0) <= time.time() + 86400:
            raise Blocked('actual human authorization reference/current expiry is absent')
        if request.get('schema') != 1 or request.get('official_revision') != REVISION or request.get('profile') != PROFILE:
            raise Blocked('request is not the fixed selected native C build profile')
        if platform.system() not in ('Darwin', 'Linux'):
            raise Blocked('selected native build platform unsupported')
        required_tools = {'git', 'meson', 'ninja', 'cc', 'pkg_config', 'otool' if platform.system() == 'Darwin' else 'readelf'}
        if set(request.get('tools', {})) != required_tools:
            raise Blocked('all actual existing build/inspection tools must be explicitly supplied')
        for name, row in request['tools'].items():
            tools[name] = checked(row)
            if not os.access(tools[name], os.X_OK):
                raise Blocked('required actual tool is not executable')
            bindings.append(reference(tools[name]))
        original = Path(request['source']).resolve()
        roots = [Path(p).resolve() for p in request['readonly_roots']]
        if not roots or len(roots) > 64 or any(not p.is_dir() or inside(output, p) or inside(p, output) for p in roots):
            raise Blocked('existing readonly dependency roots are missing/overlap output')
        if not original.is_dir() or inside(output, original) or inside(original, output):
            raise Blocked('official existing source and private output overlap')
        for row in request.get('input_receipts', []):
            bindings.append(reference(checked(row)))
        if not request.get('input_receipts') or len(bindings) > 128:
            raise Blocked('actual dependency/toolchain input evidence is missing/unbounded')
        library_dirs = [Path(p).resolve() for p in request['library_dirs']]
        pc_dirs = [Path(p).resolve() for p in request['pkg_config_dirs']]
        if not library_dirs or not pc_dirs or len(library_dirs) > 128 or len(pc_dirs) > 128 or any(not p.is_dir() or not any(inside(p, r) for r in roots) for p in library_dirs + pc_dirs):
            raise Blocked('explicit existing dependency/pkg-config directories are absent/outside supplied roots')
        path_dirs = [Path(p).resolve() for p in request.get('path_dirs', [])]
        if len(path_dirs) > 64 or any(not p.is_dir() or not any(inside(p, r) for r in roots) for p in path_dirs):
            raise Blocked('explicit existing build-program PATH directories are outside supplied readonly roots')
        home = output / 'home';home.mkdir(mode=0o700)
        temp = output / 'tmp';temp.mkdir(mode=0o700)
        env = {'PATH': os.pathsep.join(dict.fromkeys([str(p.parent) for p in tools.values()] + [str(p) for p in path_dirs] + ['/usr/bin', '/bin'])),
               'HOME': str(home), 'TMPDIR': str(temp), 'XDG_CACHE_HOME': str(home / 'cache'),
               'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1',
               'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
               'GIT_OPTIONAL_LOCKS': '0', 'GIT_ALLOW_PROTOCOL': 'file', 'GIT_NO_LAZY_FETCH': '1',
               'CC': str(tools['cc']), 'NINJA': str(tools['ninja']), 'PKG_CONFIG': str(tools['pkg_config']),
               'PKG_CONFIG_PATH': os.pathsep.join(str(p) for p in pc_dirs),
               'PKG_CONFIG_LIBDIR': os.pathsep.join(str(p) for p in pc_dirs)}
        allowed = {'CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'SDKROOT', 'DEVELOPER_DIR', 'MACOSX_DEPLOYMENT_TARGET'}
        flags = request.get('environment', {})
        if not isinstance(flags, dict) or not set(flags) <= allowed or any(not isinstance(v, str) or '\0' in v or '\n' in v for v in flags.values()):
            raise Blocked('only explicitly reviewed normal compiler flag/SDK environment is accepted')
        env.update(flags)
        jobs = request.get('jobs', 4)
        if not isinstance(jobs, int) or not 1 <= jobs <= 16:
            raise Blocked('jobs must be1 through16')
        report.update(request=reference(request_path), approval=reference(approval_path),
                      tools=[reference(p) for p in tools.values()], environment=env,
                      native_system=platform.system(), native_machine=platform.machine())
        logs = output / 'logs';logs.mkdir(mode=0o700)
        runner = Runner(logs, env, request.get('build_seconds', 3600))
        report['commands'] = runner.rows
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise Blocked('builder requires exclusive consuming wait ownership')
        def interrupted(signum, _frame):
            if runner.cleaning:
                runner.interruption(signum)
                return
            raise InterruptedError('original private C build interrupted by signal ' + str(signum))
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.getsignal(sig)
            signal.signal(sig, interrupted)
        for name in sorted(required_tools):
            if name not in ('otool', 'readelf'):
                runner.run('tool-version-' + name, [tools[name], '--version'], timeout=30)
        original_state = source_state(runner, tools['git'], original, 'original-before')
        save(output / 'source-original-before.json', original_state)
        source = output / 'source'
        git = tools['git']
        runner.run('private-clone', [git, '-c', 'core.hooksPath=/dev/null', 'clone', '--no-hardlinks', '--no-checkout', '--no-recurse-submodules', original, source], timeout=120)
        runner.git(git, source, 'private-checkout', ['checkout', '--detach', REVISION])
        runner.run('handbook-clone', [git, '-c', 'core.hooksPath=/dev/null', 'clone', '--no-hardlinks', '--no-checkout', '--no-recurse-submodules', original / 'doc/handbook', source / 'doc/handbook'], timeout=120)
        runner.git(git, source / 'doc/handbook', 'handbook-checkout', ['checkout', '--detach', HANDBOOK])
        copied_state = source_state(runner, git, source, 'private-before')
        if copied_state != original_state:
            raise Blocked('private source copy is not the exact complete original closure')
        save(output / 'source-before.json', copied_state)
        builddir, prefix, deps = output / 'build', output / 'prefix', output / 'deps'
        report.update(source=str(source), build=str(builddir), prefix=str(prefix), deps=str(deps))
        setup = [tools['meson'], 'setup', builddir, source, '--prefix=' + str(prefix), '--libdir=lib',
                 '--buildtype=debugoptimized', '--wrap-mode=nodownload', '-Ddisable-autostart=true',
                 '-Dexclude-manpages=true', '-Dinstall-rpath=true', '-Dtestbed=false', '-Dexperimental=false']
        runner.run('meson-setup', setup, timeout=1200)
        index, installed = target_index(builddir)
        selected = list(TARGETS.values()) + list(PLUGIN_TARGETS)
        missing = [name for name in selected if name not in index]
        if missing:
            raise Blocked('actual normal Conversation/backend/plugin graph missing: ' + ','.join(missing))
        if len(selected) != 31:
            raise Blocked('internal selected target contract drift')
        machines = metadata(builddir / 'meson-info/intro-machines.json')
        native = {'arm64': 'aarch64', 'aarch64': 'aarch64', 'x86_64': 'x86_64'}.get(platform.machine())
        if machines.get('host', {}).get('cpu_family') != native or machines.get('host', {}).get('system') != ('darwin' if platform.system() == 'Darwin' else 'linux'):
            raise Blocked('actual Meson host machine is not the selected native target')
        runner.run('meson-selected-compile-link', [tools['meson'], 'compile', '-C', builddir, '-j', str(jobs)] + selected, timeout=2400)
        for name in ('gnunet-helper-audio-record', 'gnunet-helper-audio-playback'):
            if name not in index:
                raise Blocked('selected real Conversation backend lacks its normal declared audio targets')
            if any(Path(p).exists() for p in index[name].get('filename', [])):
                report['audio_helpers_built'] = True
                raise ToolFailure('excluded audio helper was unexpectedly built')
        stager = Stager(builddir, source, prefix, deps, tools, runner.run, roots + [builddir], library_dirs)
        for ident, name in TARGETS.items():
            stager.stage_target(name, ident, 'binary')
        for name in PLUGIN_TARGETS:
            stager.stage_target(name, 'c.plugin.' + name, 'plugin')
        closure = stager.closure()
        defaults = stager.defaults(required={
            'util.conf', 'conversation.conf', 'identity.conf', 'peerstore.conf',
            'gns.conf', 'namestore.conf', 'namecache.conf', 'dht.conf',
            'pils.conf', 'transport.conf',
        })
        save(output / 'runtime-closure.json', closure)
        save(output / 'raw-defaults.json', defaults)
        report.update(runtime_closure_staged=closure['runtime_closure_staged'],
                      generated_defaults_complete=defaults['generated_defaults_complete'],
                      phone_plugin_present='c.plugin.gnunet_plugin_gnsrecord_conversation' in stager.artifacts)
        generated = []
        for path in builddir.rglob('*.h'):
            if len(generated) >= 1024 or not path.is_file():
                raise Blocked('generated header inventory exceeds bounded regular-file profile')
            generated.append(reference(path))
        if not any(Path(p['path']).name == 'gnunet_private_config.h' for p in generated):
            raise Blocked('normal generated private configuration header missing')
        save(output / 'generated-headers.json', generated)
        infos = [reference(builddir / 'meson-info' / name) for name in ('intro-targets.json', 'intro-installed.json', 'intro-install_plan.json', 'intro-buildoptions.json', 'intro-machines.json')]
        compiler_info = builddir / 'meson-info/intro-compilers.json'
        if compiler_info.is_file():
            infos.append(reference(compiler_info))
        for name in ('compile_commands.json', 'meson-logs/meson-log.txt', 'build.ninja'):
            path = builddir / name
            if not path.is_file():
                raise Blocked('actual compiler/configure metadata missing: ' + name)
            infos.append(reference(path))
        save(output / 'actual-meson-metadata.json', infos)
        after = source_state(runner, git, source, 'private-after')
        original_after = source_state(runner, git, original, 'original-after')
        save(output / 'source-after.json', after);save(output / 'source-original-after.json', original_after)
        if after != copied_state or original_after != original_state:
            report['source_unchanged'] = False
            raise Blocked('private or original official tracked source changed')
        report['source_unchanged'] = True
        for row in stager.rows:
            if digest(row['built_path'])[0] != row['sha256'] or digest(row['path'])[0] != row['sha256']:
                raise Blocked('actual selected original/staged output changed')
        for row in bindings:
            if digest(row['path'])[0] != row['sha256']:
                raise Blocked('actual existing dependency/tool evidence changed')
        report['status'] = 'passed'
    except BaseException as error:
        report['failure'] = reason(error)
        report['status'] = 'blocked' if isinstance(error, Blocked) else 'failed'
    finally:
        if runner is not None:
            runner.cleaning = True
            report['build_executed'] = any(row['name'] == 'meson-selected-compile-link' and row['pid'] is not None for row in runner.rows)
            if runner.current is not None:
                try:
                    if not runner.current.get('retirement_attempted'):
                        runner.retire(runner.current)
                    if runner.current.get('process') is not None and not runner.current['row']['reaped']:
                        runner.cleanup_errors.append({'stage': 'owned-build-unreaped', 'error': {'type': 'OutcomeUnknown', 'message': 'original actual child remains unreaped; no group reuse or new build step is allowed'}})
                except BaseException as error:
                    runner.cleanup_errors.append({'stage': 'final-owned-build-retirement', 'error': reason(error)})
            # A failed configure/link still gets a readonly after-state attempt,
            # under the original target and only after actual child retirement.
            # Failure to obtain it remains unknown, never an unchanged-source
            # assertion, and never replaces the original build/interruption.
            if all(row['reaped'] for row in runner.rows):
                for directory, before, name, label in (
                    (source, copied_state, 'source-after.json', 'private-failure-after'),
                    (original, original_state, 'source-original-after.json', 'original-failure-after')):
                    if directory is not None and before is not None and not (output / name).exists():
                        try:
                            after = source_state(runner, tools['git'], directory, label)
                            save(output / name, after)
                            if after != before:
                                report['source_unchanged'] = False
                                report['status'] = 'failed'
                                report.setdefault('failure', {'type': 'SourceChanged', 'message': 'actual original/private tracked source changed during failed preparation'})
                        except BaseException as error:
                            runner.cleanup_errors.append({'stage': label, 'error': reason(error)})
                if report['source_unchanged'] is None and all((output / name).is_file() for name in (
                    'source-before.json', 'source-after.json', 'source-original-before.json', 'source-original-after.json')):
                    try:
                        report['source_unchanged'] = (
                            metadata(output / 'source-before.json') == metadata(output / 'source-after.json')
                            and metadata(output / 'source-original-before.json') == metadata(output / 'source-original-after.json'))
                    except BaseException as error:
                        runner.cleanup_errors.append({'stage': 'source-after-receipt-comparison', 'error': reason(error)})
            report['cleanup_errors'] = runner.cleanup_errors
            report['cleanup_signals'] = runner.signals
            if runner.cleanup_errors or any(runner.signals.values()) or any(not row['reaped'] for row in runner.rows):
                report['status'] = 'failed'
        for sig, handler in previous.items():
            try:
                signal.signal(sig, handler)
            except BaseException as error:
                report.setdefault('cleanup_errors', []).append({'stage': 'restore-handler', 'error': reason(error)})
                report['status'] = 'failed'
        if report['status'] != 'passed':
            report.update(runtime_closure_staged=False, generated_defaults_complete=False, phone_plugin_present=False)
        report['artifacts'] = stager.rows if stager is not None else []
        try:
            save(output / 'build-result.json', report)
            # Strict controller index: only actual completed selected build and
            # staging can set status passed or the three closure facts true.
            source_bindings = [reference(output / name) for name in (
                'source-before.json', 'source-after.json', 'source-original-before.json', 'source-original-after.json',
                'generated-headers.json', 'actual-meson-metadata.json', 'raw-defaults.json', 'runtime-closure.json') if (output / name).is_file()]
            source_bindings += bindings + [reference(request_path), reference(__file__), reference(Path(__file__).with_name('conversation_build_stage.py'))]
            result = {'schema': 1, 'kind': 'normal-binary-build', 'status': report['status'], 'implementation': 'c',
                      'official_revision': REVISION,
                      'modified_official_source': None if report['source_unchanged'] is None else not report['source_unchanged'],
                      'native_system': platform.system(), 'native_machine': platform.machine(),
                      'build_executed': report['build_executed'],
                      'runtime_closure_staged': report['runtime_closure_staged'],
                      'generated_defaults_complete': report['generated_defaults_complete'],
                      'phone_plugin_present': report['phone_plugin_present'],
                      'underlying_receipts': [reference(output / 'build-result.json')], 'source_bindings': source_bindings,
                      'artifacts': stager.artifacts if stager is not None else {},
                      'runtime_verified': False, 'whole_goal_complete': False}
            save(output / 'normal-build-index.json', result)
            save(output / 'controller-artifacts.json', stager.rows if stager is not None else [])
        except BaseException as error:
            sys.stderr.write(json.dumps({'report_failure': reason(error), 'original': report.get('failure')}) + '\n')
            return 2
    return 0 if report['status'] == 'passed' else 3 if report['status'] == 'blocked' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', required=True, type=Path)
    parser.add_argument('--approval', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if not all(p.is_absolute() for p in (args.request, args.approval, args.output)):
        parser.error('all explicit paths must be absolute')
    return build(args.request.resolve(), args.approval.resolve(), args.output.resolve())


if __name__ == '__main__':
    raise SystemExit(main())
