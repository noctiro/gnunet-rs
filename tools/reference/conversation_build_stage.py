"""Static selected-output staging; importing performs no tool/build/target run."""
import hashlib
import json
import os
from collections import deque
from pathlib import Path
import platform
import re
import shutil


class Blocked(RuntimeError):
    pass


def digest(path, maximum=1 << 30):
    h = hashlib.sha256()
    size = 0
    with Path(path).open('rb') as stream:
        while True:
            block = stream.read(65536)
            if not block:
                break
            size += len(block)
            if size > maximum:
                raise Blocked('named file exceeds finite staging bound: ' + str(path))
            h.update(block)
    return h.hexdigest(), size


def inside(path, root):
    return Path(path).resolve().is_relative_to(Path(root).resolve())


def metadata(path):
    if Path(path).stat().st_size > 32 << 20:
        raise Blocked('Meson JSON exceeds the finite introspection bound')
    return json.loads(Path(path).read_text())


def outputs(target, build, prefix):
    files, destinations = target.get('filename'), target.get('install_filename')
    if target.get('installed') is not True or not isinstance(files, list) or len(files) != 1 or not isinstance(destinations, list) or not 1 <= len(destinations) <= 16:
        raise Blocked('selected target lacks a single installed normal output: ' + target['name'])
    original = Path(files[0])
    if not inside(original, build) or not original.is_file():
        raise Blocked('declared target is not an actual built file: ' + str(original))
    result = []
    for value in destinations:
        path = Path(value)
        if not path.is_absolute() or not inside(path, prefix):
            raise Blocked('Meson install destination escapes the fresh prefix')
        result.append(path)
    return original, result


def target_index(build):
    root = build / 'meson-info'
    rows = metadata(root / 'intro-targets.json')
    installed = metadata(root / 'intro-installed.json')
    if not isinstance(rows, list) or not 1 <= len(rows) <= 10000 or not isinstance(installed, dict) or len(installed) > 20000:
        raise Blocked('unsupported or unbounded actual Meson introspection shape')
    result = {}
    for row in rows:
        name = row.get('name')
        if not isinstance(name, str) or name in result:
            raise Blocked('ambiguous actual Meson target name')
        result[name] = row
    return result, installed


class Stager:
    def __init__(self, build, source, prefix, deps, tools, run, roots, library_dirs):
        self.build, self.source, self.prefix, self.deps = build, source, prefix, deps
        self.tools, self.run = tools, run
        self.roots = [Path(p).resolve() for p in roots]
        self.library_dirs = [Path(p).resolve() for p in library_dirs]
        self.targets, self.installed = target_index(build)
        self.artifacts, self.rows, self.destinations = {}, [], {}
        self.queue, self.queued, self.examined = deque(), set(), set()
        self.inspections, self.system = [], []
        self.total_bytes = 0
        self.native = platform.system()
        if self.native not in ('Darwin', 'Linux'):
            raise Blocked('only explicit native Mach-O/ELF staging profiles are implemented')
        self.by_name = {}
        # This is an index of declarations, not evidence that each was built.
        # A needed entry is checked as an actual file before it can be staged.
        for target in self.targets.values():
            if target.get('installed') and target.get('type') == 'shared library':
                for value in (target.get('filename') or []) + (target.get('install_filename') or []):
                    key = Path(value).name
                    old = self.by_name.get(key)
                    if old is not None and old['name'] != target['name']:
                        raise Blocked('ambiguous Meson shared-library basename: ' + key)
                    self.by_name[key] = target

    def add(self, ident, original, target, kind, relative):
        original, target = Path(original), Path(target)
        value, size = digest(original)
        if ident in self.artifacts:
            if self.artifacts[ident] != {'path': str(target), 'sha256': value}:
                raise Blocked('artifact identifier collision: ' + ident)
            return
        if len(self.rows) >= 512 or self.total_bytes + size > 2 << 30:
            raise Blocked('selected runtime closure exceeds controller count/byte bounds')
        old = self.destinations.get(str(target))
        reused = False
        if old is not None:
            if old != value:
                raise Blocked('different real library/default bytes claim one install path')
        else:
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if target.exists():
                # A failed later inspection may leave an exact earlier copy in
                # this owned prefix. Resume staging without overwriting it or
                # pretending a different compiler output produced these bytes.
                if target.is_symlink() or not target.is_file() or digest(target) != (value, size):
                    raise Blocked('existing staging destination differs: ' + str(target))
                reused = True
            else:
                with original.open('rb') as src, target.open('xb') as dst:
                    shutil.copyfileobj(src, dst, 65536)
            target.chmod(0o555 if kind == 'binary' else 0o444)
            if digest(target)[0] != value:
                raise Blocked('actual copied participant changed: ' + str(target))
            self.destinations[str(target)] = value
        self.total_bytes += size
        self.artifacts[ident] = {'path': str(target), 'sha256': value}
        self.rows.append({'id': ident, 'implementation': 'c', 'kind': kind,
                          'path': str(target), 'sha256': value,
                          'snapshot_relative': relative, 'built_path': str(original),
                          'bytes': size, 'reused_existing_matching_file': reused})

    def stage_target(self, name, ident, kind):
        target = self.targets.get(name)
        if target is None:
            raise Blocked('normal required Meson target is unavailable: ' + name)
        original, destinations = outputs(target, self.build, self.prefix)
        actual_install = self.installed.get(str(original))
        if actual_install not in [str(p) for p in destinations]:
            raise Blocked('target/install introspection disagree for actual output: ' + name)
        if kind == 'binary' and (target.get('type') != 'executable' or not os.access(original, os.X_OK)):
            raise Blocked('normal participant is not a built executable: ' + name)
        if kind == 'plugin' and target.get('type') != 'shared module':
            raise Blocked('required dynamic plugin is not a normal shared module: ' + name)
        for index, destination in enumerate(destinations):
            if kind == 'binary' and index:
                raise Blocked('unexpected multiple binary install aliases')
            artifact = ident if index == 0 else 'c.library.' + destination.name
            relative = 'c-prefix/' + destination.relative_to(self.prefix).as_posix()
            self.add(artifact, original, destination, kind, relative)
        self.enqueue(original)
        return original

    def enqueue(self, image):
        image = Path(image).resolve()
        if image not in self.examined and image not in self.queued:
            if len(self.queued) + len(self.examined) >= 512:
                raise Blocked('static image closure exceeds finite bound')
            self.queue.append(image)
            self.queued.add(image)

    def tool(self, name, args):
        row = self.run('inspect-' + str(len(self.inspections)), [str(self.tools[name])] + [str(v) for v in args], timeout=30)
        self.inspections.append(row)
        path = Path(row['stdout'])
        if path.stat().st_size > 4 << 20:
            raise Blocked('static dependency metadata exceeds finite output bound')
        return path.read_text(errors='strict')

    def inspect(self, image):
        if self.native == 'Darwin':
            headers = self.tool('otool', ['-hv', image])
            expected = {'arm64': 'ARM64', 'aarch64': 'ARM64', 'x86_64': 'X86_64'}.get(platform.machine())
            if expected is None or not re.search(r'\b' + expected + r'\b', headers):
                raise Blocked('Mach-O image does not expose the selected native architecture')
            linked = self.tool('otool', ['-L', image])
            commands = self.tool('otool', ['-l', image])
            identities = set(re.findall(r'cmd LC_ID_DYLIB\s+cmdsize [0-9]+\s+name (.+?) \(offset [0-9]+\)', commands))
            needed = []
            if not linked.strip():
                raise Blocked('empty actual Mach-O linked-library metadata')
            for line in linked.splitlines():
                if not line.strip() or line.startswith(str(image)) and line.rstrip().endswith(':'):
                    continue
                match = re.match(r'^\s+(.+?) \(compatibility version ', line)
                if match is None:
                    raise Blocked('unrecognized actual Mach-O dependency metadata')
                if match[1] not in identities:
                    needed.append(match[1])
            rpaths = re.findall(r'cmd LC_RPATH\s+cmdsize [0-9]+\s+path (.+?) \(offset [0-9]+\)', commands)
            if len(needed) > 512 or len(rpaths) > 128:
                raise Blocked('Mach-O dependency/rpath count exceeds bound')
            return needed, rpaths
        headers = self.tool('readelf', ['-hW', image])
        expected = {'x86_64': 'Advanced Micro Devices X86-64', 'aarch64': 'AArch64', 'arm64': 'AArch64'}.get(platform.machine())
        if expected is None or not re.search(r'Machine:\s*' + re.escape(expected) + r'\s*$', headers, re.M):
            raise Blocked('ELF image is not the selected native architecture')
        dynamic = self.tool('readelf', ['-dW', image])
        needed = re.findall(r'\(NEEDED\).*?\[([^\]]+)\]', dynamic)
        rpaths = []
        for tag, value in re.findall(r'\((RPATH|RUNPATH)\).*?\[([^\]]*)\]', dynamic):
            if tag == 'RPATH' and any(p and not p.startswith(('/lib/', '/usr/lib/')) for p in value.split(':')):
                raise Blocked('non-system legacy DT_RPATH would outrank the selected LD_LIBRARY_PATH')
            rpaths.extend(value.split(':'))
        if len(needed) > 512 or len(rpaths) > 128:
            raise Blocked('ELF dependency/rpath count exceeds bound')
        # ELF's loader itself is an explicit native-system dependency, not copied
        # or executed as an application by this tool.
        program = self.tool('readelf', ['-lW', image])
        for token in re.findall(r'Requesting program interpreter:\s*([^\]]+)\]', program):
            if not self.system_token(token):
                raise Blocked('ELF interpreter is outside the native system profile')
            self.system.append({'image': str(image), 'interpreter': token,
                                'native_system_provided': True})
        return needed, rpaths

    def system_token(self, token):
        if not token.startswith('/'):
            return False
        normalized = str(Path(token).resolve())
        return normalized.startswith(('/usr/lib/', '/System/Library/')) if self.native == 'Darwin' else normalized.startswith(('/lib/', '/lib64/', '/usr/lib/', '/usr/lib64/'))

    def candidates(self, token, image, rpaths):
        if token.startswith('@loader_path/'):
            paths = [image.parent / token[len('@loader_path/'):]]
        elif token.startswith('@rpath/'):
            tail = token[len('@rpath/'):]
            if '/' in tail:
                raise Blocked('nested @rpath dependency requires an explicit additional profile')
            paths = []
            for path in rpaths:
                if path.startswith('@loader_path/'):
                    paths.append(image.parent / path[len('@loader_path/'):] / tail)
                elif path.startswith('/'):
                    paths.append(Path(path) / tail)
            paths += [directory / tail for directory in self.library_dirs]
        elif token.startswith('@') or '$' in token:
            raise Blocked('unsupported unresolved dynamic-loader token: ' + token)
        elif token.startswith('/'):
            paths = [Path(token)]
        elif '/' not in token:
            paths = []
            for path in rpaths:
                path = path.replace('${ORIGIN}', str(image.parent)).replace('$ORIGIN', str(image.parent))
                if '$' in path or not path.startswith('/'):
                    raise Blocked('unresolved native ELF runtime path')
                paths.append(Path(path) / token)
            paths += [directory / token for directory in self.library_dirs]
        else:
            raise Blocked('relative dependency path has no stable selected owner')
        found = {}
        for path in paths:
            if not path.is_file():
                continue
            real = path.resolve()
            if not self.system_token(str(real)) and not any(inside(real, root) for root in self.roots):
                raise Blocked('dependency resolves outside explicitly supplied readonly roots: ' + str(real))
            value, _ = digest(real)
            found.setdefault(value, real)
        if len(found) != 1:
            raise Blocked('required non-system dependency is missing/ambiguous: ' + token)
        return next(iter(found.values()))

    def closure(self):
        while self.queue:
            image = self.queue.popleft()
            self.queued.discard(image)
            if image in self.examined:
                continue
            if len(self.examined) >= 512:
                raise Blocked('static recursive library closure exceeds finite bound')
            self.examined.add(image)
            needed, rpaths = self.inspect(image)
            for token in needed:
                if self.system_token(token):
                    self.system.append({'image': str(image), 'dependency': token, 'native_system_provided': True})
                    continue
                basename = Path(token).name
                if basename in self.by_name:
                    target = self.by_name[basename]
                    self.stage_target(target['name'], 'c.library.' + Path(target['filename'][0]).name, 'library')
                    continue
                original = self.candidates(token, image, rpaths)
                if self.system_token(str(original)):
                    self.system.append({'image': str(image), 'dependency': token,
                                        'resolved': str(original), 'sha256': digest(original)[0],
                                        'native_system_provided': True})
                    continue
                destination = self.deps / 'lib' / basename
                self.add('c.dependency.' + basename, original, destination, 'library', 'deps/lib/' + basename)
                self.enqueue(original)
        return {'inspections': self.inspections, 'native_system_dependencies': self.system,
                'static_images': len(self.examined), 'runtime_closure_staged': True,
                'qualification': 'Actual static linked-file closure copied and hashed, with explicit native-system dependencies; not an executed loader or node receipt.'}

    def defaults(self, required=()):
        count = 0
        seen = set()
        for value, destination in self.installed.items():
            dest = Path(destination)
            base = self.prefix / 'share/gnunet/config.d'
            if not inside(dest, base):
                continue
            if not dest.name.endswith('.conf') or dest.name in seen:
                raise Blocked('unexpected/ambiguous raw normal default configuration')
            original = Path(value)
            if not original.is_file() or not (inside(original, self.build) or inside(original, self.source)):
                raise Blocked('declared normal default is not an actual generated/source file')
            seen.add(dest.name)
            self.add('c.default.' + dest.name, original, dest, 'default', 'c-prefix/' + dest.relative_to(self.prefix).as_posix())
            count += 1
        if not set(required) <= seen:
            raise Blocked('actual installed defaults lack a selected normal service')
        return {'generated_defaults_complete': True, 'count': count,
                'qualification': 'Every config.d file in this exact actual Meson installed map, copied without expansion or rewriting; two-node expansion remains separate.'}
