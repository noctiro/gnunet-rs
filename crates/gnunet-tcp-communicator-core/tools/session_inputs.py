#!/usr/bin/env python3
"""Full-workspace and unchanged-normal-C identity contracts for TCP evidence."""
import hashlib
import json
import os
import re
import shutil
import shlex
import stat
import subprocess
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
TOOLS = Path(__file__).resolve().parent
PIN = '346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
CORE = 'gnunet-tcp-communicator-core'
HOST = 'gnunet-tcp-communicator-host'
CRYPTO = 'gnunet-session-crypto'
PACKAGES = (CORE, HOST, CRYPTO)
CORE_PATH = Path('crates/gnunet-tcp-communicator-core')
HOST_PATH = Path('adapters/tcp-communicator-std')
CRYPTO_PATH = Path('crates/gnunet-session-crypto')
NOALLOC = Path('tests/embedded/noalloc')
EXCLUDED = {'.git', 'target', '__pycache__'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tree(root):
    """Include every source/settings/lock path; detect additions and deletions."""
    root = Path(root).resolve()
    rows = {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED)
        for name in [*dirs, *sorted(n for n in names if n not in EXCLUDED)]:
            p = Path(directory) / name
            rel = p.relative_to(root).as_posix()
            if p.is_symlink():
                target = os.readlink(p)
                rows[rel] = {'kind': 'symlink', 'target': target,
                             'sha256': hashlib.sha256(os.fsencode(target)).hexdigest()}
                require(not p.is_dir(),'source directory symlink requires explicit complete-tree policy')
                if p.is_file():
                    rows[rel]['target_file_sha256']=sha(p)
            elif p.is_file():
                rows[rel] = {'kind': 'file', 'sha256': sha(p), 'size': p.stat().st_size,
                             'mode': stat.S_IMODE(p.stat().st_mode)}
    require(bool(rows), 'empty source tree')
    return dict(sorted(rows.items(), key=lambda item: os.fsencode(item[0])))


def same(actual, expected, label):
    require(actual == expected, label + ' changed')


def disjoint_output(output, roots, workspace=None):
    output = Path(output).resolve()
    for item in roots:
        root = Path(item).resolve()
        if workspace is not None and root==Path(workspace).resolve() and output.is_relative_to(root/'target'):
            continue
        require(output != root and not output.is_relative_to(root)
                and not root.is_relative_to(output), 'output overlaps input ' + str(root))


def copy_workspace(repository, destination):
    repository, destination = Path(repository).resolve(), Path(destination).resolve()
    disjoint_output(destination, (repository, TOOLS),workspace=repository)
    before = tree(repository)
    shutil.copytree(repository, destination, symlinks=True,
                    ignore=lambda _directory, names: [n for n in names if n in EXCLUDED])
    same(tree(repository), before, 'original workspace during copy')
    same(tree(destination), before, 'complete copied workspace/settings/two locks')
    for path in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'rustfmt.toml',
                 '.cargo/config.toml', str(NOALLOC / 'Cargo.toml'), str(NOALLOC / 'Cargo.lock')):
        require(path in before, 'required workspace input absent: ' + path)
    return before


def _path(value, root):
    if isinstance(value, str):
        prefix = str(root)
        return '@WORKSPACE' + value[len(prefix):] if value == prefix or value.startswith(prefix + '/') else value
    if isinstance(value, list):
        return [_path(v, root) for v in value]
    if isinstance(value, dict):
        return {k: _path(v, root) for k, v in value.items()}
    return value


def metadata_contract(metadata, repository):
    """Preserve all declared normal/dev/build/target/rename/feature fields and graph."""
    repository = Path(repository).resolve()
    idmap = {}
    for p in metadata['packages']:
        if p['source'] is None:
            manifest = Path(p['manifest_path']).resolve()
            require(manifest.is_relative_to(repository), 'local dependency outside full workspace')
            key = 'local:' + manifest.parent.relative_to(repository).as_posix() + '#' + p['name'] + '@' + p['version']
        else:
            key = p['source'] + '#' + p['name'] + '@' + p['version']
        require(key not in idmap.values(), 'duplicate package identity')
        idmap[p['id']] = key
    packages = {}
    for p in metadata['packages']:
        value = _path(p, repository)
        value['id'] = idmap[p['id']]
        value['dependencies'] = sorted(value['dependencies'], key=lambda d: json.dumps(d, sort_keys=True))
        value['targets'] = sorted(value['targets'], key=lambda d: json.dumps(d, sort_keys=True))
        packages[value['id']] = value
    resolve = metadata.get('resolve')
    nodes = {}
    if resolve:
        for node in resolve['nodes']:
            value = _path(node, repository)
            value['id'] = idmap[node['id']]
            value['dependencies'] = sorted(idmap[x] for x in node['dependencies'])
            value['deps'] = sorted(({**d, 'pkg': idmap[d['pkg']],
                                     'dep_kinds': sorted(d['dep_kinds'], key=lambda k: json.dumps(k, sort_keys=True))}
                                    for d in node['deps']), key=lambda d: json.dumps(d, sort_keys=True))
            value['features'] = sorted(value['features'])
            nodes[value['id']] = value
    session = [p for p in metadata['packages'] if p['name'] == CRYPTO]
    require(len(session) == 1 and session[0]['source'] is None, 'unique local session-crypto type identity required')
    return {'packages': packages, 'workspace_members': sorted(idmap[x] for x in metadata['workspace_members']),
            'workspace_default_members': sorted(idmap[x] for x in metadata['workspace_default_members']),
            'resolve_nodes': nodes, 'resolve_root': idmap.get(resolve.get('root')) if resolve else None,
            'workspace_metadata': _path(metadata.get('metadata'), repository)}


def role_contract(repository):
    """Use the actual complete reviewed Root architecture table, without a subset."""
    text = (Path(repository) / 'tools/xtask/src/checks.rs').read_text()
    roles = {}
    for body in re.findall(r'Policy\s*\{(.*?)\n\s*\}', text, re.S):
        name = re.search(r'name:\s*"([^"]+)"', body)
        if name is None:
            continue
        directory = re.search(r'directory:\s*"([^"]+)"', body)
        core = re.search(r'core:\s*(true|false)', body)
        deps = re.search(r'dependencies:\s*&\[(.*?)\]', body, re.S)
        require(directory is not None and core is not None and deps is not None, 'incomplete architecture role')
        require(name[1] not in roles, 'duplicate architecture role')
        roles[name[1]] = {'directory': directory[1], 'core': core[1] == 'true',
                          'dependencies': re.findall(r'"([^"]+)"', deps[1])}
    require(roles.get(CORE, {}).get('core') is True and roles.get(HOST, {}).get('core') is False
            and roles.get(CRYPTO, {}).get('core') is True, 'TCP full-workspace role contract absent')
    return roles


def registry_contract(path):
    rows = []
    for block in Path(path).read_text().split('[[package]]')[1:]:
        values = {}
        for field in ('name', 'version', 'source', 'checksum'):
            match = re.search(r'^' + field + r'\s*=\s*(".*")\s*$', block, re.M)
            if match:
                values[field] = json.loads(match[1])
        if 'source' in values:
            require(values['source'].startswith('registry+') and len(values.get('checksum', '')) == 64,
                    'registry identity/checksum missing')
            rows.append(values)
    require(rows and len({(r['name'], r['version'], r['source']) for r in rows}) == len(rows),
            'empty/duplicate registry lock contract')
    return sorted(rows, key=lambda r: (r['name'], r['version'], r['source']))


def workspace_contract(repository, metadata_profiles):
    root = Path(repository)
    contracts = {name: metadata_contract(value, root) for name, value in metadata_profiles.items()}
    roles = role_contract(root)
    default = metadata_profiles['default']
    members = [p for p in default['packages'] if p['id'] in default['workspace_members']]
    require({p['name'] for p in members} == set(roles), 'complete workspace role/member set differs')
    for p in members:
        role = roles[p['name']]
        require(Path(p['manifest_path']).resolve() == (root / role['directory'] / 'Cargo.toml').resolve(),
                'architecture package directory mismatch')
        require(all(d['name'] in role['dependencies'] for d in p['dependencies']), 'forbidden architecture dependency')
    host = next(p for p in members if p['name'] == HOST)
    require(any(d['name'] == 'tokio' and d['kind'] == 'dev' and 'macros' in d['features'] for d in host['dependencies']),
            'actual host dev-only Tokio macros contract absent')
    require(not any(d['name'] == 'tokio' and d['kind'] != 'dev' and 'macros' in d['features'] for d in host['dependencies']),
            'Tokio macros leaked into host normal/build dependency')
    locks = {'workspace': registry_contract(root / 'Cargo.lock'),
             'noalloc': registry_contract(root / NOALLOC / 'Cargo.lock')}
    require([r['version'] for r in locks['workspace'] if r['name'] == 'tokio-macros'] == ['2.7.2'],
            'reviewed current tokio-macros2.7.2 registry package absent')
    require(not any(r['name'] == 'tokio-macros' for r in locks['noalloc']), 'Tokio macros entered noalloc registry lock')
    return {'metadata': contracts, 'roles': roles, 'registries': locks,
            'registry_note': 'tokio-macros2.7.2 is a current dev-only Root addition; no claim of zero registry change'}


def historical_builder(repository,kind,expected_sha256):
    """Validate historical source data explicitly; never execute archived Python."""
    tools=Path(repository)/CORE_PATH/'tools'
    name='build_peer_normal.py'if kind.endswith('peer-services-reference-build')else'build_normal.py'
    current=tools/name
    require(current.is_file(),'normal builder source missing')
    current_sha=sha(current)
    if current_sha==expected_sha256:
        return{'kind':'current-builder-source','path':str(current.resolve()),'sha256':current_sha,
               'archived':False,'executed_by_verifier':False}
    mapping=tools/'historical-builders.json'
    require(mapping.is_file(),'historical normal builder provenance map absent')
    document=json.loads(mapping.read_text())
    require(document.get('schema')==1,'historical builder provenance schema differs')
    entries=[r for r in document['entries']if r['builder']==name and r['profile_kind']==kind
             and r['original_sha256']==expected_sha256]
    require(len(entries)==1,'unique exact historical normal builder binding required')
    row=entries[0];archive=(tools/row['archive']).resolve()
    require(archive.is_relative_to((tools/'history').resolve())and archive.suffix=='.snapshot'
            and archive.is_file()and not(archive.stat().st_mode&0o111)
            and row.get('archive_executed')is False,'historical builder must be inert source data')
    require(sha(archive)==expected_sha256 and current_sha==row['replacement_builder_sha256'],
            'historical/current builder source bytes differ from reviewed provenance')
    return{'kind':'historical-builder-source-data','path':str(archive),'sha256':expected_sha256,
           'archived':True,'executed_by_verifier':False,'provenance':str(mapping.resolve()),
           'provenance_sha256':sha(mapping),'current_builder':str(current.resolve()),
           'current_builder_sha256':current_sha,'reason':'Existing immutable receipt binds original builder bytes; '
           'active builder assertions were explicitly converted to raises, not relabeled as the old build.'}


class Commands:
    def __init__(self, output, repository, environment=None):
        self.output, self.repository = Path(output), Path(repository)
        self.env = os.environ.copy()
        self.env.update(environment or {})
        self.env.update(PYTHONDONTWRITEBYTECODE='1', CARGO_BUILD_JOBS='1',
                        CARGO_TARGET_DIR=str(self.output / 'target'))
        self.rows = []
        self.artifacts = {}
        self.headers = {}

    def run(self, label, argv, stdin=b'', cwd=None, timeout=480):
        argv = list(map(str, argv))
        result = subprocess.run(argv, cwd=cwd or self.repository, env=self.env, input=stdin,
                                capture_output=True, timeout=timeout)
        stdout, stderr = (self.output / (label + ending) for ending in ('.stdout', '.stderr'))
        stdout.write_bytes(result.stdout)
        stderr.write_bytes(result.stderr)
        self.rows.append({'label': label, 'argv': argv, 'cwd': str(cwd or self.repository),
                          'exit': result.returncode, 'stdin_sha256': hashlib.sha256(stdin).hexdigest(),
                          'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr)})
        require(result.returncode == 0, label + ' failed')
        return result.stdout

    def metadata(self, label, profile=()):
        return json.loads(self.run(label, ['cargo', '+1.99.1', 'metadata', '--manifest-path',
                                         self.repository / 'Cargo.toml', '--locked', '--offline',
                                         '--format-version=1', *profile]))

    def bind(self, path):
        path = Path(path).resolve()
        require(path.is_file(), 'actual artifact missing')
        self.artifacts[str(path)] = sha(path)
        return path

    def check_artifacts(self):
        require(all(Path(p).is_file() and sha(p) == digest for p, digest in self.artifacts.items()),
                'actual built/executed binary changed')
        require(all(Path(p).is_file() and sha(p)==digest for p,digest in self.headers.items()),
                'actual C compiler header/source input changed')

    def compile_c(self,label,argv,cwd):
        """Bind actual full preprocessor dependencies before compile and afterward."""
        argv=list(map(str,argv));cwd=Path(cwd)
        prep=[argv[0]];index=1
        while index<len(argv):
            value=argv[index]
            if value=='-o':index+=2;continue
            if value.startswith(('-L','-l','-Wl,')):index+=1;continue
            prep.append(value);index+=1
        before_file=self.output/(label+'-before.d')
        actual_file=self.output/(label+'-actual.d')
        self.run(label+'-dependencies',[*prep,'-M','-MF',before_file,'-MT','tcp-witness'],cwd=cwd)
        def dependencies(path):
            content=Path(path).read_text().replace('\\\n',' ')
            require(content.startswith('tcp-witness:'),'actual compiler dependency rule absent')
            names=shlex.split(content[len('tcp-witness:'):])
            require(bool(names),'empty compiler dependency set')
            return{str((cwd/Path(name)).resolve()):sha((cwd/Path(name)).resolve())for name in names}
        before=dependencies(before_file)
        self.run(label,[*argv,'-MD','-MF',actual_file,'-MT','tcp-witness'],cwd=cwd)
        same(dependencies(actual_file),before,'actual compiler dependency file set/bytes')
        for path,digest in before.items():
            require(path not in self.headers or self.headers[path]==digest,'compiler input changed between profiles')
            self.headers[path]=digest

    def example(self, package, name):
        output = self.run('build-' + name, ['cargo', '+1.99.1', 'build', '--manifest-path',
                          self.repository / 'Cargo.toml', '--locked', '--offline', '-p', package,
                          '--example', name, '--message-format=json', '-j', '1'])
        artifacts = [json.loads(row) for row in output.splitlines() if row.startswith(b'{')]
        finished = [a for a in artifacts if a.get('reason') == 'build-finished']
        require(len(finished) == 1 and finished[0].get('success') is True, 'Cargo successful finish absent')
        choices = [a for a in artifacts if a.get('reason') == 'compiler-artifact'
                   and a['target']['name'] == name and 'example' in a['target']['kind'] and a.get('executable')]
        require(len(choices) == 1, 'unique actual Cargo example artifact required')
        require(Path(choices[0]['manifest_path']).resolve() ==
                (self.repository / (CORE_PATH if package == CORE else HOST_PATH) / 'Cargo.toml').resolve(),
                'Cargo example belongs to wrong package')
        return self.bind(choices[0]['executable'])

    def tests(self):
        selected = [piece for name in PACKAGES for piece in ('-p', name)]
        cargo = ['cargo', '+1.99.1', 'test', '--manifest-path', self.repository / 'Cargo.toml',
                 '--locked', '--offline', *selected, '-j', '1', '--message-format=json']
        built = self.run('test-build', [*cargo, '--no-run'])
        def executables(data):
            rows = [json.loads(line) for line in data.splitlines() if line.startswith(b'{')]
            return {str(Path(r['executable']).resolve()) for r in rows
                    if r.get('reason') == 'compiler-artifact' and r.get('executable')
                    and r['profile']['test'] and Path(r['manifest_path']).resolve()
                    in {(self.repository / p / 'Cargo.toml').resolve() for p in (CORE_PATH, HOST_PATH, CRYPTO_PATH)}}
        before = executables(built)
        require(len(before) == 11, 'exact11 actual selected test executables required')
        for binary in before:
            self.bind(binary)
        tested = self.run('rust-tests', cargo)
        same(executables(tested), before, 'actual selected test executable set')
        self.check_artifacts()
        return check_tests(tested.decode())

    def xtask(self):
        output = self.run('build-xtask', ['cargo', '+1.99.1', 'build', '--manifest-path',
                          self.repository / 'Cargo.toml', '--locked', '--offline', '-p', 'xtask',
                          '--bin', 'xtask', '--message-format=json', '-j', '1'])
        rows = [json.loads(line) for line in output.splitlines() if line.startswith(b'{')]
        choices = [r for r in rows if r.get('reason') == 'compiler-artifact'
                   and r['target']['name'] == 'xtask' and r.get('executable')]
        require(len(choices) == 1 and Path(choices[0]['manifest_path']).resolve()
                == (self.repository / 'tools/xtask/Cargo.toml').resolve(), 'actual complete-workspace xtask artifact required')
        return self.bind(choices[0]['executable'])


class Reference:
    def __init__(self, repository, source, receipt, kind):
        self.repo, self.source, self.receipt = (Path(p).resolve() for p in (repository, source, receipt))
        self.normal = json.loads(self.receipt.read_text())
        self.kind = kind
        self.helper = self.repo / 'tools/reference/build_reference.py'
        self.module = types.ModuleType('tcp_source_identity')
        self.module.__file__ = str(self.helper)
        exec(compile(self.helper.read_bytes(), str(self.helper), 'exec'), self.module.__dict__)
        self.check()

    def check(self):
        n = json.loads(self.receipt.read_text())
        require(n == self.normal and n['status'] == 'passed' and n['kind'] == self.kind
                and n['source_unchanged'] is True and Path(n['source']).resolve() == self.source,
                'normal reference receipt/profile changed')
        require(n['upstream']['revision'] == PIN and n['upstream']['tag'] == 'v0.29.1'
                and self.module.source_state(self.source) == n['upstream'], 'normal complete C source state changed')
        setups = [r for r in n['commands'] if r.get('name') == 'meson-setup']
        require(len(setups) == 1 and setups[0]['exit_code'] == 0, 'unique successful Meson setup required')
        argv = setups[0]['argv']
        require(argv[1] == 'setup' and Path(argv[2]).resolve() == Path(n['build']).resolve()
                and Path(argv[3]).resolve() == self.source and '--prefix=' + n['prefix'] in argv,
                'normal Meson actual source/build/prefix differs')
        prefix = Path(n['prefix']).resolve()
        for name in ('DYLD_LIBRARY_PATH', 'LD_LIBRARY_PATH'):
            require(Path(n['runtime_environment'][name]).resolve() == prefix / 'lib', 'normal runtime prefix differs')
        require(Path(n['runtime_environment']['GNUNET_PREFIX']).resolve() == prefix, 'normal GNUnet prefix differs')
        self.builder_provenance=historical_builder(self.repo,self.kind,n['builder_sha256'])
        for name,digest in n['inputs'].items():
            path=self.helper if name.endswith('/tools/reference/build_reference.py')else Path(name)
            require(path.is_file()and sha(path)==digest,'declared normal build input differs')
        rows = [*n['artifacts'].values(), *n['libraries'], n['generated_config'], n['compile_commands']]
        for row in rows:
            require(Path(row['path']).is_file() and sha(row['path']) == row['sha256'], 'declared normal artifact changed')
        return rows

    def inputs(self):
        rows = self.check()
        paths = {self.helper, self.receipt, *(Path(r['path']).resolve() for r in rows)}
        paths.add(Path(self.builder_provenance['path']))
        if self.builder_provenance['archived']:
            paths|={Path(self.builder_provenance['provenance']),Path(self.builder_provenance['current_builder'])}
        paths |= {Path(name).resolve()for name in self.normal['inputs']if not name.endswith('/tools/reference/build_reference.py')}
        paths |= {p.resolve() for p in Path(self.normal['build']).rglob('*.h') if p.is_file()}
        queue = [Path(r['path']).resolve() for r in rows if Path(r['path']).suffix in ('', '.dylib')]
        seen = set()
        search = [Path(self.normal['prefix']) / 'lib']
        while queue:
            original = queue.pop()
            if original in seen:
                continue
            seen.add(original)
            result = subprocess.run(['/usr/bin/otool', '-L', str(original)], capture_output=True)
            require(result.returncode == 0, 'native dependency inspection failed')
            for line in result.stdout.decode().splitlines()[1:]:
                name = line.strip().split(' (', 1)[0]
                if name.startswith('@rpath/'):
                    candidates = [p / name[len('@rpath/'):] for p in search]
                elif name.startswith(('@loader_path/', '@executable_path/')):
                    candidates = [original.parent / name.split('/', 1)[1]]
                else:
                    candidates = [Path(name)]
                found = next((p.resolve() for p in candidates if p.is_file()), None)
                if found is None:
                    require(name.startswith(('/usr/lib/', '/System/Library/')), 'unresolved non-system native provider')
                    continue
                paths.add(found)
                if found not in seen:
                    queue.append(found)
        return {str(p): sha(p) for p in sorted(paths, key=os.fsencode)}


class Inputs:
    def __init__(self, repository, source, reference, output, kind):
        self.repo = Path(repository).resolve()
        self.reference = Reference(self.repo, source, reference, kind)
        disjoint_output(output, (self.repo, source, Path(reference).parent, self.reference.normal['prefix'], TOOLS),workspace=self.repo)

    def discover(self):
        reference=self.reference.inputs()
        return {'workspace': tree(self.repo), 'tools': tree(TOOLS), 'reference': reference,
                'normal_builder_provenance':self.reference.builder_provenance}


def require_processes(rows):
    require(rows and len({r['label'] for r in rows}) == len(rows), 'empty/duplicate process observations')
    for row in rows:
        require(row['exit'] == 0 and bool(row['binary_sha256'])
                and row['binary_sha256'] == row['after_sha256'], 'process failure or changed executable')


def check_tests(output):
    names = re.findall(r'^test (.+?) \.\.\. ok$', output, re.M)
    runtime = sorted(n for n in names if '.rs - ' not in n)
    docs = [re.sub(r' \(line \d+\)', '', n) for n in names if '.rs - ' in n]
    docs = [n.replace('crates/gnunet-session-crypto/', 'crypto/')
            .replace('crates/gnunet-tcp-communicator-core/', '') for n in docs]
    ignored = sorted(re.findall(r'^test (.+?) \.\.\. ignored,', output, re.M))
    required = json.loads((TOOLS / 'required-tests.json').read_text())
    require(len(required['runtime']) == 79 and len(required['docs']) == 9 and len(required['ignored']) == 3,
            'reviewed nonempty79/9/3 requirements absent')
    same(runtime, required['runtime'], 'exact79 runtime names')
    same(sorted(docs), required['docs'], 'exact9 compile-fail docs')
    same(ignored, required['ignored'], 'explicit ignored external oracle names')
    return {'runtime': runtime, 'docs': sorted(docs), 'ignored': ignored}


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--check-processes':
        try:
            require_processes(json.loads(Path(sys.argv[2]).read_text()))
        except ValueError as error:
            print('rejected-process-contract: ' + str(error), file=sys.stderr)
            sys.exit(2)
        print('valid-process-contract')
    else:
        raise ValueError('no standalone success path; use maintained verifier')
