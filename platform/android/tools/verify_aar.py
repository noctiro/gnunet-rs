"""Verify the staged Android publication and publish exact release artifacts."""

import fcntl
import hashlib
import io
import json
import re
import shutil
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from sdk_profile import read_profile

project, readelf, logs, output, version = sys.argv[1:]
project, logs, output = map(Path, (project, logs, output))
settings, targets = read_profile(project / 'sdk-profile.properties')
artifacts = list((project / 'build/outputs/aar').glob('*-release.aar'))
if len(artifacts) != 1:
    raise SystemExit('Expected exactly one current release AAR')

def sha256(path):
    with path.open('rb') as contents:
        return hashlib.file_digest(contents, 'sha256').hexdigest()

group, artifact = 'io.github.noctiro', 'gnunet-node-android'
coordinate = f'{group}:{artifact}:{version}'
repository = project / 'build/sdk-repository'
version_path = repository.joinpath(*group.split('.'), artifact, version)
basename = f'{artifact}-{version}'
published_aar = version_path / f'{basename}.aar'
aar_sha256 = sha256(artifacts[0])
if sha256(published_aar) != aar_sha256:
    raise SystemExit('Published AAR differs from the compiled release AAR')
ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
pom = ET.parse(version_path / f'{basename}.pom').getroot()
if tuple(pom.findtext(f'm:{key}', namespaces=ns)
         for key in ('groupId', 'artifactId', 'version', 'packaging')) != (group, artifact, version, 'aar'):
    raise SystemExit('Invalid Maven identity or packaging for the published AAR')
kotlin_versions = {dep.findtext('m:version', namespaces=ns)
                   for dep in pom.findall('m:dependencies/m:dependency', ns)
                   if dep.findtext('m:groupId', namespaces=ns) == 'org.jetbrains.kotlin'
                   and dep.findtext('m:artifactId', namespaces=ns) == 'kotlin-stdlib'
                   and dep.findtext('m:scope', default='compile', namespaces=ns) in {'compile', 'runtime'}}
if len(kotlin_versions) != 1 or not all(kotlin_versions):
    raise SystemExit('Published Maven AAR has no Kotlin runtime dependency')
module = json.loads((version_path / f'{basename}.module').read_bytes())
if tuple(module['component'].get(key) for key in ('group', 'module', 'version')) != (group, artifact, version):
    raise SystemExit('Invalid Gradle module identity for the published AAR')
runtime_variants = [variant for variant in module['variants']
                    if variant['attributes'].get('org.gradle.usage') == 'java-runtime']
if len(runtime_variants) != 1:
    raise SystemExit('Expected one Gradle runtime variant for the AAR')
runtime = runtime_variants[0]
if not any(dep.get('group') == 'org.jetbrains.kotlin' and dep.get('module') == 'kotlin-stdlib'
           and dep.get('version', {}).get('requires') in kotlin_versions for dep in runtime.get('dependencies', [])):
    raise SystemExit('Gradle runtime variant has no matching Kotlin standard library dependency')
if not any(file.get('url') == published_aar.name and file.get('sha256') == aar_sha256
           for file in runtime.get('files', [])):
    raise SystemExit('Gradle runtime variant does not name the verified AAR')

# The ELF identifiers are an independent acceptance check for each ABI.
elf_targets = {'arm64-v8a': (2, 183), 'armeabi-v7a': (1, 40), 'x86_64': (2, 62), 'x86': (1, 3)}
if unknown := targets.keys() - elf_targets.keys():
    raise SystemExit(f'Missing ELF architecture checks for: {", ".join(sorted(unknown))}')
methods = {'start', 'stop', 'notifyNetworkChange', 'setDnsServers', 'snapshot', 'error', 'destroy',
           'vpnNext', 'vpnInstalled', 'vpnComplete', 'vpnFence', 'vpnRevoke', 'vpnDestroy'}
with zipfile.ZipFile(published_aar) as aar:
    assets = project / 'src/main/assets'
    staged = {path.relative_to(assets).as_posix(): path
              for directory in ('gnunet', 'gnunet-notices')
              for path in (assets / directory).rglob('*') if path.is_file()}
    if not {'gnunet-notices/LICENSE', 'gnunet-notices/NOTICE.md',
            'gnunet-notices/THIRD_PARTY_LICENSES.txt'}.issubset(staged):
        raise SystemExit('Missing staged GNUnet license or notice assets')
    packaged = {name.removeprefix('assets/') for name in aar.namelist()
                if name.startswith(('assets/gnunet/', 'assets/gnunet-notices/')) and not name.endswith('/')}
    if packaged != set(staged):
        raise SystemExit('AAR GNUnet assets differ from the staged files')
    for name, path in staged.items():
        if aar.read(f'assets/{name}') != path.read_bytes():
            raise SystemExit(f'AAR changed staged GNUnet asset: {name}')
    libraries = {name for name in aar.namelist() if name.startswith('jni/') and name.endswith('.so')}
    expected = {f'jni/{abi}/libgnunet_node_android.so' for abi in targets}
    if libraries != expected or 'AndroidManifest.xml' not in aar.namelist():
        raise SystemExit(f'Unexpected AAR native content: {libraries}')
    manifest = ET.fromstring(aar.read('AndroidManifest.xml'))
    minimum = manifest.find('uses-sdk')
    if minimum is None or minimum.get('{http://schemas.android.com/apk/res/android}minSdkVersion') != settings['minSdk']:
        raise SystemExit(f"AAR does not declare minimum Android API {settings['minSdk']}")
    with zipfile.ZipFile(io.BytesIO(aar.read('classes.jar'))) as classes:
        required = {'GnunetNode', 'GnunetNode$Snapshot', 'NativeNode', 'AndroidNodeOptions',
                    'NetworkObserver', 'BootstrapHellos', 'AndroidVpnAddress', 'AndroidVpnRoute',
                    'AndroidVpnSettings', 'AndroidVpnProvider', 'NativeSocketProtection', 'GnunetVpnService'}
        if not {f'org/gnunet/sdk/{name}.class' for name in required}.issubset(classes.namelist()):
            raise SystemExit('AAR is missing current Kotlin SDK classes')
    for abi in targets:
        kind, machine = elf_targets[abi]
        body = aar.read(f'jni/{abi}/libgnunet_node_android.so')
        if body[:6] != b'\x7fELF' + bytes([kind, 1]) or struct.unpack_from('<HH', body, 16) != (3, machine):
            raise SystemExit(f'Wrong native ELF target: {abi}')
        if kind == 2:
            phoff = struct.unpack_from('<Q', body, 32)[0]
            stride, count = struct.unpack_from('<HH', body, 54)
            loads = [struct.unpack_from('<IIQQQQQQ', body, phoff + i * stride) for i in range(count)
                     if struct.unpack_from('<I', body, phoff + i * stride)[0] == 1]
            if not loads or any(p[7] < 16384 or p[2] % 16384 != p[3] % 16384 for p in loads):
                raise SystemExit(f'Native LOAD segments lack 16KB alignment: {abi}')
        library = logs / f'{abi}.so'
        library.write_bytes(body)
        symbols = subprocess.run([readelf, '--dyn-syms', '--wide', str(library)], check=True,
                                 capture_output=True, text=True).stdout
        (logs / f'{abi}-symbols.log').write_text(symbols)
        rows = [line.split() for line in symbols.splitlines()]
        exports = {row[7] for row in rows if len(row) >= 8 and row[6] != 'UND'}
        if not {f'Java_org_gnunet_sdk_NativeNode_{name}' for name in methods}.issubset(exports):
            raise SystemExit(f'Missing JNI exports: {abi}')
        if any(len(row) >= 8 and row[6] == 'UND' and
               row[7].startswith(('gnunet_node_', 'gnunet_vpn_')) for row in rows):
            raise SystemExit(f'Rust C ABI was not linked into JNI: {abi}')
        dynamic = subprocess.run([readelf, '--dynamic', str(library)], check=True,
                                 capture_output=True, text=True).stdout
        (logs / f'{abi}-dynamic.log').write_text(dynamic)
        needed = set(re.findall(r'Shared library: \[([^]]+)\]', dynamic))
        if not needed.issubset({'libc.so', 'libdl.so', 'liblog.so', 'libm.so'}):
            raise SystemExit(f'Unhandled native runtime dependency for {abi}: {needed}')
flat = project / 'build/gnunet-node-android.aar'
maven_zip = project / 'build/gnunet-node-android-maven.zip'
shutil.copyfile(published_aar, flat)

def zip_tree(archive, root, prefix):
    for file in sorted(root.rglob('*')):
        if file.is_file():
            # Keep byte order and ZIP metadata independent of the build host.
            entry = zipfile.ZipInfo((prefix / file.relative_to(root)).as_posix())
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            entry.file_size = file.stat().st_size
            with file.open('rb') as source, archive.open(entry, 'w') as target:
                shutil.copyfileobj(source, target)

with zipfile.ZipFile(maven_zip, 'w') as archive:
    zip_tree(archive, project / 'src/main/assets/gnunet-notices', Path())
    zip_tree(archive, repository, Path('maven'))
report = {'artifact': flat.name, 'abis': list(targets), 'min_sdk': int(settings['minSdk']),
          'gradle': settings['gradleVersion'], 'ndk': settings['ndk'], 'compile_sdk': int(settings['compileSdk']),
          'sha256': aar_sha256, 'maven': {'artifact': maven_zip.name, 'coordinate': coordinate,
                                        'sha256': sha256(maven_zip)}}
receipt = project / 'build/artifact.json'
receipt.write_text(json.dumps(report, indent=2) + '\n')
with (output / '.publish.lock').open('a') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    # The receipt is published only once both named artifacts are in place.
    (output / receipt.name).unlink(missing_ok=True)
    for artifact in (flat, maven_zip, receipt):
        artifact.replace(output / artifact.name)
print(f'AAR: {output / flat.name}')
print(f'Maven repository: {output / maven_zip.name} ({coordinate})')
