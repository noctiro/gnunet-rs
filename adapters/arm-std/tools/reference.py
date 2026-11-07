"""Read-only checks for the existing normal ARM build; never rewrite receipts."""
import hashlib
import importlib.util
import json
import pathlib
import shlex
import subprocess


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


PINNED_REVISION='346358e26d4dcc2dc4f51bef5d52dca29c7d8165'


def validate_data(receipt,source,current):
    source=pathlib.Path(source).resolve()
    upstream=receipt.get('upstream',{})
    if (receipt.get('kind')!='unmodified-official-c-arm-reference-build'
            or receipt.get('status')!='passed'
            or receipt.get('source_unchanged')is not True
            or upstream.get('revision')!=PINNED_REVISION
            or upstream.get('tag')!='v0.29.1'
            or not upstream.get('tracked_files')
            or upstream.get('tracked_sources_clean')is not True
            or upstream!=current):
        raise ValueError('normal ARM reference source commitment does not match')
    setups=[row for row in receipt['commands']if row.get('name')=='meson-setup']
    if len(setups)!=1 or pathlib.Path(setups[0]['argv'][3]).resolve()!=source:
        raise ValueError('normal build uses another source tree')
    build=pathlib.Path(receipt['build']).resolve()
    prefix=pathlib.Path(receipt['prefix']).resolve()
    if not receipt.get('libraries'):
        raise ValueError('normal libraries not declared')
    libraries={pathlib.Path(row['path']).resolve().name for row in receipt['libraries']}
    if not any(name.startswith('libgnunetarm.')for name in libraries)or not any(name.startswith('libgnunetutil.')for name in libraries):
        raise ValueError('both actual normal ARM/util libraries are required')
    declared=[*receipt['libraries'],receipt['generated_config'],receipt['compile_commands']]
    if len({row['path']for row in declared})!=len(declared):
        raise ValueError('duplicate normal build input')
    for row in declared:
        if not row.get('sha256')or sha(row['path'])!=row['sha256']:
            raise ValueError('declared normal build input changed: '+row['path'])
    if pathlib.Path(receipt['generated_config']['path']).resolve()!=build/'gnunet_private_config.h':
        raise ValueError('wrong normal compile configuration')
    if pathlib.Path(receipt['compile_commands']['path']).resolve()!=build/'compile_commands.json':
        raise ValueError('wrong normal compile database')
    expected={'DYLD_LIBRARY_PATH':str(prefix/'lib'),'LD_LIBRARY_PATH':str(prefix/'lib'),'GNUNET_PREFIX':str(prefix)}
    if receipt.get('runtime_environment')!=expected:
        raise ValueError('normal runtime prefix does not match its libraries')
    for row in receipt['libraries']:
        if pathlib.Path(row['path']).absolute().parent!=prefix/'lib':
            raise ValueError('normal library outside declared prefix')
    return {row['path']:row['sha256']for row in declared}


def load(path,source,repo):
    path,source,repo=map(lambda p:pathlib.Path(p).resolve(),(path,source,repo))
    helper=repo/'tools/reference/build_reference.py'
    spec=importlib.util.spec_from_file_location('normal_reference_source',helper)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    receipt=json.loads(path.read_text())
    declared=validate_data(receipt,source,module.source_state(source))
    return receipt,{str(path):sha(path),str(helper):sha(helper),**declared}


def compile_probe(source,output,reference):
    entries=json.loads(pathlib.Path(reference['compile_commands']['path']).read_text())
    row=next(item for item in entries if item['file'].endswith('/arm_api.c'))
    command=row.get('arguments')or shlex.split(row['command'])
    flags=[];index=1
    while index<len(command):
        value=command[index]
        if value in ['-o','-MQ','-MF','-MT']:
            index+=2;continue
        if value in ['-c','-MD','-MMD']or value.endswith('/arm_api.c'):
            index+=1;continue
        flags.append(value);index+=1
    prefix=pathlib.Path(reference['prefix'])
    argv=[command[0],*flags,str(pathlib.Path(source).resolve()),
          '-L'+str(prefix/'lib'),'-lgnunetarm','-lgnunetutil',
          '-Wl,-rpath,'+str(prefix/'lib'),'-o',str(pathlib.Path(output).resolve())]
    compiled=subprocess.run(argv,cwd=row['directory'],capture_output=True)
    if compiled.returncode:
        raise RuntimeError(compiled.stderr.decode())
    return {'argv':argv,'cwd':row['directory'],'exit_code':compiled.returncode,
            'source_sha256':sha(source),'binary_sha256':sha(output)}
