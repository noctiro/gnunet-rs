#!/usr/bin/env python3
"""Compare all 43 configuration APIs through the actual unmodified C library.

Production Rust never links GNUnet C. This runner compiles only a public-API
caller against an existing normal reference build; no function extraction/shim.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools/reference'))
from build_reference import REVISION, source_state

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def fixture(root):
    files={
      'install/share/gnunet/config.d/10-base.conf':b'[demo]\nnumber=123\nfloat=1.25\ntime=1h\nsize=2KiB\nyes=YeS\nchoice=green\ndata=0000\nfiles=/one /a\\ path\npath=$DATADIR/entry\nvalue=base\n',
      'install/share/gnunet/config.d/20-override.conf':b'[demo]\nvalue=defaults\n',
      'install/share/gnunet/config.d/skip.txt':b'not a configuration\n',
      'main.conf':b'@INLINE@ child.conf\n@INLINE-MATCHING@ fragments/*.conf\n@INLINE-SECRET@ vault secret.conf\n[unavailable]\nvisible=prior\n@INLINE-SECRET@ unavailable missing.conf\n[demo]\nvalue=main\nduplicate=same\nduplicate=same\n',
      'child.conf':b'[demo]\nvalue=child\n',
      'fragments/a.conf':b'[demo]\nfragment=a\n',
      'fragments/b.conf':b'[demo]\nfragment=b\n',
      'fragments/.hidden.conf':b'[demo]\nhidden=included\n',
      'secret.conf':b'[vault]\nkey=old\nKEY=current\n[unrelated]\nleak=hidden\n',
      'xdg/gnunet.conf':b'[xdg]\nselected=yes\n',
      'ignored/skip.txt':b'not parsed\n',
    }
    for name,value in files.items():
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(value)
    (root/'secret.conf').chmod(0o600)
    for name in ['empty','install/bin','install/lib/gnunet/libexec','home','cache','runtime']:(root/name).mkdir(parents=True,exist_ok=True)
def normalized(raw,root):
    result=[]
    needle=str(root).encode()
    for line in raw.splitlines():
        key,sep,value=line.partition(b'|')
        if not sep:raise ValueError('non-trace stdout line: '+repr(line))
        try:decoded=bytes.fromhex(value.decode('ascii'))
        except (ValueError,UnicodeError):pass
        else:value=decoded.replace(needle,b'<FIXTURE>').hex().encode()
        result.append(key+b'|'+value)
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference',required=True,type=Path)
    parser.add_argument('--rust',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--cc',default='cc')
    parser.add_argument('--configuration-reference',type=Path)
    parser.add_argument('--rust-cli',type=Path)
    parser.add_argument('--rust-diff',type=Path)
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    report={'schema':1,'kind':'normal-c-configuration-public-api','status':'failed','commands':[],'scope':'Actual normal C shared-library public API, real defaults/include/glob/secret/diagnostics/write/clean files. No whole util or generic OS/plugin certification.'}
    owned=None
    def run(name,argv,env=None,cwd=ROOT,expected=0):
        result=subprocess.run([str(v) for v in argv],cwd=cwd,env=env,capture_output=True,timeout=90)
        (out/(name+'.stdout')).write_bytes(result.stdout);(out/(name+'.stderr')).write_bytes(result.stderr)
        report['commands'].append({'name':name,'argv':[str(v) for v in argv],'exit_code':result.returncode,'stdout_sha256':sha(out/(name+'.stdout')),'stderr_sha256':sha(out/(name+'.stderr'))})
        if result.returncode!=expected:raise ValueError(name+' exit '+str(result.returncode)+' expected '+str(expected)+': '+result.stderr.decode(errors='replace')[-2500:])
        return result.stdout
    try:
        ref=json.loads(args.reference.read_text())
        if ref.get('status')!='passed' or ref.get('kind')!='unmodified-official-c-reference-build' or ref['upstream']['revision']!=REVISION:raise ValueError('pinned normal build receipt required')
        before=source_state(Path(ref['source']))
        if before!=ref['upstream']:raise ValueError('reference source changed since build')
        refs=[*ref['artifacts'].values(),*ref['libraries'],*ref['default_configurations']]
        if any(sha(v['path'])!=v['sha256'] for v in refs):raise ValueError('reference artifact changed')
        report['reference']={'receipt':str(args.reference.resolve()),'sha256':sha(args.reference),'upstream':before}
        inputs=sorted(v for v in (ROOT/'adapters/config-std').rglob('*') if v.is_file() and '__pycache__' not in v.parts)
        report['rust_sources_sha256']={str(v.relative_to(ROOT)):sha(v) for v in inputs}
        participants={'rust_trace':args.rust.resolve()}
        if args.rust_cli:participants['rust_cli']=args.rust_cli.resolve()
        if args.rust_diff:participants['rust_diff']=args.rust_diff.resolve()
        report['participant_sha256']={name:sha(path) for name,path in participants.items()}
        source=ROOT/'adapters/config-std/tests/normal_api.c';binary=out/'c-normal-api'
        flags=[args.cc,'-DHAVE_CONFIG_H','-D_GNU_SOURCE','-I'+str(Path(ref['build'])/'src/include'),'-I'+ref['build'],'-I'+str(Path(ref['source'])/'src/include')]+shlex.split(ref['build_environment']['CPPFLAGS'])
        if platform.system()=='Darwin':flags+=['-DDARWIN','-D_APPLE_C_SOURCE']
        links=shlex.split(ref['build_environment']['LDFLAGS'])+['-L'+str(Path(ref['prefix'])/'lib'),'-Wl,-rpath,'+str(Path(ref['prefix'])/'lib'),'-lgnunetutil']
        run('compile-c',flags+[source]+links+['-o',binary])
        owned=Path(tempfile.mkdtemp(prefix='gcfg-',dir='/private/tmp' if Path('/private/tmp').is_dir() else tempfile.gettempdir()));owned.chmod(0o700)
        traces=[]
        for name,original in [('c',binary),('rust',args.rust.resolve())]:
            root=owned/name;fixture(root);active=root/'install/bin'/name;shutil.copy2(original,active);active.chmod(0o700)
            env={k:v for k,v in os.environ.items() if not k.startswith('GNUNET_')};env.update(ref['runtime_environment'],GNUNET_PREFIX=str(root/'install'),XDG_CONFIG_HOME=str(root/'xdg'),XDG_DATA_HOME=str(root/'data'),XDG_CACHE_HOME=str(root/'cache'),XDG_RUNTIME_DIR=str(root/'runtime'),LC_ALL='C')
            raw=run(name+'-trace',[active,root],env,root);trace=normalized(raw,root);traces.append(trace);(out/(name+'-normalized.txt')).write_bytes(b'\n'.join(trace)+b'\n')
            for filename in ['written.conf','diff.conf','main.conf']:
                data=(root/filename).read_bytes().replace(str(root).encode(),b'<FIXTURE>');(out/(name+'-'+filename)).write_bytes(data)
        if traces[0]!=traces[1]:
            first=next((i for i,(a,b) in enumerate(zip(*traces)) if a!=b),min(len(traces[0]),len(traces[1])))
            report['first_difference']={'line':first+1,'c':traces[0][first].decode() if first<len(traces[0]) else None,'rust':traces[1][first].decode() if first<len(traces[1]) else None};raise ValueError('normal API traces differ')
        for filename in ['written.conf','diff.conf','main.conf']:
            if (out/('c-'+filename)).read_bytes()!=(out/('rust-'+filename)).read_bytes():raise ValueError('file outputs differ: '+filename)
        report['trace_rows']=len(traces[0]);report['direct_public_functions_called']=43
        if bool(args.configuration_reference)!=bool(args.rust_cli):raise ValueError('both CLI arguments are required together')
        if args.configuration_reference:
            tools=json.loads(args.configuration_reference.read_text())
            if tools.get('status')!='passed' or tools.get('kind')!='normal-c-configuration-tools' or tools['base_receipt_sha256']!=sha(args.reference):raise ValueError('matching normal configuration tool receipt required')
            for entry in tools['artifacts'].values():
                if sha(entry['path'])!=entry['sha256'] or sha(entry['build_path'])!=entry['sha256']:raise ValueError('normal tool changed')
            cases=[('version',['--version'],2),('prefix',['-p'],0),('cflags',['-C'],0),('libs',['-j'],0),('experimental',['-E'],0),
                ('query',['-c','MAIN','-s','demo','-o','value'],0),('filename',['-c','MAIN','-f','-s','demo','-o','path'],0),
                ('section',['-c','MAIN','-s','demo'],0),('sections',['-c','MAIN','-S'],0),('diagnostics',['-c','MAIN','-d'],0),('verbose',['-c','MAIN','-dd'],0),
                ('ram',['-n','-R','[ram]\nx=1\n','-s','ram','-o','x'],0),('missing',['-c','MAIN','-s','demo','-o','absent'],6),
                ('invalid-clean',['-c','MAIN','-x','-s','demo'],2),('set-diff',['-c','MAIN','-s','demo','-o','value','-V','new'],0),
                ('rewrite',['-c','MAIN','-r'],0),('full',['-c','MAIN','-F'],0),('clean',['-c','MAIN','-x'],0),
                ('missing-option',['-c','MAIN','-s','demo','-V','new'],2),('xdg-default',['-s','xdg','-o','selected'],0),
                ('ram-include',['-n','-R','@INLINE@ main.conf\n','-s','demo','-o','value'],1),('no-defaults',['-n','-s','demo','-o','number'],6),('base-unreadable',['-c','MAIN','-s','demo','-o','number'],6),('base-no-search',['-c','MAIN','-s','demo','-o','number'],6)]
            if hasattr(os,'getuid') and os.getuid()==0:
                cases=[case for case in cases if case[0] not in ('base-unreadable','base-no-search')]
                report['permission_case_skip']='root bypasses the synthetic Unix permission denial; no denied-access credit'
            for case,arguments,expected in cases:
                observations=[]
                for side,original in [('c',Path(tools['artifacts']['gnunet-config']['path'])),('rust',args.rust_cli.resolve())]:
                    root=owned/('cli-'+case+'-'+side);fixture(root);active=root/'install/bin/gnunet-config';shutil.copy2(original,active);active.chmod(0o700)
                    env={k:v for k,v in os.environ.items() if not k.startswith('GNUNET_')};env.update(ref['runtime_environment'],GNUNET_PREFIX=str(root/'install'),XDG_CONFIG_HOME=str(root/'xdg'),XDG_DATA_HOME=str(root/'data'),XDG_CACHE_HOME=str(root/'cache'),XDG_RUNTIME_DIR=str(root/'runtime'),LC_ALL='C')
                    if case in ('cflags','libs'):
                        include=root/'install/include';include.mkdir()
                        for header in (Path(ref['source'])/'src/include').glob('*.h'):shutil.copy2(header,include/header.name)
                        for header in (Path(ref['build'])/'src/include').glob('*.h'):shutil.copy2(header,include/header.name)
                        for library in ref['libraries']:
                            if 'libgnunetutil' in Path(library['path']).name:shutil.copy2(library['path'],root/'install/lib/gnunet'/Path(library['path']).name)
                    restricted=None
                    if case in ('base-unreadable','base-no-search'):
                        restricted=root/'restricted-defaults';restricted.mkdir();(restricted/'10.conf').write_bytes(b'[demo]\nnumber=999\n');restricted.chmod(0 if case=='base-unreadable' else 0o400);env['GNUNET_BASE_CONFIG']=str(restricted)
                    actual=[str(root/'main.conf') if value=='MAIN' else value for value in arguments]
                    quiet=[] if case=='version' else ['-L','ERROR']
                    try:raw=run('cli-'+case+'-'+side,[active,*quiet,*actual],env,root,expected)
                    finally:
                        if restricted is not None:restricted.chmod(0o700)
                    observations.append((raw.replace(str(root).encode(),b'<FIXTURE>'),(root/'main.conf').read_bytes().replace(str(root).encode(),b'<FIXTURE>')))
                if observations[0]!=observations[1]:raise ValueError('normal CLI differs: '+case)
            report['normal_cli_cases']=len(cases)
            report['configuration_tools_receipt']={'path':str(args.configuration_reference.resolve()),'sha256':sha(args.configuration_reference)}
            report['rust_cli_sha256']=sha(args.rust_cli.resolve())
            if args.rust_diff:
                diff_cases=[('rewrite',0),('missing-input',1)]+([('denied-write',2)] if not hasattr(os,'getuid') or os.getuid()!=0 else [])
                for case,expected in diff_cases:
                    observations=[]
                    for side,original in [('c',Path(tools['artifacts']['gnunet-config-diff']['path'])),('rust',args.rust_diff.resolve())]:
                        root=owned/('diff-'+case+'-'+side);fixture(root);active=root/'install/bin/gnunet-config-diff';shutil.copy2(original,active);active.chmod(0o700)
                        first=root/'defaults.conf';first.write_bytes(b'[diff]\nx=1\ny=2\n');second=root/'output/main.conf';second.parent.mkdir();second.write_bytes(b'[diff]\nx=3\ny=2\n')
                        env={k:v for k,v in os.environ.items() if not k.startswith('GNUNET_')};env.update(ref['runtime_environment'],GNUNET_PREFIX=str(root/'install'),XDG_CONFIG_HOME=str(root/'xdg'),LC_ALL='C')
                        if case=='missing-input':first=root/'missing.conf'
                        if case=='denied-write':second.parent.chmod(0o500)
                        try:raw=run('diff-'+case+'-'+side,[active,first,second],env,root,expected)
                        finally:second.parent.chmod(0o700)
                        observations.append((raw.replace(str(root).encode(),b'<FIXTURE>'),second.read_bytes().replace(str(root).encode(),b'<FIXTURE>')))
                    if observations[0]!=observations[1]:raise ValueError('normal config-diff differs: '+case)
                report['normal_diff_cases']=len(diff_cases);report['rust_diff_sha256']=sha(args.rust_diff.resolve())

        report['rust_sources_unchanged']=report['rust_sources_sha256']=={str(v.relative_to(ROOT)):sha(v) for v in inputs}
        report['reference_source_unchanged']=source_state(Path(ref['source']))==before
        report['reference_files_unchanged']=all(sha(v['path'])==v['sha256'] for v in refs)
        if args.configuration_reference:
            report['reference_tools_unchanged']=all(sha(v['path'])==v['sha256'] and sha(v['build_path'])==v['sha256'] for v in tools['artifacts'].values())
            if not report['reference_tools_unchanged']:raise ValueError('normal reference tools changed during run')
        report['participants_unchanged']=report['participant_sha256']=={name:sha(path) for name,path in participants.items()}
        report['rust_binary_sha256']=sha(args.rust.resolve())
        if not all(report[k] for k in ['rust_sources_unchanged','reference_source_unchanged','reference_files_unchanged','participants_unchanged']):raise ValueError('proof inputs changed during run')
        report['status']='passed'
    except Exception as error:report['failure']=type(error).__name__+': '+str(error)
    finally:
        if owned is not None:shutil.rmtree(owned);report['owned_runtime_removed']=not owned.exists()
        (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'rows':report.get('trace_rows'),'report':str(out/'result.json'),'failure':report.get('failure')}))
    return 0 if report['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
