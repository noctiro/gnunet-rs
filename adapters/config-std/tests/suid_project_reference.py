#!/usr/bin/env python3
"""Compare project arguments/cache path strings; never execute a resolved helper."""
import argparse,hashlib,importlib.util,json,os,shlex,stat,subprocess,sys,tempfile
from pathlib import Path
sys.dont_write_bytecode=True
REPO=Path(__file__).resolve().parents[3]
BUILDER=REPO/'tools/reference/build_reference.py'
spec=importlib.util.spec_from_file_location('reference_builder',BUILDER)
builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference',type=Path,required=True)
    parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cc',default=os.environ.get('CC','cc'))
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    ref=json.loads(args.reference.read_text());source=Path(ref['source'])
    official_before=builder.source_state(source)
    if ref.get('status')!='passed' or official_before!=ref['upstream']:raise ValueError('normal official source changed')
    for v in [*ref['libraries'],*ref['artifacts'].values(),ref['generated_config']]:
        if sha(v['path'])!=v['sha256']:raise ValueError('normal reference artifact changed')
    c_source=Path(__file__).with_name('suid_project_api.c');binary=out/'normal-c-path-observer'
    argv=[args.cc,'-std=c11','-D_DARWIN_C_SOURCE','-D_GNU_SOURCE','-Wall','-Wextra','-Werror','-I'+str(source/'src/include'),'-I'+str(Path(ref['build'])/'src/include')]+shlex.split(ref['build_environment']['CPPFLAGS'])+[str(c_source)]+shlex.split(ref['build_environment']['LDFLAGS'])+['-L'+str(Path(ref['prefix'])/'lib'),'-Wl,-rpath,'+str(Path(ref['prefix'])/'lib'),'-lgnunetutil','-o',str(binary)]
    compile_result=subprocess.run(argv,capture_output=True,text=True,timeout=120)
    compilation={'argv':argv,'exit_code':compile_result.returncode,'stdout':compile_result.stdout,'stderr':compile_result.stderr}
    (out/'compile.json').write_text(json.dumps(compilation,indent=2)+'\n')
    if compile_result.returncode:raise ValueError('normal C caller did not compile')
    rust=args.rust.resolve()
    paths=[Path(__file__),c_source,BUILDER,args.reference,rust,binary,REPO/'Cargo.toml',REPO/'Cargo.lock']
    paths.extend(p for p in (REPO/'adapters/config-std').rglob('*') if p.is_file() and p.suffix in ('.rs','.toml','.py','.c','.md'))
    paths.extend(Path(v['path']) for v in ref['libraries'])
    inputs_before={str(p.resolve()):sha(p) for p in paths}
    report={'status':'failed','scope':'Path strings only, independent project/cache; no returned program execution','reference':{'path':str(args.reference.resolve()),'sha256':sha(args.reference),'upstream':official_before},'inputs_before':inputs_before,'commands':[],'comparisons':[],'actual_trace_rows_per_side':0,'checks':[]}
    def check(name,condition):
        report['checks'].append({'id':name,'passed':bool(condition)})
        if not condition:raise AssertionError(name)
    owned=tempfile.TemporaryDirectory(prefix='gcfg-pd-',dir='/tmp');root=Path(owned.name)
    try:
        env={k:v for k,v in os.environ.items() if not k.startswith(('GNUNET_','GCFG_SUID_'))}
        env.update(ref['runtime_environment']);env['LC_ALL']='C'
        for letter,project in (('a','config-a'),('b','supplied-b'),('c','supplied-c')):
            directory=root/letter/'lib'/project/'libexec';directory.mkdir(parents=True)
            (directory/'plain-helper').write_bytes(b'')
            env['GCFG_SUID_'+letter.upper()]=str(root/letter)
        def fixture_state():return {str(p.relative_to(root)):{'sha256':sha(p),'mode':stat.S_IMODE(p.stat().st_mode)} for p in root.rglob('*') if p.is_file()}
        fixture_before=fixture_state()
        for policy in ('global','owned'):
            for mode in ('b-first','c-first','absolute-first','raw-override','empty-then-override','self-project','libexec-b-first','suid-then-libexec','libexec-absolute-first','libexec-empty'):
                traces=[]
                for side,active in (('c',binary),('rust',rust)):
                    command=[str(active),str(root),mode,policy]
                    result=subprocess.run(command,capture_output=True,env=env,timeout=10)
                    prefix=out/(policy+'-'+mode+'-'+side)
                    stdout=prefix.with_suffix('.stdout');stderr=prefix.with_suffix('.stderr')
                    stdout.write_bytes(result.stdout);stderr.write_bytes(result.stderr)
                    report['commands'].append({'argv':command,'exit_code':result.returncode,'stdout':str(stdout),'stdout_sha256':sha(stdout),'stderr':str(stderr),'stderr_sha256':sha(stderr)})
                    check(policy+'.'+mode+'.'+side+'.exit',result.returncode==0)
                    traces.append(result.stdout.splitlines())
                check(policy+'.'+mode+'.equal',traces[0]==traces[1] and bool(traces[0]))
                observed={line.split(b'|',1)[0].decode():bytes.fromhex(line.split(b'|',1)[1].decode()) for line in traces[0]}
                b=str(root/'b').encode()+b'/lib//supplied-b/libexec/plain-helper'
                c=str(root/'c').encode()+b'/lib//supplied-c/libexec/plain-helper'
                a=str(root/'a').encode()+b'/lib//config-a/libexec/plain-helper'
                if mode=='b-first':expected={'first':b,'second':b,'third':b}
                elif mode=='c-first':expected={'first':c,'second':c}
                elif mode=='absolute-first':expected={'absolute':b'/ordinary/absolute-helper','first':c,'second':c}
                elif mode=='raw-override':expected={'first':b'/raw/$UNEXPANDED/plain-helper','second':b'/raw/$UNEXPANDED/plain-helper','absolute':b'/ordinary/absolute-helper'}
                elif mode=='empty-then-override':expected={'fallback':b,'first':b'/raw/$UNEXPANDED/plain-helper','second':b'/raw/$UNEXPANDED/plain-helper'}
                elif mode=='libexec-b-first':expected={'first':b,'second':b,'fallback':b}
                elif mode=='suid-then-libexec':expected={'first':b,'second':b,'absolute':b'/ordinary/absolute-helper'}
                elif mode=='libexec-absolute-first':expected={'absolute':b'/ordinary/absolute-helper','first':c,'second':c}
                elif mode=='libexec-empty':expected={'empty':b[:-len(b'plain-helper')],'first':b}
                else:expected={'first':a,'second':a}
                check(policy+'.'+mode+'.literal-path-and-cache',observed==expected)
                report['actual_trace_rows_per_side']+=len(traces[0]);report['comparisons'].append({'policy':policy,'mode':mode,'rows':len(traces[0])})
        check('owned-ordinary-files-unchanged',fixture_before==fixture_state())
        check('owned-marker-files-never-executable',all(not(v['mode']&0o111) for v in fixture_state().values()))
        report['fixtures_unchanged']=True;report['status']='passed'
    except Exception as error:
        report['failure']=repr(error);raise
    finally:
        owned.cleanup();report['owned_runtime_removed']=not root.exists()
        after={str(p.resolve()):sha(p) for p in paths};official_after=builder.source_state(source)
        report.update(inputs_after=after,inputs_unchanged=inputs_before==after,official_sources_unchanged=official_before==official_after,actual_check_count=len(report['checks']))
        if inputs_before!=after or official_before!=official_after:report['status']='failed'
        (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    if report['status']!='passed':raise ValueError('source/reference changed')
    print(json.dumps({'status':report['status'],'comparisons':len(report['comparisons']),'trace_rows_per_side':report['actual_trace_rows_per_side'],'checks':report['actual_check_count'],'result':str(out/'result.json')}))
if __name__=='__main__':main()
