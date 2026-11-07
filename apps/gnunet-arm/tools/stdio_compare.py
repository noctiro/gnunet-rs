#!/usr/bin/env python3
"""Actual CLI local-ARM spawn with a finite owned native observation child.
This is process/stdio evidence, not proof the child implements ARM service IPC.
"""
import argparse,json,os,stat,subprocess,tempfile,time
from pathlib import Path
from paired import sha,save
BASE=Path(__file__).resolve().parents[1]
def actor(binary,target,flags,environment,destination):
    destination.mkdir()
    with tempfile.TemporaryDirectory(prefix='gastd-',dir='/private/tmp')as owned:
        owned=Path(owned);home=owned/'home';home.mkdir();trace=destination/'target.json';config=destination/'arm.conf'
        config.write_bytes(b'[PATHS]\nGNUNET_HOME = '+os.fsencode(home)+b'\n[arm]\nUNIXPATH = '+os.fsencode(owned/'s')+b'\nBINARY = '+os.fsencode(target)+b'\nOPTIONS = --output '+os.fsencode(trace)+b'\n[TESTING]\nWEAKRANDOM = YES\n')
        env=environment.copy();env.update(HOME=str(owned/'user'),XDG_CONFIG_HOME=str(owned/'xdg'),GNUNET_ARGS='')
        proc=subprocess.run([b'gnunet-arm',b'-c',os.fsencode(config),b'-L',b'ERROR',b'-s']+[os.fsencode(x)for x in flags],executable=os.fsencode(binary),env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4)
        until=time.monotonic()+2
        while not trace.exists()and time.monotonic()<until:time.sleep(.005)
        actual=json.loads(trace.read_text())
        if actual['readiness_type']!=stat.S_IFIFO or actual['readiness_cloexec'] or not actual['readiness_nonblock'] or actual['readiness_close_errno']!=0:raise RuntimeError('target did not receive actual readiness FIFO')
        if actual['pipe']!='default' or actual['mask']:raise RuntimeError('unexpected inherited native signal boundary')
        if proc.returncode or proc.stderr or proc.stdout!=b"":raise RuntimeError(('local CLI output',proc.returncode,proc.stdout,proc.stderr))
        # FD numbers are local allocation details, not GNUnet peer identity.
        comparable={k:v for k,v in actual.items()if k!='readiness_fd'}
        observation={'exit':proc.returncode,'stdout_hex':proc.stdout.hex(),'stderr_hex':proc.stderr.hex(),'target':comparable}
        (destination/'stdout').write_bytes(proc.stdout);(destination/'stderr').write_bytes(proc.stderr);save(destination/'observation.json',observation)
        return observation

def main():
    ap=argparse.ArgumentParser()
    for name in ['reference','rust','output']:ap.add_argument('--'+name,type=Path,required=True)
    args=ap.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False);receipt=json.loads(args.reference.read_text());normal=Path(receipt['artifacts']['client']['path']);assert sha(normal)==receipt['artifacts']['client']['sha256']
    target=out/'stdio-child';build=subprocess.run(['cc',str(BASE/'tools/stdio_child.c'),'-o',str(target)],capture_output=True);(out/'compile.stdout').write_bytes(build.stdout);(out/'compile.stderr').write_bytes(build.stderr)
    if build.returncode:raise RuntimeError('owned fixture compile failed')
    compiled_binary_sha256=sha(target);env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_'))};env.update(receipt['runtime_environment']);env.update(LC_ALL='C',GNUNET_ARGS='');base=out/'base';base.mkdir();env['GNUNET_BASE_CONFIG']=str(base);rows=[]
    try:
        for name,flags in [('inherit-both',[]),('no-stdout',['-O']),('no-stderr',['-E']),('no-both',['-O','-E'])]:
            directory=out/name;directory.mkdir();c=actor(normal,target,flags,env,directory/'c');rust=actor(args.rust,target,flags,env,directory/'rust');rows.append({'name':name,'matched':c==rust,'c':c,'rust':rust});save(out/'progress.json',rows)
            if c!=rust:raise RuntimeError('stdio mismatch '+name)
        if sha(target)!=compiled_binary_sha256:raise RuntimeError('actual compiled native fixture changed')
        result={'status':'passed','actual_compiled_binary_sha256':compiled_binary_sha256,'actual_compiled_binary_unchanged':True,'scope':'actual CLI -s native target exec and all four -O/-E combinations; actual readiness FIFO closure, stdio and child signal state; finite child does not implement ARM IPC','rows':rows,'normal_cli_sha256':sha(normal),'rust_cli_sha256':sha(args.rust),'owned_fixture_source_sha256':sha(BASE/'tools/stdio_child.c'),'owned_fixture_sha256':sha(target)}
    except Exception as error:result={'status':'failed','error':str(error),'rows':rows};raise
    finally:save(out/'result.json',result)
    print(json.dumps({'status':result['status'],'profiles':len(rows)}))
if __name__=='__main__':main()
