#!/usr/bin/env python3
"""Actual CLI start/restart of unchanged normal ARM daemon via official PREFIX.
The private prefix only records its own exec PID and a finite failure watchdog.
No wait status is claimed for the daemon after its CLI parent has exited.
"""
import argparse,json,os,socket,subprocess,tempfile,time
from pathlib import Path
from paired import sha,save
from daemon_compare import call
BASE=Path(__file__).resolve().parents[1]
def actor(binary,service,wrapper,environment,destination):
    destination.mkdir();steps=[]
    with tempfile.TemporaryDirectory(prefix='gald-')as owned:
        owned=Path(owned);home=owned/'home';home.mkdir();endpoint=owned/'s';config=owned/'arm.conf';trace=destination/'actual-daemon-exec-pids'
        config.write_bytes(b'[PATHS]\nGNUNET_HOME = '+os.fsencode(home)+b'\nDEFAULTCONFIG = '+os.fsencode(config)+b'\n[arm]\nUNIXPATH = '+os.fsencode(endpoint)+b'\nBINARY = '+os.fsencode(service)+b'\nPREFIX = '+os.fsencode(wrapper)+b'\nOPTIONS =\nSTART_SYSTEM_SERVICES = NO\nSTART_USER_SERVICES = YES\n[TESTING]\nWEAKRANDOM = YES\n')
        (destination/'config').write_bytes(config.read_bytes());env=environment.copy();env.update(HOME=str(owned/'user'),XDG_CONFIG_HOME=str(owned/'xdg'),XDG_CACHE_HOME=str(owned/'cache'),XDG_DATA_HOME=str(owned/'data'),XDG_RUNTIME_DIR=str(owned/'run'),GNUNET_ARGS='',OWNED_ARM_CLI_EXEC_TRACE=str(trace));finished=False
        for name in ['user','xdg','cache','data','run']:(owned/name).mkdir(mode=0o700)
        try:
            for name,arguments in [('actual-local-start',['-s','-O','-E','-T','2s']),('list-after-start',['-I','-T','2s']),('actual-local-restart',['-r','-O','-E','-T','2s']),('list-after-restart',['-I','-T','2s']),('end',['-e','-T','2s'])]:
                row={'name':name,**call(binary,config,arguments,env,destination,name)};steps.append(row);save(destination/'progress.json',steps)
                if row['exit'] or row['stderr_hex']:raise RuntimeError(('local daemon CLI failed',name,row))
                if name.startswith('list-')and bytes.fromhex(row['stdout_hex'])!=b'Services (excluding stopped services):\n(No services configured.)\n':raise RuntimeError(('actual list mismatch',row))
                if name.startswith('actual-local') and row['stdout_hex']:raise RuntimeError(('real local launch returned failure',row))
            until=time.monotonic()+2
            while endpoint.exists()and time.monotonic()<until:time.sleep(.005)
            if endpoint.exists():raise RuntimeError('normal service did not remove owned listener')
            pids=[int(line)for line in trace.read_text().splitlines()]
            if len(pids)!=2 or len(set(pids))!=2:raise RuntimeError('expected two actual separate native daemon execs')
            finished=True
            return {'steps':steps,'actual_daemon_exec_pids':pids,'owned_endpoint_removed':True,'daemon_wait_status_claimed':False}
        finally:
            if not finished:
                try:call(binary,config,['-e','-T','500ms'],env,destination,'failure-cleanup-end')
                except Exception:pass
                # Each exec'd service also owns its own eight-second alarm.
def main():
    ap=argparse.ArgumentParser()
    for name in ['reference','rust','output']:ap.add_argument('--'+name,type=Path,required=True)
    args=ap.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False);receipt=json.loads(args.reference.read_text());normal=Path(receipt['artifacts']['client']['path']);service=Path(receipt['artifacts']['service']['path']);assert sha(normal)==receipt['artifacts']['client']['sha256']and sha(service)==receipt['artifacts']['service']['sha256']
    wrapper=out/'owned-exec-prefix';build=subprocess.run(['cc',str(BASE/'tools/daemon_exec.c'),'-o',str(wrapper)],capture_output=True);(out/'compile.stderr').write_bytes(build.stderr)
    if build.returncode:raise RuntimeError('owned exec prefix compile failed')
    compiled_binary_sha256=sha(wrapper);env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_','OWNED_ARM_'))};env.update(receipt['runtime_environment']);env.update(LC_ALL='C',GNUNET_ARGS='');base=out/'base';base.mkdir();env['GNUNET_BASE_CONFIG']=str(base);result={}
    try:
        c=actor(normal,service,wrapper,env,out/'c');rust=actor(args.rust,service,wrapper,env,out/'rust')
        if c['steps']!=rust['steps']:raise RuntimeError('actual local daemon CLI transcripts differ')
        if sha(wrapper)!=compiled_binary_sha256:raise RuntimeError('actual compiled native fixture changed')
        result={'status':'passed','actual_compiled_binary_sha256':compiled_binary_sha256,'actual_compiled_binary_unchanged':True,'scope':'full actual C/Rust CLI start then public LIST then restart then public LIST then end; four real unchanged normal C daemon execs; no literal peer; no wait status claimed for reparented child','c':c,'rust':rust,'normal_service_sha256':sha(service),'normal_cli_sha256':sha(normal),'rust_cli_sha256':sha(args.rust),'owned_exec_prefix_source_sha256':sha(BASE/'tools/daemon_exec.c')}
    except Exception as error:result={'status':'failed','error':str(error)};raise
    finally:save(out/'result.json',result)
    print(json.dumps({'status':result['status'],'actual_daemon_execs':4,'paired_cli_steps':len(c['steps'])}))
if __name__=='__main__':main()
