#!/usr/bin/env python3
"""Real Rust ClientHost/MonitorHost to unchanged official C ARM daemon.
All paths, listeners and managed children belong to this finite test; no public
DNS or system service/account configuration is used. No response is simulated.
"""
import argparse,json,os,pathlib,socket,subprocess,time
from reference import load,sha
from _common import require_disjoint_output


def main():
    parser=argparse.ArgumentParser()
    for name in ['repo','source','reference','rust','helper','output']:parser.add_argument('--'+name,type=pathlib.Path,required=True)
    args=parser.parse_args();package=pathlib.Path(__file__).resolve().parents[1];reference,normal=load(args.reference,args.source,args.repo);out=require_disjoint_output(args.output,[package,args.repo,args.source,args.reference.resolve().parent,pathlib.Path(reference['build']),pathlib.Path(reference['prefix'])]);out.mkdir()
    service=reference['artifacts']['service'];binary=pathlib.Path(service['path'])
    if sha(binary)!=service['sha256']:raise ValueError('normal C daemon binary changed')
    target=out/'owned-managed-child';compilation=subprocess.run(['cc',str(package/'tools/daemon_fixture.c'),'-o',str(target)],capture_output=True)
    (out/'target-compile.stderr').write_bytes(compilation.stderr)
    if compilation.returncode:raise RuntimeError(compilation.stderr.decode())
    inputs={**normal,**{str(path.resolve()):sha(path)for path in [binary,target,args.rust,args.helper,pathlib.Path(__file__),package/'tools/daemon_fixture.c',package/'examples/daemon_owner.rs']}}
    environment={key:value for key,value in os.environ.items()if not key.startswith(('GNUNET_','LISTEN_'))};environment.update(reference['runtime_environment'],LC_ALL='C');base=out/'base';base.mkdir();environment['GNUNET_BASE_CONFIG']=str(base)
    cases=[]
    for profile in ['unix','tcp4']:
        directory=out/profile;directory.mkdir();home=directory/'home';home.mkdir();endpoint=directory/'arm.sock';config=directory/'server.conf';client=directory/'client.conf';port=0
        if profile=='tcp4':
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM)as reservation:reservation.bind(('127.0.0.1',0));port=reservation.getsockname()[1]
        config.write_text('[paths]\nGNUNET_HOME = '+str(home)+'\nDEFAULTCONFIG = '+str(config)+'\n[arm]\nUNIXPATH = '+str(endpoint)+'\nPORT = '+str(port)+'\nHOSTNAME = 127.0.0.1\nBINDTO = 127.0.0.1\nSTART_SYSTEM_SERVICES = NO\nSTART_USER_SERVICES = YES\nGLOBAL_PREFIX =\nGLOBAL_POSTFIX =\n[TESTING]\nWEAKRANDOM = YES\n'+''.join('['+name+']\nTYPE = SIMPLE\nBINARY = configured-'+name+'\nPREFIX = '+(''if name=='empty-prefix'else str(target))+'\nOPTIONS = '+('3000'if name=='running'else'0')+'\nRUN_PER_USER = YES\nIMMEDIATE_START = NO\nSTART_ON_DEMAND = NO\n'for name in ['finished','empty-prefix','running']))
        client.write_text('[arm]\n'+('UNIXPATH = '+str(endpoint)+'\n'if profile=='unix'else'PORT = '+str(port)+'\nHOSTNAME = 127.0.0.1\n'))
        process=None;rust=None;stdout_file=open(directory/'daemon.stdout','wb');stderr_file=open(directory/'daemon.stderr','wb')
        try:
            argv=[str(binary),'-c',str(config)];process=subprocess.Popen(argv,env=environment,stdin=subprocess.DEVNULL,stdout=stdout_file,stderr=stderr_file)
            deadline=time.monotonic()+5;ready=False
            while time.monotonic()<deadline:
                if process.poll()is not None:raise RuntimeError(('normal daemon exited',process.returncode))
                probe=socket.socket(socket.AF_UNIX if profile=='unix'else socket.AF_INET,socket.SOCK_STREAM);probe.settimeout(.05)
                try:probe.connect(str(endpoint)if profile=='unix'else('127.0.0.1',port));ready=True;break
                except (FileNotFoundError,ConnectionRefusedError,TimeoutError):time.sleep(.01)
                finally:probe.close()
            if not ready:raise RuntimeError('actual C listener not ready')
            actor_argv=[str(args.rust),str(client),str(args.helper)];rust=subprocess.Popen(actor_argv,env=environment,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            stdout,stderr=rust.communicate(timeout=16);(directory/'rust.stdout').write_bytes(stdout);(directory/'rust.stderr').write_bytes(stderr)
            if rust.returncode:raise RuntimeError((profile,'Rust actor failed',rust.returncode,stderr.decode()))
            events=[json.loads(line)for line in stdout.splitlines()];done=[row for row in events if row['event']=='done'];stopped=[row for row in events if row['event']=='stop-arm'];results=[row for row in events if row['event']=='result'];statuses=[(row['status'],row['name'])for row in events if row['event']=='monitor']
            if len(done)!=1 or done[0]['results']!=9 or done[0]['helper_children']!=0 or not done[0]['canceled_callback_suppressed']or done[0]['repeat_connections']<2:raise ValueError('real C/Rust ownership chain missing')
            expected=[('UnknownStart',7),('UnknownStop',7),('Stopped',6),('Failed',8),('StartFinished',2),('StartRunning',2),('StopRunning',0),('Already',5)]
            if [(row['kind'],row['result'])for row in results]!=expected or any(row['status']!=0 for row in results):raise ValueError('actual native result sequence differs')
            if len(stopped)!=1 or (stopped[0]['status'],stopped[0]['result'])not in [(0,0),(2,None)]:raise ValueError('actual self-stop must preserve STOPPING waiter versus pending EOF')
            if not all(item in statuses for item in [(0,'arm'),(2,'finished'),(1,'finished'),(2,'running'),(3,'RuNnInG'),(1,'running')]):raise ValueError('normal daemon monitor stream incomplete')
            exit_code=process.wait(timeout=5)
            if exit_code!=0:raise ValueError(('normal daemon did not naturally stop/reap',exit_code))
            cases.append({'profile':profile,'status':'passed','daemon_argv':argv,'daemon_pid':process.pid,'daemon_exit':exit_code,'rust_argv':actor_argv,'rust_exit':rust.returncode,'self_stop_observation':stopped[0],'events':events,'server_config_sha256':sha(config),'client_config_sha256':sha(client),'listener_owned':str(endpoint)if profile=='unix'else['127.0.0.1',port]})
        finally:
            if rust is not None and rust.poll()is None:rust.kill();rust.communicate(timeout=2)
            if process is not None and process.poll()is None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=2)
            stdout_file.close();stderr_file.close()
    after,normal_after=load(args.reference,args.source,args.repo)
    if reference!=after or normal!=normal_after or any(sha(path)!=value for path,value in inputs.items()):raise ValueError('source/library/executed binary changed')
    document={'status':'passed','scope':'actual Rust ClientHost/MonitorHost streams to unchanged normal C ARM daemon and real own SIMPLE children, Unix and numeric-loopback TCP4, io_slice1; no Rust daemon/CLI/testing owner promotion','cases':cases,'inputs':inputs,'inputs_unchanged':True,'normal_daemon_sha256':service['sha256']};(out/'result.json').write_text(json.dumps(document,indent=2)+'\n');print(json.dumps({'status':'passed','profiles':2,'result':str(out/'result.json')}))


if __name__=='__main__':main()
