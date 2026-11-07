#!/usr/bin/env python3
"""Normal unchanged C ARM FIFO progress with two owned legal-message clients."""
import hashlib,json,os,re,signal,socket,struct,subprocess,sys,time
from pathlib import Path
import argparse
parser=argparse.ArgumentParser(description=__doc__)
for name in ('repository','source','reference','output'):
    parser.add_argument('--'+name,type=Path,required=True)
args=parser.parse_args()
repo,source,reference_path,out=[getattr(args,name).resolve()for name in ('repository','source','reference','output')]
sys.path.insert(0,str(repo/'adapters/arm-std/tools'));import reference
ref,inputs=reference.load(reference_path,source,repo)
for protected in (repo,source,reference_path.parent,Path(ref['build']),Path(ref['prefix'])):
    if out==protected or out in protected.parents or protected in out.parents:
        raise ValueError('output overlaps source/reference')
if out.exists():raise ValueError('output must be fresh')
out.mkdir(mode=0o700)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
inputs[str(Path(__file__).resolve())]=sha(__file__)
binary=Path(ref['artifacts']['service']['path']);inputs[str(binary)]=sha(binary)
for relative in ['src/lib/util/service.c','src/lib/util/scheduler.c']:inputs[str(source/relative)]=sha(source/relative)
endpoint=out/'arm.sock';cfg=out/'owned.conf'
cfg.write_text('[paths]\nGNUNET_HOME = '+str(out/'home')+'\nDEFAULTCONFIG = '+str(cfg)+'\n[arm]\nUNIXPATH = '+str(endpoint)+'\nPORT = 0\nHOSTNAME = localhost\nSTART_SYSTEM_SERVICES = NO\nSTART_USER_SERVICES = YES\n')
env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_'))};env.update(ref['runtime_environment'],LC_ALL='C',GNUNET_ARGS='')
for name,key in [('home','HOME'),('xdg','XDG_CONFIG_HOME'),('cache','XDG_CACHE_HOME'),('data','XDG_DATA_HOME'),('run','XDG_RUNTIME_DIR'),('base','GNUNET_BASE_CONFIG')]:
    directory=out/name;directory.mkdir(mode=0o700);env[key]=str(directory)
def receive(peer):
    def exact(n):
        data=b''
        while len(data)<n:
            part=peer.recv(n-len(data))
            if not part:raise EOFError()
            data+=part
        return data
    header=exact(4);size,kind=struct.unpack('>HH',header);assert size>=4
    return kind,header+exact(size-4)
test=struct.pack('>HH',4,15)
listing=lambda identity:struct.pack('>HHIQ',16,12,0,identity)
process=None;peers=[];stopped=False
stdout=open(out/'daemon.stdout','wb',buffering=0);stderr=open(out/'daemon.stderr','wb',buffering=0)
try:
    argv=[str(binary),'-c',str(cfg),'-L','DEBUG']
    process=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr)
    for index in range(2):
        deadline=time.monotonic()+5
        while True:
            peer=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);peer.settimeout(3)
            try:peer.connect(str(endpoint));break
            except (FileNotFoundError,ConnectionRefusedError):
                peer.close();assert process.poll()is None and time.monotonic()<deadline;time.sleep(.005)
        peers.append(peer);peer.sendall(test);assert receive(peer)==(15,test)
    peers[1].sendall(listing(17));kind,data=receive(peers[1]);assert kind==13 and struct.unpack_from('>H',data,16)[0]==0
    marker=(out/'daemon.stderr').stat().st_size
    os.kill(process.pid,signal.SIGSTOP)
    observed,status=os.waitpid(process.pid,os.WUNTRACED);assert observed==process.pid and os.WIFSTOPPED(status)
    stopped=True
    peers[0].sendall(test*64);peers[1].sendall(listing(37))
    os.kill(process.pid,signal.SIGCONT);stopped=False
    kind,data=receive(peers[1]);assert kind==13 and struct.unpack_from('>Q',data,8)[0]==37 and struct.unpack_from('>H',data,16)[0]==0
    for index in range(64):assert receive(peers[0])==(15,test)
    peers[1].sendall(struct.pack('>HHIQ',20,9,0,38)+b'arm\0')
    try:
        while True:receive(peers[1])
    except EOFError:pass
    assert process.wait(timeout=5)==0 and not endpoint.exists()
    raw=(out/'daemon.stderr').read_bytes()[marker:];types=[int(x)for x in re.findall(rb'util-service-\d+ DEBUG Received message of type (\d+) and size \d+ from client',raw)]
    assert types.count(15)==64 and types.count(12)==1 and types.count(9)==1,types
    assert types.index(12)<32,types
    current,after=reference.load(reference_path,source,repo);assert ref==current and all(sha(p)==h for p,h in inputs.items())
    result={'status':'passed','scope':'actual unchanged official C daemon FIFO continuation observation; two admitted private Unix clients; finite64 legal TEST backlog versus one LIST; no application children/system service or Rust equivalence claim','source_policy':'service.c:2434 continuation queues one next receive; scheduler.c:545 FIFO ready tail and2081 existing-priority pass','argv':argv,'actual_initial_list_count':0,'actual_both_admitted_TEST_echoes':True,'actual_own_child_stop_and_continue_observed':True,'request_type_trace':types,'later_client_dispatch_index':types.index(12),'first_client_TEST_before_later_LIST':types[:types.index(12)].count(15),'daemon_exit':process.returncode,'inputs':inputs,'inputs_unchanged':True,'stderr_sha256':sha(out/'daemon.stderr'),'configuration_sha256':sha(cfg)}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':'passed','later_LIST_index':types.index(12),'result':str(out/'result.json')}))
finally:
    if process is not None and process.poll()is None:
        if stopped:os.kill(process.pid,signal.SIGCONT)
        process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=2)
    for peer in peers:peer.close()
    stdout.close();stderr.close()
