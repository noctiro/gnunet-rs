#!/usr/bin/env python3
"""Normal C mutable-configuration observation; no Rust equivalence fabrication."""
import argparse,json,os,pathlib,socket,struct,subprocess
from reference import load,compile_probe,sha
from _common import require_disjoint_output
p=argparse.ArgumentParser()
for name in ['repo','source','reference','output']:p.add_argument('--'+name,type=pathlib.Path,required=True)
a=p.parse_args();package=pathlib.Path(__file__).resolve().parents[1];r,inputs=load(a.reference,a.source,a.repo);out=require_disjoint_output(a.output,[package,a.repo,a.source,a.reference.resolve().parent,pathlib.Path(r['build']),pathlib.Path(r['prefix'])]);out.mkdir();binary=out/'monitor-configuration';compilation=compile_probe(package/'tools/monitor_configuration.c',binary,r);before={**inputs,**{str(path):sha(path)for path in [binary,package/'tools/monitor_configuration.c',pathlib.Path(__file__)]}};endpoint=out/'m.sock';s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.bind(str(endpoint));s.listen();s.settimeout(5);environment={key:value for key,value in os.environ.items()if not key.startswith(('GNUNET_','LISTEN_'))};environment.update(r['runtime_environment']);process=subprocess.Popen([str(binary),str(endpoint)],env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
 conn,_=s.accept();conn.settimeout(5);data=b''
 while len(data)<4:
  part=conn.recv(4-len(data))
  if not part:raise ValueError('physical EOF before actual MONITOR')
  data+=part
 if data!=struct.pack('!HH',4,14):raise ValueError('actual MONITOR missing')
 conn.sendall(struct.pack('!HHI',12,11,0)+b'arm\0');conn.shutdown(socket.SHUT_WR);conn.close();stdout,stderr=process.communicate(timeout=5);(out/'caller.stdout').write_bytes(stdout);(out/'caller.stderr').write_bytes(stderr)
 if process.returncode:raise RuntimeError((process.returncode,stderr.decode()))
 events=[json.loads(line)for line in stdout.splitlines()];expected=[{'event':'status','status':0,'service':'arm'},{'event':'configuration-removed'},{'event':'unavailable','status':1},{'event':'done','statuses':1,'unavailable':1,'failed':0}]
 if events!=expected:raise ValueError(events)
 after,more=load(a.reference,a.source,a.repo)
 if r!=after or inputs!=more or any(sha(path)!=value for path,value in before.items()):raise ValueError('source/library/binary changed')
 result={'status':'observed-normal-C-only','events':events,'exit_code':process.returncode,'compilation':compilation,'inputs':before,'inputs_unchanged':True,'rust_equivalence':'pending explicit update port; no fake Rust callback','source_semantics':'C ARM retains borrowed cfg; new logical MQ rereads full config and can issue one actual unavailable callback/no new timer'};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'result':str(out/'result.json')}))
finally:
 s.close()
 if process.poll()is None:process.kill();process.communicate(timeout=2)
