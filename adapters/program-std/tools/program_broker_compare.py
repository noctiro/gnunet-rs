#!/usr/bin/env python3
"""Actual normal PROGRAM -> Resolver selection and source SPEEDUP/driver wake.
No DNS/public network is used: only two owned Unix peers, with child IP denied.
"""
import argparse,asyncio,json,os,re,shutil,struct,subprocess,tempfile,time
from pathlib import Path
from _common import sha,local_snapshot,require_disjoint_output,require_lint_contract
from normal_reference import load,compile_probe
BASE=Path(__file__).resolve().parents[1]
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
async def frame(reader):
 h=await reader.readexactly(4);n,k=struct.unpack('!HH',h)
 if n<4:raise ValueError('bad frame')
 return h+await reader.readexactly(n-4)
def clock_rows(data,before,after,speedup):
 events=[];clock={}
 for line in data.splitlines():
  m=re.fullmatch(rb'(MAIN|QUEUED|END) WALL ([0-9]+) ([0-9]+) LOGICAL ([0-9]+) OFFSET (-?[0-9]+)',line)
  if not m:events.append(line.decode());continue
  name=m[1].decode();first,last,logical,offset=map(int,m.groups()[1:])
  if name in clock or not before<=first<=last<=after or not first+offset<=logical<=last+offset:raise ValueError(('actual coherent clock boundary invalid',line))
  if offset<0 or offset%100000 or (not speedup and offset):raise ValueError('unexpected actual source offset')
  clock[name]={'wall_before':first,'wall_after':last,'logical':logical,'offset':offset};events.append(name)
 if set(clock)!= {'MAIN','QUEUED','END'}:raise ValueError('actual clock stages missing')
 if clock['MAIN']['offset']or clock['QUEUED']['offset']:raise ValueError('speedup tick ran before main callback returned')
 if speedup:
  end=clock['END'];queued=clock['QUEUED'];start=clock['MAIN'];earliest=start['logical']+500000;latest=queued['logical']+500000
  if not earliest<=end['logical']<=latest+100000 or end['offset']<=0:raise ValueError('source logical timeout/revision did not expire original deadline')
 return events,clock
async def actor(binary,label,config,initial,env,mode,run,out,sandbox):
 graphs={'a':[],'b':[]};errors=[];tasks=[]
 async def peer(reader,writer,name):
  rows=[];graphs[name].append(rows)
  try:
   raw=await asyncio.wait_for(frame(reader),2);size,kind,direction,family=struct.unpack('!HHII',raw[:12]);expected=b'owned.program.invalid\0'
   if size!=len(raw)or kind!=4 or direction!=0 or family!=0 or raw[12:16]!=(1).to_bytes(4,os.sys.byteorder)or raw[16:]!=expected:raise ValueError(('official request mismatch',raw.hex()))
   rows.append({'request_hex':raw.hex()})
   if mode=='reply':
    for payload in [bytes.fromhex('7f00002a'),b'']:
     packet=struct.pack('!HH',8+len(payload),5)+raw[12:16]+payload;writer.write(packet);await writer.drain();rows.append({'response_hex':packet.hex()})
   if await asyncio.wait_for(reader.read(),2)!=b'':raise ValueError('unexpected extra request')
   rows.append({'eof':True})
  except Exception as e:errors.append(name+' '+str(e))
  finally:writer.close();await writer.wait_closed()
 def accept(name):
  def start(reader,writer):tasks.append(asyncio.create_task(peer(reader,writer,name)))
  return start
 a=await asyncio.start_unix_server(accept('a'),path=str(run/'a'));b=await asyncio.start_unix_server(accept('b'),path=str(run/'b'));current=env.copy();current['OWNED_BROKER_INITIAL']=str(initial);argv=['/usr/bin/sandbox-exec','-f',str(sandbox),str(binary),'-c',str(config),'-L','NONE'];before=time.time_ns()//1000;started=time.monotonic();child=await asyncio.create_subprocess_exec(*argv,env=current,stdin=asyncio.subprocess.DEVNULL,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
 try:
  stdout,stderr=await asyncio.wait_for(child.communicate(),3);after=time.time_ns()//1000;elapsed=time.monotonic()-started;await asyncio.wait_for(asyncio.gather(*tasks),3);(out/(label+'.stdout')).write_bytes(stdout);(out/(label+'.stderr')).write_bytes(stderr)
  if child.returncode or stderr or errors:raise ValueError(('actual participant failure',label,mode,child.returncode,stderr,errors))
  events,clock=clock_rows(stdout,before,after,mode=='speedup');expected=['MAIN','QUEUED']+(['ADDRESS 7f00002a']if mode=='reply'else[])+['END','RETURN 1 TASKS 1 ENDS 1']
  if events!=expected or graphs['a']or len(graphs['b'])!=1:raise ValueError(('PROGRAM selection/actual callbacks mismatch',events,graphs))
  if mode=='timeout'and not .45<=elapsed<1.5:raise ValueError('normal original timeout interval outside bound')
  if mode=='speedup'and not .05<=elapsed<.45:raise ValueError('actual speedup did not wake existing original request timer')
  return {'actor':label,'pid':child.pid,'exit_code':child.returncode,'argv':argv,'events':events,'clock':clock,'graphs':graphs,'elapsed_seconds':elapsed,'stderr_hex':stderr.hex()}
 finally:
  if child.returncode is None:child.terminate();await asyncio.wait_for(child.wait(),3)
  a.close();b.close();await a.wait_closed();await b.wait_closed()
  for task in tasks:
   if not task.done():task.cancel()
  await asyncio.gather(*tasks,return_exceptions=True)
  for path in [run/'a',run/'b']:
   if path.exists():path.unlink()
async def main(a):
 r,normal=load(a.reference,a.source,a.repo);env=os.environ.copy();env['CARGO_TARGET_DIR']=str(BASE/'target');cargo=['cargo','+'+a.toolchain,'metadata','--manifest-path',str(BASE/'Cargo.toml'),'--offline','--locked','--all-features','--format-version','1'];md=json.loads(subprocess.check_output(cargo,env=env));policy=require_lint_contract(BASE,a.repo,md);_,inputs=local_snapshot(md,BASE,BASE/'tools');inputs[str(a.rust.resolve())]=sha(a.rust);out=require_disjoint_output(a.output,[BASE,a.repo,a.source,a.reference.resolve().parent,Path(r['build']),Path(r['prefix'])]);out.mkdir();rows=[];result={'status':'not-run'}
 try:
  c=out/'normal-program-broker';compiled=compile_probe(BASE/'reference/program_broker.c',c,r);save(out/'compile.json',compiled);rust=out/'rust-program-broker';shutil.copy2(a.rust,rust);actors={str(c):sha(c),str(rust):sha(rust)};env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_','OWNED_','DYLD_','LD_'))and k not in['POSIXLY_CORRECT','JOURNAL_STREAM']};env.update(r['runtime_environment']);env['LC_ALL']='C'
  for mode in ['reply','timeout','speedup']:
   folder=out/mode;folder.mkdir();run=Path(tempfile.mkdtemp(prefix='pgbr-',dir='/private/tmp'));base=run/'base';base.mkdir();home=run/'home';home.mkdir();initial=run/'initial';initial.write_text('[resolver]\nUNIXPATH = '+str(run/'a')+'\nHOSTNAME = localhost\nPORT = 0\n');config=run/'main';config.write_text('[resolver]\nUNIXPATH = '+str(run/'b')+'\nHOSTNAME = localhost\nPORT = 0\n'+('[TESTING]\nSPEEDUP_INTERVAL = 100ms\nSPEEDUP_DELTA = 100ms\n'if mode=='speedup'else''));current=env.copy();current.update(HOME=str(home),XDG_CONFIG_HOME=str(home),GNUNET_BASE_CONFIG=str(base));observed=[]
   try:
    for label,binary in [('c',c),('rust',rust)]:observed.append(await actor(binary,label,config,initial,current,mode,run,folder,BASE/'reference/no_ip.sb'))
    if observed[0]['events']!=observed[1]['events']or observed[0]['graphs']!=observed[1]['graphs']:raise ValueError('actual C/R PROGRAM graph mismatch')
    rows.append({'mode':mode,'actors':observed,'matched':True,'configuration':config.read_text(),'initial_configuration':initial.read_text()});save(out/'progress.json',rows)
   finally:shutil.rmtree(run)
  _,new_normal=load(a.reference,a.source,a.repo);new_md=json.loads(subprocess.check_output(cargo,env={**os.environ,'CARGO_TARGET_DIR':str(BASE/'target')}));_,after=local_snapshot(new_md,BASE,BASE/'tools');after[str(a.rust.resolve())]=sha(a.rust)
  if inputs!=after or normal!=new_normal or any(sha(p)!=h for p,h in actors.items()):raise ValueError('actual source closure/actor/normal library changed')
  result={'status':'passed','profiles':len(rows),'actual_C_R_actors':len(rows)*2,'scope':'normal unchanged PROGRAM_run2 public main selects actual shared Resolver before one real type4 request; caller-driven broker with same logical clock; raw response/END vs original timeout vs source SPEEDUP revision; owned Unix peers with IP denied; no normal Resolver daemon credit','rows':rows,'inputs':inputs,'normal_inputs':normal,'actors':actors,'compiled':compiled,'root_lint_policy':policy,'inputs_unchanged':True}
 except Exception as e:result={'status':'failed','error':str(e),'rows':rows};raise
 finally:save(out/'result.json',result)
 print(json.dumps({'status':result['status'],'profiles':len(rows)}))
if __name__=='__main__':
 p=argparse.ArgumentParser()
 for key in ['repo','source','reference','rust','output']:p.add_argument('--'+key,type=Path,required=True)
 p.add_argument('--toolchain',default='1.99.1');asyncio.run(main(p.parse_args()))
