#!/usr/bin/env python3
"""Normal public C Elligator primitives, finite valid corpus, no peer/session claim."""
import argparse,hashlib,importlib.util,json,os,re,shlex,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
from session_inputs import CORE, TOOLS, Commands, Inputs, require, same
BASE=TOOLS
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def files(root):return {p.resolve()for p in root.rglob('*')if p.is_file()and not {'target','.git','__pycache__'}.intersection(p.relative_to(root).parts)}
def main():
 p=argparse.ArgumentParser()
 for k in ['repository','source','reference','output']:p.add_argument('--'+k,type=Path,required=True)
 a=p.parse_args();repo,source,reference,out=[getattr(a,k).resolve()for k in ['repository','source','reference','output']];guard=Inputs(repo,source,reference,out,'unmodified-official-c-tcp-communicator-reference-build');normal=guard.reference.normal
 out.mkdir(mode=0o700,exist_ok=False);cmd=Commands(out,repo,normal['runtime_environment']);commands=cmd.rows
 run=cmd.run
 discover=guard.discover
 try:
  before=discover();(out/'inputs-before.json').write_text(json.dumps(before,indent=2)+'\n');rust=cmd.example(CORE,'elligator');artifacts=cmd.artifacts
  build=Path(normal['build']);entry=next(r for r in json.loads((build/'compile_commands.json').read_text())if r['file'].endswith('/crypto_elligator.c'));original=entry.get('arguments')or shlex.split(entry['command']);flags=[];i=1
  while i<len(original):
   x=original[i]
   if x in ['-o','-MF','-MT','-MQ']:i+=2;continue
   if x in ['-c','-MD','-MMD']or x.endswith('/crypto_elligator.c')or re.fullmatch('-O[0-9sgz]',x):i+=1;continue
   flags.append(x);i+=1
  cs=[];prefix=Path(normal['prefix'])
  for opt in ['O0','O2']:
   c=out/('normal-elligator-'+opt);cmd.compile_c('compile-'+opt,[original[0],*flags,'-'+opt,str(TOOLS/'elligator.c'),*shlex.split(normal['build_environment']['LDFLAGS']),'-L'+str(prefix/'lib'),'-lgnunetutil','-Wl,-rpath,'+str(prefix/'lib'),'-o',str(c)],cwd=Path(entry['directory']));cs.append((opt,c));artifacts[str(c)]=sha(c)
  profiles=[];special=[('S',bytes([i])*32,t)for i in range(1,32)for t in [0,1,2,3,4,5,6,7,255]]+[('S',hashlib.sha256(b'official-elligator-'+str(i).encode()).digest(),i%256)for i in range(128)]
  representatives=[bytes([i])*32 for i in [0,1,2,3,31,63,64,127,128,255]]+[hashlib.sha256(b'representative-'+str(i).encode()).digest()for i in range(32)]
  direct=[('D',bytes([*b[:31],(b[31]&63)|high]),0)for b in representatives for high in [0,64,128,192]]
  def batch(label,corpus):
   data=''.join(m+' '+b.hex()+' '+str(t)+'\n'for m,b,t in corpus).encode();(out/(label+'.input')).write_bytes(data);r=[json.loads(s)for s in run(label+'-rust',[rust],data).splitlines()];allc=[]
   if len(r)!=len(corpus):raise ValueError('Rust row count')
   for opt,c in cs:
    actual=[json.loads(s)for s in run(label+'-'+opt,[c],data).splitlines()]
    if actual!=r:
     for i,(a,b)in enumerate(zip(actual,r)):
      if a!=b:(out/'first-difference.json').write_text(json.dumps({'index':i,'input':data.decode().splitlines()[i],'C':a,'Rust':b},indent=2)+'\n');break
     raise ValueError('normal C/Rust '+label+' difference '+opt)
    allc.append({'profile':opt,'rows':len(actual)})
   profiles.append({'corpus':label,'rows':len(r),'actual_C_profiles':allc,'input_sha256':hashlib.sha256(data).hexdigest()});return r
  matched=batch('special',special);batch('direct',direct)
  valid=sorted({r['point']for r in matched if 'error'not in r})[:64];encode=[('E',bytes.fromhex(point),t)for point in valid for t in [0,1,2,3,4,5,6,7,255]];batch('canonical-public-encode',encode)
  require(sum(r['rows']for r in profiles)==1151,'complete finite Elligator corpus1151 required')
  cmd.check_artifacts()
  after=discover();(out/'inputs-after.json').write_text(json.dumps(after,indent=2)+'\n')
  if before!=after or any(sha(Path(p))!=value for p,value in artifacts.items()):raise ValueError('inputs or actual binaries changed')
  result={'status':'passed-finite-normal-primitives','inputs_unchanged':True,'normal_reference':{'path':str(reference),'sha256':sha(reference)},'corpora':profiles,'Rust_observations':sum(r['rows']for r in profiles),'C_observations':sum(r['rows']for r in profiles)*2,'shared_KEM_proofs':'Source0x0022 encaps+decaps agree and exact public HKDF-expand proof bytes match; no production PRK export','safe_corpus':'All representatives are valid public direct-map inputs. Scalars call special-public first; unrepresentable cases never invoke C KEM that ignores an error. Encoding input consists only of canonical valid curve points already compared in both observers. No malformed base32/time/low-order C DH case.','actual_daemon_or_peer_interoperation':False,'commands':commands,'artifacts':artifacts,'actual_c_header_inputs':cmd.headers,'pending':['full session owner/host','HPKE Context0x0022 setup integration','public inverse-map noncanonical-coordinate acceptance profile','complete primitive/public API acceptance beyond this finite corpus']};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'Rust':result['Rust_observations'],'C':result['C_observations'],'receipt':str(out/'result.json')}))
 except BaseException as e:(out/'failure.json').write_text(json.dumps({'error':str(e),'commands':commands},indent=2)+'\n');raise
if __name__=='__main__':main()
