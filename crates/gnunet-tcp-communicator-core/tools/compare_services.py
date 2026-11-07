#!/usr/bin/env python3
"""Fresh normal C library/layout observations; no daemon/session promotion."""
import argparse,hashlib,importlib.util,json,os,re,shlex,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
from session_inputs import CORE, TOOLS, Commands, Inputs, require, same
BASE=TOOLS
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def files(root):return{p.resolve()for p in root.rglob('*')if p.is_file()and not{'target','.git','__pycache__'}.intersection(p.relative_to(root).parts)}
def main():
 p=argparse.ArgumentParser()
 for k in ['repository','source','reference','output']:p.add_argument('--'+k,type=Path,required=True)
 a=p.parse_args();repo,source,reference,out=[getattr(a,k).resolve()for k in ['repository','source','reference','output']];guard=Inputs(repo,source,reference,out,'unmodified-official-c-tcp-peer-services-reference-build');normal=guard.reference.normal
 out.mkdir(mode=0o700,exist_ok=False);cmd=Commands(out,repo,normal['runtime_environment']);commands=cmd.rows
 run=cmd.run
 discover=guard.discover
 try:
  before=discover();(out/'inputs-before.json').write_text(json.dumps(before,indent=2)+'\n');rust=cmd.example(CORE,'services');artifacts=cmd.artifacts;expected=json.loads(run('rust-observe',[rust]));same(set(expected),{'sizes','pils_public','store','native_v4','nat_register_layout'},'exact5 service fields');require(all(expected.values()),'empty service field')
  entry=next(r for r in json.loads(Path(normal['compile_commands']['path']).read_text())if r['file'].endswith('/peerstore_common.c'));original=entry.get('arguments')or shlex.split(entry['command']);flags=[];i=1
  while i<len(original):
   x=original[i]
   if x in ['-o','-MF','-MT','-MQ']:i+=2;continue
   if x in ['-c','-MD','-MMD']or x.endswith('/peerstore_common.c')or re.fullmatch('-O[0-9sgz]',x):i+=1;continue
   flags.append(x);i+=1
  prefix=Path(normal['prefix']);profiles=[]
  for opt in['O0','O2']:
   binary=out/('service-components-'+opt);cmd.compile_c('compile-'+opt,[original[0],*flags,'-'+opt,*['-I'+str(source/'src/service'/part)for part in ['peerstore','transport','pils','nat']],str(TOOLS/'service_components.c'),*shlex.split(normal['build_environment']['LDFLAGS']),'-L'+str(prefix/'lib'),'-lgnunetpils','-lgnunetpeerstore','-lgnunetutil','-Wl,-rpath,'+str(prefix/'lib'),'-o',binary],cwd=Path(entry['directory']));artifacts[str(binary)]=sha(binary);actual=json.loads(run('observe-'+opt,[binary]));same(actual,expected,'normal C/Rust service bytes');profiles.append({'profile':opt,'fields':actual})
  cmd.check_artifacts()
  after=discover();(out/'inputs-after.json').write_text(json.dumps(after,indent=2)+'\n');require(before==after and all(sha(Path(p))==s for p,s in artifacts.items()),'complete workspace/reference/artifact set changed');result={'status':'passed-source-bound-service-components','inputs_unchanged':True,'commands':commands,'artifacts':artifacts,'actual_c_header_inputs':cmd.headers,'profiles':profiles,'normal_reference':{'path':str(reference),'sha256':sha(reference)},'scope':'Normal C PILS derive public API, normal-library PEERSTORE_create_record_mq_envelope, original header sizeof/offset layouts, native initialized sockaddr. NAT register is an explicitly handwritten finite layout composition; not actual C register/API scheduler or normal daemon.','actual_peer_interoperation':False};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'receipt':str(out/'result.json')}))
 except BaseException as e:(out/'failure.json').write_text(json.dumps({'error':str(e),'commands':commands},indent=2)+'\n');raise
if __name__=='__main__':main()
