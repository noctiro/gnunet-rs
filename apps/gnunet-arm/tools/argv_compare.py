#!/usr/bin/env python3
"""Exact normal-C/Rust argv C-locale transcript; no service/network operation."""
import argparse,json,os,subprocess,tempfile,hashlib
from pathlib import Path
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser()
 for name in ('reference','rust','output'):p.add_argument('--'+name,type=Path,required=True)
 args=p.parse_args();out=args.output.resolve();out.mkdir(exist_ok=False);ref=json.loads(args.reference.read_text());normal=Path(ref['artifacts']['client']['path']);assert sha(normal)==ref['artifacts']['client']['sha256']
 profiles=[[b'--help'],[b'--version'],[b'-h'],[b'-v'],[b'--he'],[b'--vers'],[b'--unknown'],[b'-z'],[b'-?'],[b'-i'],[b'--init'],[b'--ini'],[b'--in'],[b'--quiet=x'],[b'--qu=x'],[b'--v=x'],[b'--n'],[b'--=oops'],[b'---foo'],[b'--hello=x'],[b'--help',b'-s'],[b'-s',b'--help'],[b'--help',b'--version'],[b'--version',b'--help'],[b'-hh'],[b'-vv'],[b'--unknown',b'--help'],[b'--help',b'--unknown'],[b'--init=-s',b'--help'],[b'-ifoo',b'--help'],[b'-aqIEO',b'--help'],[b'--help',b'--',b'-s']]
 rows=[];env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_'))};env.update(ref['runtime_environment']);env['LC_ALL']='C';env.pop('POSIXLY_CORRECT',None);env['GNUNET_ARGS']=''
 for name,key in [('user','HOME'),('xdg','XDG_CONFIG_HOME'),('cache','XDG_CACHE_HOME'),('data','XDG_DATA_HOME'),('run','XDG_RUNTIME_DIR'),('base','GNUNET_BASE_CONFIG')]:
  directory=out/name;directory.mkdir(mode=0o700);env[key]=str(directory)
 try:
  for i,argv in enumerate(profiles):
   observations=[]
   for actor,binary in [('c',normal),('rust',args.rust)]:
    command=[b'gnunet-arm']+argv;r=subprocess.run(command,executable=os.fsencode(binary),env=env,capture_output=True,timeout=3);(out/(str(i)+'-'+actor+'.stdout')).write_bytes(r.stdout);(out/(str(i)+'-'+actor+'.stderr')).write_bytes(r.stderr);observations.append({'exit':r.returncode,'stdout_hex':r.stdout.hex(),'stderr_hex':r.stderr.hex()})
   rows.append({'argv_hex':[a.hex()for a in argv],'matched':observations[0]==observations[1],'c':observations[0],'rust':observations[1]});(out/'progress.json').write_text(json.dumps(rows,indent=2)+'\n')
   if observations[0]!=observations[1]:raise ValueError('argv mismatch '+str(i))
  result={'status':'passed','scope':'actual C-locale argv processors and transcripts, not genericPROGRAM locale/logging/startup completion','profiles':len(rows),'actual_cli_processes':2*len(rows),'excluded_malformed_relative_time_profiles':4,'malformed_relative_time_C_executed':False,'rows':rows,'normal_binary_sha256':sha(normal),'rust_binary_sha256':sha(args.rust)}
 except Exception as error:result={'status':'failed','error':str(error),'rows':rows};raise
 finally:(out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'status':result['status'],'profiles':len(rows),'result':str(out/'result.json')}))
if __name__=='__main__':main()
