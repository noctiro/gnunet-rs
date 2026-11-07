#!/usr/bin/env python3
"""Actual compiler diagnostics for scoped owner reset and borrowed frame controls."""
import argparse,hashlib,json,pathlib,subprocess
BASE=pathlib.Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser();p.add_argument('--target',required=True,type=pathlib.Path);p.add_argument('--output',required=True,type=pathlib.Path);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 deps=a.target.resolve()/'debug/deps'
 def library(name):
  paths=list(deps.glob('lib'+name+'-*.rlib'));assert len(paths)==1,paths;return paths[0]
 own=library('gnunet_arm_service_core');core=library('gnunet_arm_core')
 binding={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [own,core]}
 common=['rustc','+1.99.1','--edition=2024','--crate-type=lib','--emit=metadata','--error-format=json','--extern','gnunet_arm_service_core='+str(own),'--extern','gnunet_arm_core='+str(core),'-L','dependency='+str(deps)]
 cases=[]
 for name,expected in [('scope_reset_negative','E0499'),('scope_reset_positive',None)]:
  source=BASE/'tests/ui'/(name+'.rs');result=subprocess.run(common+['--crate-name',name,'-o',str(out/(name+'.rmeta')),str(source)],capture_output=True,text=True)
  (out/(name+'.stdout')).write_text(result.stdout);(out/(name+'.stderr')).write_text(result.stderr)
  diagnostics=[json.loads(s) for s in result.stderr.splitlines() if s.strip()];coded=[d for d in diagnostics if d.get('level')=='error' and d.get('code')]
  if expected:
   assert result.returncode!=0 and len(coded)==1 and coded[0]['code']['code']==expected,result.stderr
   assert any(span['is_primary'] and pathlib.Path(span['file_name']).resolve()==source.resolve() for span in coded[0]['spans'])
  else:assert result.returncode==0 and not coded and (out/(name+'.rmeta')).stat().st_size>0,result.stderr
  cases.append({'name':name,'expected_diagnostic':expected,'exit':result.returncode,'passed':True,'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest()})
 assert binding=={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [own,core]}
 (out/'result.json').write_text(json.dumps({'status':'passed','cases':cases,'selected_rlibs':binding,'scope':'actual compiler, negative requires only E0499 at intended source and positive requires nonempty metadata'},indent=2)+'\n')
 print(json.dumps({'status':'passed','cases':len(cases)}))
if __name__=='__main__':main()
