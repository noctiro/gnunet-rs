#!/usr/bin/env python3
"""Exact public-type compile-fail/positive witnesses, without native execution."""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
from _common import sha,local_snapshot,require_disjoint_output,require_lint_contract
BASE=Path(__file__).resolve().parents[1]
CASES={'locale_send':'E0277','persistent_local_logger':'E0277','config_event_escape':'E0521','main_config_escape':'E0521','options_reuse':'E0382','description_escape':'E0515','option_observer_escape':'E0521','log_record_escape':'E0521','owned_controls':None}
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def artifact(lines,package):
 rows=[]
 for line in lines.splitlines():
  try:row=json.loads(line)
  except ValueError:continue
  if row.get('reason')=='compiler-artifact'and row.get('package_id')==package and row.get('target',{}).get('kind')==['lib']:
   rows.extend(Path(v)for v in row['filenames']if v.endswith('.rlib'))
 if len(set(rows))!=1:raise ValueError(('actual selected rlib missing/ambiguous',package,rows))
 return rows[0]
def errors(data):
 codes=[];messages=[]
 for line in data.splitlines():
  try:row=json.loads(line)
  except ValueError:continue
  if row.get('level')=='error':
   code=row.get('code')
   if code is not None:codes.append(code['code']);messages.append(row.get('message'))
   elif not row.get('message','').startswith('aborting due to '):raise ValueError('unclassified compiler error')
 return codes,messages

def main():
 p=argparse.ArgumentParser()
 for key in ['manifest','repo','target-dir','output']:p.add_argument('--'+key,type=Path,required=True)
 p.add_argument('--toolchain',default='1.99.1');a=p.parse_args()
 if a.manifest.resolve()!=BASE/'Cargo.toml':raise ValueError('manifest is not this maintained package')
 env=os.environ.copy();env['CARGO_TARGET_DIR']=str(a.target_dir.resolve());env.pop('RUSTC',None);env.pop('RUSTC_WRAPPER',None);env.pop('RUSTC_WORKSPACE_WRAPPER',None);cargo=['cargo','+'+a.toolchain];common=['--manifest-path',str(a.manifest),'--offline','--locked','--all-features'];md=json.loads(subprocess.check_output(cargo+['metadata',*common,'--format-version','1'],env=env));selected,inputs=local_snapshot(md,BASE,BASE/'tools');policy=require_lint_contract(BASE,a.repo,md);roots=[Path(row['manifest_path']).parent for row in md['packages']if row['source']is None];out=require_disjoint_output(a.output,[BASE,a.repo,*roots]);out.mkdir();save(out/'inputs-before.json',inputs);result={'status':'not-run'};cases=[]
 try:
  if len(CASES)!=9 or sum(v is not None for v in CASES.values())!=8:raise ValueError('required lifetime witnesses not nonempty/exact')
  build=subprocess.run(cargo+['build',*common,'--lib','--target-dir',str(a.target_dir),'--message-format=json'],capture_output=True,env=env,timeout=120);(out/'build.stdout').write_bytes(build.stdout);(out/'build.stderr').write_bytes(build.stderr)
  if build.returncode:raise ValueError('actual library build failed')
  cfg=[row for row in md['packages']if row['name']=='gnunet-config'and row['source']is None]
  if len(cfg)!=1:raise ValueError('config type identity not unique')
  libs={'gnunet_program_host':artifact(build.stdout,selected['id']),'gnunet_config':artifact(build.stdout,cfg[0]['id'])};library_hashes={str(path):sha(path)for path in libs.values()};version=subprocess.check_output(['rustc','+'+a.toolchain,'--version','--verbose'],env=env);(out/'rustc-version.txt').write_bytes(version)
  rustc_path=Path(subprocess.check_output(['rustup','which','--toolchain',a.toolchain,'rustc'],env=env).decode().strip());compiler_sha=sha(rustc_path)
  for name,expected in CASES.items():
   folder=out/name;folder.mkdir();source=BASE/'tests/ui'/(name+'.rs');copy=folder/source.name;copy.write_bytes(source.read_bytes());library_parent=next(iter(libs.values())).parent;argv=['rustc','+'+a.toolchain,'--edition','2024','--crate-type','lib','--crate-name',name,str(copy),'-L','dependency='+str(library_parent),'-L','dependency='+str(library_parent/'deps'),'--out-dir',str(folder),'--error-format=json']
   for lib,path in libs.items():argv+=['--extern',lib+'='+str(path)]
   child=subprocess.run(argv,env=env,capture_output=True,timeout=30);(folder/'stdout').write_bytes(child.stdout);(folder/'stderr').write_bytes(child.stderr);codes,messages=errors(child.stderr)
   if expected is None:
    if child.returncode or codes:raise ValueError(('positive ownership control did not compile',name,codes))
   elif child.returncode==0 or not codes or set(codes)!={expected}:raise ValueError(('wrong primary compiler error',name,expected,codes))
   cases.append({'name':name,'expected':expected,'exit_code':child.returncode,'actual_primary_codes':codes,'actual_primary_messages':messages,'source':str(copy),'source_sha256':sha(copy),'stdout_sha256':sha(folder/'stdout'),'stderr_sha256':sha(folder/'stderr')});save(out/'progress.json',cases)
  new=json.loads(subprocess.check_output(cargo+['metadata',*common,'--format-version','1'],env=env));_,after=local_snapshot(new,BASE,BASE/'tools')
  if inputs!=after or any(sha(path)!=digest for path,digest in library_hashes.items())or sha(rustc_path)!=compiler_sha:raise ValueError('source/selected artifact/compiler changed')
  result={'status':'passed','negative_controls':8,'positive_controls':1,'cases':cases,'inputs':inputs,'library_artifacts':library_hashes,'compiler':{'path':str(rustc_path),'sha256':compiler_sha,'version_sha256':sha(out/'rustc-version.txt')},'root_lint_policy':policy,'inputs_unchanged':True,'native_program_executed':False}
 except Exception as e:result={'status':'failed','error':str(e),'cases':cases};raise
 finally:save(out/'result.json',result)
 print(json.dumps({'status':result['status'],'negative_controls':8,'positive_controls':1}))
if __name__=='__main__':main()
