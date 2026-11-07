#!/usr/bin/env python3
"""Source-bound pure ARM core+native-header byte verification; no ARM service startup."""
import argparse,hashlib,json,os,re,shlex,subprocess,time,importlib.util
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
UPSTREAM=None
PIN='346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def input_files(reference):
 files={ROOT/'Cargo.toml',ROOT/'Cargo.lock',ROOT/'rust-toolchain.toml',reference}
 for base in [HERE,ROOT/'crates/gnunet-types',ROOT/'crates/gnunet-wire']:
  for p in base.rglob('*'):
   if 'target' in p.relative_to(base).parts:continue
   if p.is_symlink():raise RuntimeError('source symlink '+str(p))
   if p.is_file() and (p.suffix in {'.rs','.c','.md','.py','.json','.toml'}or p.name=='Cargo.lock'):files.add(p)
 inv=json.loads((HERE/'inventory.json').read_text())
 for name,expected in inv['source_sha256'].items():
  p=UPSTREAM/name
  if sha(p)!=expected:raise RuntimeError('pinned C source changed: '+name)
  files.add(p)
 ref=json.loads(reference.read_text())
 if ref['status']!='passed'or not ref['source_unchanged']:raise RuntimeError('normal C build is not passed/source-bound')
 if ref['upstream']['revision']!=PIN:raise RuntimeError('normal C build revision differs from pinned source')
 if ref.get('source') is not None and Path(ref['source']).resolve()!=UPSTREAM:raise RuntimeError('normal C build declares another source')
 setup=[row for row in ref['commands'] if row['name']=='meson-setup']
 if len(setup)!=1 or setup[0]['exit_code']!=0 or Path(setup[0]['argv'][3]).resolve()!=UPSTREAM or Path(setup[0]['argv'][2]).resolve()!=Path(ref['build']).resolve():raise RuntimeError('normal C setup source/build differs')
 helper=ROOT/'tools/reference/build_reference.py'
 spec=importlib.util.spec_from_file_location('arm_reference_inputs',helper)
 common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
 if common.source_state(UPSTREAM)!=ref['upstream']:raise RuntimeError('normal C full tracked source state differs')
 files.update([helper,Path(ref['build'])/'src/include/gnunet_config.h'])
 for group in ['libraries']:
  for item in ref[group]:
   p=Path(item['path'])
   if sha(p)!=item['sha256']:raise RuntimeError('normal library changed: '+str(p))
   files.add(p)
 for group in ['compile_commands','generated_config']:
  item=ref[group];p=Path(item['path'])
  if sha(p)!=item['sha256']:raise RuntimeError('normal build input changed: '+str(p))
  files.add(p)
 for item in json.loads((HERE/'api-status.json').read_text())['compiler_inventory_sha256'].items():
  name,expected=item;p=HERE/name
  if sha(p)!=expected:raise RuntimeError('compiler inventory changed')
  files.add(p)
 return {str(p):sha(p)for p in sorted(files)}
def main():
 global UPSTREAM
 ap=argparse.ArgumentParser(description=__doc__)
 for name in ['output','reference','upstream']:ap.add_argument('--'+name,type=Path,required=True)
 args=ap.parse_args();out=args.output.resolve();refpath=args.reference.resolve();UPSTREAM=args.upstream.resolve();TARGET=out/'target'
 for source in [HERE,UPSTREAM]:
  if out.is_relative_to(source) or source.is_relative_to(out):raise RuntimeError('output/source must be disjoint')
 out.mkdir(parents=True,exist_ok=False)
 before=input_files(refpath);(out/'sources-before.json').write_text(json.dumps(before,indent=2)+'\n');commands=[]
 controls=[];original_reference=json.loads(refpath.read_text())
 for label in ['revision','declared-source','setup-source']:
  changed=json.loads(json.dumps(original_reference))
  if label=='revision':changed['upstream']['revision']='0'*40
  elif label=='declared-source':changed['source']=str(out/'wrong-source')
  else:next(c for c in changed['commands'] if c['name']=='meson-setup')['argv'][3]=str(out/'wrong-source')
  control=out/('invalid-reference-'+label+'.json');control.write_text(json.dumps(changed,indent=2)+'\n')
  try:input_files(control)
  except RuntimeError as error:controls.append({'case':label,'rejected':True,'reason':str(error)})
  else:raise RuntimeError('invalid normal reference accepted: '+label)
 (out/'reference-negative-controls.json').write_text(json.dumps(controls,indent=2)+'\n')
 def run(name,argv,cwd=ROOT,nonzero=False,env=None):
  start=time.monotonic();r=subprocess.run([str(a)for a in argv],cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE);(out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
  commands.append({'name':name,'argv':[str(a)for a in argv],'cwd':str(cwd),'exit_code':r.returncode,'elapsed_seconds':time.monotonic()-start})
  if (r.returncode==0)==nonzero:raise RuntimeError(name+' unexpected exit '+str(r.returncode))
  return r.stdout.decode('utf-8','replace')+'\n'+r.stderr.decode('utf-8','replace')
 common=['--manifest-path',HERE/'Cargo.toml','--target-dir',TARGET,'--offline','--locked','--no-default-features','-p','gnunet-arm-core']
 run('toolchain',['rustc','+1.99.1','-Vv']);run('cargo-version',['cargo','+1.99.1','-V'])
 run('fmt',['cargo','+1.99.1','fmt','--manifest-path',HERE/'Cargo.toml','--','--check'])
 text=run('tests',['cargo','+1.99.1','test',*common,'--tests']);actual=re.findall(r'^test (\S+) \.\.\. ok$',text,re.M)
 expected=[]
 for p in list((HERE/'src').glob('*.rs'))+list((HERE/'tests').glob('*.rs')):expected+=re.findall(r'#\[test\](?:\s*#\[[\s\S]*?\])*\s*fn\s+(\w+)',p.read_text())
 if not actual or len(actual)!=len(expected)or set(actual)!=set(expected):raise RuntimeError('actual test set differs from source')
 doc=run('doctests',['cargo','+1.99.1','test',*common,'--doc']);docnames=re.findall(r'^test (.+?) \.\.\. ok$',doc,re.M)
 if len(docnames)!=4 or sum('compile fail'in n for n in docnames)!=2:raise RuntimeError('missing lifetime documentation controls')
 run('clippy',['cargo','+1.99.1','clippy',*common,'--all-targets','--','-D','warnings'])
 env=os.environ.copy();env['RUSTDOCFLAGS']='-D warnings';run('docs',['cargo','+1.99.1','doc',*common,'--no-deps'],env=env)
 run('thumb',['cargo','+1.99.1','check',*common,'--target','thumbv6m-none-eabi'])
 run('metadata',['cargo','+1.99.1','metadata','--manifest-path',HERE/'Cargo.toml','--offline','--locked','--no-default-features','--format-version','1']);meta=json.loads((out/'metadata.stdout').read_text())
 run('production-tree',['cargo','+1.99.1','tree','--manifest-path',HERE/'Cargo.toml','--offline','--locked','--no-default-features','-p','gnunet-arm-core','--edges','normal','--prefix','none','--format','{p}|{f}'])
 used=set()
 for line in (out/'production-tree.stdout').read_text().splitlines():
  package,features=line.removesuffix(' (*)').split('|',1)
  if features.strip():raise RuntimeError('unexpected production feature')
  used.add(package.split()[0])
 if used!={'gnunet-arm-core','gnunet-types','gnunet-wire'}or any(p['source']is not None for p in meta['packages']if p['name']in used):raise RuntimeError('unexpected production dependency')
 run('ui-artifacts',['cargo','+1.99.1','build',*common,'--lib','--message-format=json']);libraries={}
 for line in (out/'ui-artifacts.stdout').read_text().splitlines():
  a=json.loads(line)
  if a.get('reason')=='compiler-artifact':
   for f in a['filenames']:
    if f.endswith('.rlib'):libraries[a['target']['name']]=f
 rust=['rustc','+1.99.1','--edition=2024','--crate-type=lib','--emit=metadata','--error-format=json','-L','dependency='+str(TARGET/'debug/deps'),'--extern','gnunet_arm_core='+libraries['gnunet_arm_core'],'--extern','gnunet_types='+libraries['gnunet_types']]
 ui=[]
 for name,expected_code in [('frame_after_write','E0502'),('list_escape','E0515'),('controls',None)]:
  run('ui-'+name,[*rust,HERE/'tests/ui'/(name+'.rs'),'-o',out/(name+'.rmeta')],nonzero=expected_code is not None)
  codes=[]
  for line in (out/('ui-'+name+'.stderr')).read_text().splitlines():
   d=json.loads(line)
   if d.get('level')=='error'and d.get('code'):codes.append(d['code']['code'])
  if codes!=([expected_code]if expected_code else[]):raise RuntimeError('unexpected UI code '+name+':'+str(codes))
  ui.append({'case':name,'codes':codes,'expected':expected_code,'success':True})
 reference=json.loads(refpath.read_text());ccdb=json.loads(Path(reference['compile_commands']['path']).read_text());entry=next(e for e in ccdb if e['file'].endswith('/arm_api.c'));argv=entry.get('arguments')or shlex.split(entry['command']);cc=[];skip=False
 for a in argv:
  if skip:skip=False;continue
  if a in ['-MQ','-MF','-o']:skip=True;continue
  if a in ['-MD','-c']or a.endswith('/arm_api.c'):continue
  cc.append(a)
 cc +=[str(HERE/'normal_bytes.c'),'-o',str(out/'normal-bytes')]
 run('normal-header-compile',cc,cwd=Path(entry['directory']));run('normal-header-bytes',[out/'normal-bytes'])
 run('rust-wire-bytes',['cargo','+1.99.1','run',*common,'--example','wire_trace'])
 crows=[json.loads(s)for s in (out/'normal-header-bytes.stdout').read_text().splitlines()];rrows=[json.loads(s)for s in (out/'rust-wire-bytes.stdout').read_text().splitlines()];cframes=[r for r in crows if r['kind']=='frame'];layout=next(r for r in crows if r['kind']=='layout')
 if len(cframes)!=8 or cframes!=rrows:raise RuntimeError('actual native C/Rust frames differ')
 if layout!={'kind':'layout','message':16,'result':24,'list':24,'info':28,'status':8,'message_align':8,'result_field':16,'list_count':16,'info_restart':12,'info_last_start':20}:raise RuntimeError('native peer ABI unavailable for this proven profile')
 if next(r for r in crows if r['kind']=='public_exit_status')['value']!=65535:raise RuntimeError('C unsigned projection mismatch')
 requirements=json.loads((HERE/'requirements.json').read_text());apis=json.loads((HERE/'api-status.json').read_text())
 if apis['arm_functions']!=8 or apis['testing_functions']!=6 or len(apis['functions'])!=14 or any(f['verification']is not None for f in apis['functions']):raise RuntimeError('surface shrink/promotion')
 test_names=set(expected)
 for f in requirements['features']:
  if f['verification']is not None or any(n not in test_names for n in f['pure_tests']):raise RuntimeError('invalid test binding/promotion')
 after=input_files(refpath);(out/'sources-after.json').write_text(json.dumps(after,indent=2)+'\n')
 if before!=after:raise RuntimeError('source/reference mutated during proof')
 result={'schema':1,'success':True,'scope':'Integrated pure ARM client/monitor/codec plus normal native-header8-frame component oracle; no libgnunetarm public API or ARM daemon interoperability credit','commands':commands,'reference_negative_controls':controls,'actual_pure_tests':len(actual),'test_names':actual,'actual_rustdoc_controls':len(docnames),'rustdoc_names':docnames,'ui':ui,'native_C_Rust_matched_frames':len(cframes),'native_layout':layout,'frame_sizes':{f['label']:f['size']for f in cframes},'native_normal_library_build_receipt':str(refpath),'native_normal_library_build_receipt_sha256':sha(refpath),'normal_public_API_trace_executed':False,'ARM_daemon_or_managed_process_started':False,'network_or_system_changes':False,'source_unchanged':True,'source_inputs_sha256':sha(out/'sources-before.json'),'all8_ARM_and6_testing_functions_retained':True,'source_derived_case_count':requirements['feature_count'],'verification_promotion':False,'actual_align4_platform_interop':False,'thumb_is_only_no_std_build_not_peer_ABI_evidence':True,'artifact_sha256':{p.name:sha(p)for p in sorted(out.iterdir())if p.is_file()}}
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'success':True,'pure_tests':len(actual),'rustdoc':len(docnames),'normal_header_frames':len(cframes),'result':str(out/'result.json'),'sha256':sha(out/'result.json')}))
if __name__=='__main__':main()
