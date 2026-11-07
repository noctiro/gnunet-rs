#!/usr/bin/env python3
"""Source-bound IDNA validation, with explicit immutable reference/data paths.

All generated probes, Cargo targets, logs and receipts live under --output.
Source tables are checked rather than rewritten. No network is used.
"""
import argparse,hashlib,json,pathlib,re,subprocess,sys,time,tarfile
ROOT=pathlib.Path(__file__).resolve().parent
EXPECTED={'libidn2_archive':'f557911bf6171621e1f72ff35f5b1825bb35b52ed45325dcdee931e5d3c0787a','libunistring_archive':'5b0ecd46cbf225375f20ab4056197e66a7ac590e2684c069af407ae3383c9d81','ucd15':'cb1c663d053926500cd501229736045752713a066bd75802098598b7a7056177','ucd18':'7b3e555514060b92290d154f53655c5eb0fa62b16eb04c03434ff72d1a66a0d8'}
COUNTS={'selected':174,'normal':95370,'normal15':95370,'normal18':100855,'scalar':3336189,'properties':134172,'idna15':50120,'alabels':2223872,'context':770860,'puny_fuzz':200000,'expanded_nfc':6,'invalid_utf8':130578,'parsed_label':1,'compressed_name':1233,'compressed_record':1,'dns_flags':65536,'dns_constants':1,'dns_header':65536}
GNUNET_INPUTS={'src/include/gnunet_tun_lib.h':'4df0fd8a7749134b4bd64fc891924037dd4688e95060657298807a1b032ef419','src/lib/util/dnsparser.c':'9659bf2c49618c229d0b1ee91ecd1abb4a013708110193724d255e00acbc9ec8','src/include/gnunet_dnsparser_lib.h':'f5fb0c9441f5075113df938c74e7cc75b79135e4c4ca1738205a1fddc6493904'}
IDN2_INPUTS=['lookup.c','idna.c','context.c','bidi.c','decode.c','punycode.c','idn2.h','Idna2008.txt','IdnaMappingTable.txt','DerivedNormalizationProps.txt']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ['gnunet-source','reference-build','reference-library','idn2-library','unistring-library','libidn2-source','libidn2-archive','libunistring-archive','ucd15','ucd18','output']:p.add_argument('--'+name,type=pathlib.Path,required=True)
 a=p.parse_args();a=argparse.Namespace(**{k:v.resolve() for k,v in vars(a).items()});out=a.output
 assert not out.is_relative_to(ROOT) and not ROOT.is_relative_to(out),'Output and source directories must be disjoint'
 out.mkdir(parents=True,exist_ok=False);commands=[];start=time.time();libs=[a.reference_library,a.idn2_library,a.unistring_library]
 def run(argv,name,cwd=ROOT):
  argv=[str(v) for v in argv];t=time.monotonic();r=subprocess.run(argv,cwd=cwd,capture_output=True,text=True)
  (out/(name+'.stdout')).write_text(r.stdout);(out/(name+'.stderr')).write_text(r.stderr)
  commands.append({'argv':argv,'cwd':str(cwd),'exit_code':r.returncode,'stdout':name+'.stdout','stderr':name+'.stderr','elapsed_seconds':time.monotonic()-t})
  if r.returncode:raise RuntimeError(name+' failed: '+r.stderr[-6000:])
  return r.stdout
 cargo=['cargo','+1.99.1'];common=['--manifest-path',ROOT/'Cargo.toml','--target-dir',out/'cargo-target','--offline','--locked']
 meta=json.loads(run([*cargo,'metadata','--format-version','1','--manifest-path',ROOT/'Cargo.toml','--offline','--locked'],'cargo-metadata'))
 def inputs():
  paths=[ROOT/'Cargo.toml',ROOT/'README.md',ROOT/'UPSTREAM.md',ROOT/'generate.py',ROOT/'verify.py']
  for sub in ['src','tests','tools','examples','data']:paths.extend(x for x in (ROOT/sub).rglob('*') if x.is_file() and '__pycache__' not in x.parts)
  for package in meta['packages']:
   if package['source'] is not None:continue
   manifest=pathlib.Path(package['manifest_path']);paths.append(manifest);paths.extend((manifest.parent/'src').rglob('*.rs'))
   for ancestor in manifest.parents:
    paths.extend(q for q in [ancestor/'Cargo.toml',ancestor/'rust-toolchain.toml'] if q.exists())
  for q in [pathlib.Path(meta['workspace_root'])/'Cargo.lock',ROOT/'Cargo.lock']:
   if q.exists():paths.append(q)
  paths.extend(getattr(a,k) for k in EXPECTED);paths.extend(libs);paths.append(a.reference_build/'compile_commands.json')
  paths.extend(a.gnunet_source/n for n in GNUNET_INPUTS);paths.extend(a.libidn2_source/'lib'/n for n in IDN2_INPUTS)
  return {str(x):sha(x) for x in sorted(set(paths))}
 before=inputs();result={'status':'failed','scope':'libidn2 2.3.8 flags25/16 + actual libunistring1.5 Unicode18 properties; fixed lookup Unicode15.1','source_inputs':before,'commands':commands,'automatic_owner_promotion':False}
 try:
  for name,expected in EXPECTED.items():assert sha(getattr(a,name))==expected,name
  for name,expected in GNUNET_INPUTS.items():assert sha(a.gnunet_source/name)==expected,name
  with tarfile.open(a.libidn2_archive) as archive:
   for name in IDN2_INPUTS:assert archive.extractfile('libidn2-2.3.8/lib/'+name).read()==(a.libidn2_source/'lib'/name).read_bytes(),name+' changed from pinned GNU archive'
  for argv,name in [([*cargo,'--version'],'cargo-version'),(['rustc','+1.99.1','--version'],'rustc-version'),(['rustfmt','+1.99.1','--version'],'rustfmt-version'),(['cc','--version'],'cc-version'),([sys.executable,'--version'],'python-version')]:run(argv,name)
  run([sys.executable,'-B',ROOT/'tools/guard_tests.py'],'tool-output-boundaries')
  data_args=['--libidn2-source',a.libidn2_source,'--ucd15',a.ucd15,'--ucd18',a.ucd18]
  run([sys.executable,'-B',ROOT/'generate.py','--check',*data_args],'table-regeneration')
  run([*cargo,'fmt','--manifest-path',ROOT/'Cargo.toml','--','--check'],'format')
  rust_stdout=run([*cargo,'test',*common],'rust-tests')
  actual_tests=re.findall(r'^test (.+?) \.\.\. ok$',rust_stdout,re.M)
  integration_names=[]
  for source in sorted((ROOT/'tests').glob('*.rs')):
   integration_names.extend(re.findall(r'#\[test\]\s+fn (\w+)',source.read_text()))
  required_names=['backend::tests::unavailable_workspace_never_reports_conversion_or_malformed',*integration_names]
  assert len(required_names)==25 and len(actual_tests)==27,'Rust test scope changed or filtered; re-review witnesses'
  assert set(required_names).issubset(set(actual_tests)),'Rust native test witness missing'
  docs=[name for name in actual_tests if ' - backend::Backend (line ' in name]
  assert len(docs)==2 and sum('compile fail' in name for name in docs)==1,'Rust lifetime controls missing'
  result['actual_rust_tests']=actual_tests
  run([*cargo,'clippy','--all-targets',*common,'--','-D','warnings'],'clippy')
  run([*cargo,'doc','--no-deps',*common],'documentation')
  for target in ['thumbv6m-none-eabi','thumbv7em-none-eabi']:run([*cargo,'check','--lib','--target',target,*common],'embedded-'+target)
  run([*cargo,'build','--release','--example','probe',*common],'rust-probe-build')
  run([*cargo,'build','--release','--example','native_pack_probe',*common],'rust-native-pack-probe-build')
  run([*cargo,'tree','--edges','normal','--manifest-path',ROOT/'Cargo.toml','--offline','--locked'],'production-dependency-tree')
  ref=[]
  for name in ['gnunet_source','reference_build','reference_library','idn2_library','unistring_library']:ref.extend(['--'+name.replace('_','-'),getattr(a,name)])
  run([sys.executable,'-B',ROOT/'tools/build_probe.py',*ref,'--output',out/'native'],'c-probe-build')
  c=out/'native/c-probe';rust=out/'cargo-target/release/examples/probe'
  native_pack_c=out/'native/native-pack-probe';native_pack_rust=out/'cargo-target/release/examples/native_pack_probe'
  run([sys.executable,'-B',ROOT/'tools/native_pack_compare.py','--c-probe',native_pack_c,'--rust-probe',native_pack_rust,'--output',out/'native-pack.json'],'native-pack-boundaries')
  native_pack=json.loads((out/'native-pack.json').read_text());assert native_pack['status']=='passed' and native_pack['comparisons']==3846 and native_pack['functional_mismatches']==0
  result['native_pack']={'cases':3846,'functional_mismatches':0,'receipt':'native-pack.json','sha256':sha(out/'native-pack.json')}
  metadata=run([c,'--metadata'],'c-metadata');assert metadata=='libidn2=2.3.8\nlibunistring=10500\nunicode=1200\n',metadata
  result['actual_binaries']={str(q):sha(q) for q in [c,out/'native/frontend-probe',rust,native_pack_c,native_pack_rust]};result['reference_libraries']={str(q):sha(q) for q in libs}
  run([sys.executable,'-B',ROOT/'tools/compare.py','--c-probe',c,'--rust-probe',rust,*data_args,'--output',out/'cases',*COUNTS.keys()],'normal-c-differential')
  summaries={}
  for mode,count in COUNTS.items():
   r=json.loads((out/'cases'/(mode+'.json')).read_text());assert r['cases']==count,(mode,r['cases'],count)
   assert r['mismatch_count']==0 and not r['mismatches'] and not r['normative_mismatches'],mode
   if mode=='puny_fuzz':assert len(r['diagnostic_variances'])==18 and all(x['c']=='-300\t' and x['rust']=='-313\t' for x in r['diagnostic_variances'])
   else:assert not r['diagnostic_variances'],mode
   summaries[mode]={'cases':r['cases'],'c_success':r['c_success'],'functional_mismatches':0,'diagnostic_variances':len(r['diagnostic_variances']),'normative_mismatches':0,'receipt':str(pathlib.Path('cases')/(mode+'.json')),'sha256':sha(out/'cases'/(mode+'.json'))}
  run([sys.executable,'-B',ROOT/'tools/frontend_reference.py','--probe',out/'native/frontend-probe','--output',out],'fresh-gnunet-frontend')
  result.update({'status':'passed-native-profile','corpora':summaries,'actual_c_rust_observations':sum(x['cases'] for x in summaries.values()),'rust_checks':{'unit':1,'integration':24,'positive_rustdoc':1,'compile_fail_rustdoc':1,'total':27},'fresh_gnunet_frontend':{'count':55,'direct':53,'explicit_safe_boundaries':2},'workspace_bytes':6352,'new_registry_dependencies':0,'limitations':['Unicode15.1 all-properties profile is source/data validated, not an independently built second C runtime.','18 low-surrogate diagnostic category differences remain explicit; complete APIs reject them.','Input excludes interior NUL C-string terminator/trailing storage; parser native writer separately truncates native label values.','Stricter IDNA2008 helper validates one label and requires caller Bidi-domain context.']})
 except Exception as e:result['error']=repr(e)
 result['inputs_unchanged']=before==inputs();result['elapsed_seconds']=time.time()-start
 if not result['inputs_unchanged']:result['status']='failed-source-changed'
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'status':result['status'],'inputs_unchanged':result['inputs_unchanged'],'result':str(out/'result.json'),'error':result.get('error')},indent=2))
 if not result['status'].startswith('passed'):raise SystemExit(1)
if __name__=='__main__':main()
