#!/usr/bin/env python3
"""Fresh source-bound normal-library differential; never executes a C daemon."""
import argparse,hashlib,json,os,shlex,shutil,subprocess,sys,re,importlib.util
from pathlib import Path
sys.dont_write_bytecode=True
from corpus import generate,openings,summary
from udp_source import generate as generate_udp_source
PIN='346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
TOOLCHAIN='1.99.1'
PACKAGE=Path(__file__).resolve().parents[1]

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(p,obj):p.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n')
def contained(out,roots):
 for root in roots:
  if out.is_relative_to(root) or root.is_relative_to(out):raise ValueError(f'output overlaps input: {root}')
def files(root):return sorted(p for p in root.rglob('*') if p.is_file() and not any(s in {'target','__pycache__','.git'} for s in p.relative_to(root).parts))
def snapshot(paths):return {str(p):sha(p) for p in sorted(set(paths))}
def command(argv,cwd,env,base,input=None):
 proc=subprocess.run([str(x) for x in argv],cwd=cwd,env=env,input=input,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 Path(str(base)+'.stdout').write_text(proc.stdout);Path(str(base)+'.stderr').write_text(proc.stderr)
 dump(Path(str(base)+'.json'),{'argv':[str(x) for x in argv],'cwd':str(cwd),'status':proc.returncode})
 if proc.returncode:raise RuntimeError(f'command failed {argv[0]} ({proc.returncode}): {base}.stderr')
 return proc.stdout

def flags(entry):
 args=entry.get('arguments') or shlex.split(entry['command']);out=[];skip=False
 for v in args[1:]:
  if skip:skip=False;continue
  if v in ['-o','-MF','-MT','-MQ']:skip=True;continue
  if v in ['-c','-MD','-MMD'] or v==entry['file'] or v.endswith('/crypto_ecc.c') or v.startswith('-O'):continue
  out.append(v)
 return args[0],out

def registry(lock):
 result={}
 for block in lock.read_text().split('[[package]]')[1:]:
  fields={k:json.loads(v) for k,v in re.findall(r'^(name|version|source|checksum) = ("[^"\n]*")$',block,re.M)}
  if fields.get('source','').startswith('registry+'):
   assert all(k in fields for k in ['name','version','source','checksum'])
   result[(fields['name'],fields['version'])]=(fields['source'],fields['checksum'])
 return result

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 for name in ['repository','source','reference','deps-prefix','output']:ap.add_argument('--'+name,type=Path,required=True)
 a=ap.parse_args();repo=a.repository.resolve();source=a.source.resolve();ref=a.reference.resolve();deps=a.deps_prefix.resolve();out=a.output.resolve()
 receipt=json.loads(ref.read_text());build=Path(receipt['build']).resolve();prefix=Path(receipt['prefix']).resolve()
 contained(out,[repo,source,PACKAGE,build,prefix,deps,ref.parent]);out.mkdir(parents=True,exist_ok=False)
 env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1';env.update(receipt['runtime_environment']);env['CARGO_TARGET_DIR']=str(out/'target')
 try:
  assert receipt['source_unchanged'] and receipt['status']=='passed' and Path(receipt['source']).resolve()==source and receipt['upstream']['revision']==PIN
  head=command(['git','rev-parse','HEAD'],source,env,out/'git-head').strip();assert head==PIN
  assert not command(['git','status','--porcelain','--untracked-files=no'],source,env,out/'git-clean').strip()
  helper=repo/'tools/reference/build_reference.py'
  spec=importlib.util.spec_from_file_location('session_reference_inputs',helper);reference_inputs=importlib.util.module_from_spec(spec);spec.loader.exec_module(reference_inputs)
  assert receipt['kind']=='unmodified-official-c-reference-build','wrong normal C reference profile'
  assert reference_inputs.source_state(source)==receipt['upstream'],'full normal source profile differs'
  util=next(Path(x['path']).resolve() for x in receipt['libraries'] if 'libgnunetutil' in x['path'] and not x['symlink'])
  assert sha(util)==next(x['sha256'] for x in receipt['libraries'] if Path(x['path']).resolve()==util and not x['symlink'])
  sodium=next(p.resolve() for p in (deps/'lib').glob('libsodium.*') if p.suffix in {'.so','.dylib'})
  generated_config=receipt['generated_config'];assert sha(Path(generated_config['path']))==generated_config['sha256']
  assert Path(generated_config['path']).resolve()==(build/'gnunet_private_config.h').resolve(),'wrong generated configuration path'
  for item in receipt['libraries']:assert sha(Path(item['path']))==item['sha256'],'declared normal library changed'
  for key in ['LD_PRELOAD','DYLD_INSERT_LIBRARIES','DYLD_FORCE_FLAT_NAMESPACE']:env.pop(key,None)
  linked={util,sodium};pending=list(linked);linkage=[]
  while pending:
   library=pending.pop()
   if sys.platform=='darwin':argv=['otool','-L',library]
   elif sys.platform.startswith('linux'):argv=['ldd',library]
   else:raise RuntimeError('normal-library linkage auditing requires otool(macOS) or ldd(Linux)')
   listed=command(argv,build,env,out/('linkage-'+str(len(linkage))))
   linkage.append({'path':str(library),'listing':listed})
   for line in listed.splitlines()[1:] if sys.platform=='darwin' else listed.splitlines():
    entry=line.strip().split(' (',1)[0].split('=>')[-1].strip()
    dependency=Path(entry)
    if dependency.is_absolute() and dependency.is_file():
     dependency=dependency.resolve()
     if dependency not in linked:linked.add(dependency);pending.append(dependency)
  dump(out/'normal-linkage.json',{'libraries':{str(p):sha(p) for p in sorted(linked)},'listings':linkage,'unhashable_os_shared_cache_paths_remain_in_listings':True})
  command(['git','ls-files'],source,env,out/'git-files')
  def discover_paths():
   cpaths=[source/line for line in subprocess.check_output(['git','ls-files'],cwd=source,text=True).splitlines() if (source/line).is_file()]
   paths=files(PACKAGE)+cpaths+list(linked)+[helper,ref,build/'gnunet_private_config.h',build/'src/include/gnunet_config.h',build/'compile_commands.json',repo/'Cargo.toml',repo/'Cargo.lock',repo/'rust-toolchain.toml',repo/'spec/gnunet/api/declarations.json']
   paths += [Path(item['path']) for item in receipt['libraries']]
   for name in ['gnunet-types','gnunet-wire','gnunet-crypto','gnunet-gnscrypto','gnunet-hello']:paths+=files(repo/'crates'/name)
   return paths
  paths=discover_paths()
  before=snapshot(paths);dump(out/'inputs-before.json',before)
  udp_component=generate_udp_source(source,out/'udp-source')
  rust=out/'rust';rust.mkdir();
  for name in ['src','examples','tests']:shutil.copytree(PACKAGE/name,rust/name)
  (rust/'Cargo.toml').write_text((PACKAGE/'Cargo.toml.in').read_text().replace('@REPOSITORY@',str(repo)))
  shutil.copy2(repo/'Cargo.lock',rust/'Cargo.lock')
  cargo=['cargo','+'+TOOLCHAIN]
  metadata=json.loads(command(cargo+['metadata','--manifest-path',rust/'Cargo.toml','--offline','--format-version','1'],repo,env,out/'metadata'))
  actual_meta=json.loads(command(cargo+['metadata','--manifest-path',PACKAGE/'Cargo.toml','--offline','--locked','--format-version','1','--no-deps'],repo,env,out/'production-metadata'))
  actual_package=next(p for p in actual_meta['packages'] if Path(p['manifest_path']).resolve()==(PACKAGE/'Cargo.toml').resolve())
  generated_package=next(p for p in metadata['packages'] if Path(p['manifest_path']).resolve()==(rust/'Cargo.toml').resolve())
  def contract(p):
   keys=['name','req','source','kind','rename','optional','uses_default_features','target','path']
   return sorted([{**{k:d.get(k) for k in keys},'features':sorted(d['features'])} for d in p['dependencies']],key=lambda d:json.dumps(d,sort_keys=True))
  assert contract(actual_package)==contract(generated_package),'standalone template differs from production dependencies/features'
  assert actual_package['features']==generated_package['features'],'standalone template differs from production declared features'
  packages={p['id']:p for p in metadata['packages']};nodes={n['id']:n for n in metadata['resolve']['nodes']}
  pending=[metadata['resolve']['root']];normal_graph={}
  while pending:
   item=pending.pop()
   if item in normal_graph:continue
   pkg=packages[item];features=nodes[item]['features'];assert not {'alloc','std'}&set(features),(pkg['name'],features)
   normal_graph[item]={'name':pkg['name'],'features':features}
   for dep in nodes[item]['deps']:
    if not any(k['kind'] is None for k in dep['dep_kinds']):continue
    if any('proc-macro' in target['kind'] for target in packages[dep['pkg']]['targets']):continue
    pending.append(dep['pkg'])
  dump(out/'normal-noalloc-graph.json',normal_graph)
  # The single proposed dependency is explicit. No arbitrary cached update is accepted.
  baseline=registry(repo/'Cargo.lock');actual=registry(rust/'Cargo.lock');new={}
  for key,value in actual.items():
   if key in baseline:assert baseline[key]==value,(key,value,baseline[key])
   else:
    assert key==('chacha20','0.10.2'),('unapproved new registry package',key)
    expected=json.loads((PACKAGE/'reference/dependency.json').read_text());assert value==(expected['source'],expected['checksum']);new['/'.join(key)]=value
  dump(out/'new-dependencies.json',new)
  generated_before=snapshot(files(rust));dump(out/'generated-before.json',generated_before)
  command(cargo+['fmt','--manifest-path',rust/'Cargo.toml','--all','--','--check'],repo,env,out/'fmt')
  tests=command(cargo+['test','--manifest-path',rust/'Cargo.toml','--offline','--locked'],repo,env,out/'unit-doc')
  assert 'test result: ok. 24 passed; 0 failed; 3 ignored;' in tests and 'test result: ok. 2 passed; 0 failed; 0 ignored;' in tests
  public_names=re.findall(r'#\[test\]\s*fn\s+(\w+)',(PACKAGE/'tests/independent.rs').read_text());assert len(public_names)==7 and len(set(public_names))==7
  assert 'test result: ok. 7 passed; 0 failed; 0 ignored;' in tests and all('test '+name+' ... ok' in tests for name in public_names),'independent public API witnesses missing'
  command(cargo+['clippy','--manifest-path',rust/'Cargo.toml','--all-targets','--offline','--locked'],repo,env,out/'clippy')
  command(cargo+['doc','--manifest-path',rust/'Cargo.toml','--no-deps','--offline','--locked'],repo,env,out/'doc')
  command([sys.executable,'-B',PACKAGE/'tools/ownership.py','--manifest',rust/'Cargo.toml','--target-dir',out/'target','--output',out/'ownership','--toolchain',TOOLCHAIN],repo,env,out/'ownership-run')
  ownership=json.loads((out/'ownership/result.json').read_text());assert ownership['status']=='passed' and ownership['negative_case_count']==14 and ownership['positive_control']['passed'] and ownership['inputs_unchanged']
  points=command(cargo+['run','--manifest-path',rust/'Cargo.toml','--example','public_points','--offline','--locked'],repo,env,out/'points').splitlines();assert len(points)==256
  base=generate(points)
  commands=json.loads((build/'compile_commands.json').read_text());entry=next(x for x in commands if x['file'].endswith('/crypto_ecc.c'))
  cc,options=flags(entry);ccpath=shutil.which(cc);assert ccpath
  dump(out/'compiler.json',{'path':ccpath,'sha256':sha(Path(ccpath).resolve()),'version':command([cc,'--version'],build,env,out/'compiler-version')})
  profile_results=[]
  for level in ['0','2']:
   dest=out/('c-O'+level);dest.mkdir();binary=dest/'probe'
   command([cc]+options+['-I'+str(out/'udp-source'),'-O'+level,PACKAGE/'reference/probe.c','-L'+str(util.parent),'-Wl,-rpath,'+str(util.parent),'-L'+str(deps/'lib'),'-lgnunetutil','-lsodium','-o',binary],entry['directory'],env,dest/'build')
   meta=command([binary],build,env,dest/'meta','META\n').strip();assert meta.split()[2:]==['32','32','24','64','64'],meta
   pre=command([binary],build,env,dest/'base','\n'.join(base)+'\n').splitlines();assert len(pre)==len(base)
   rows=base+openings(base,pre);casefile=dest/'cases.txt';casefile.write_text('\n'.join(rows)+'\n')
   normal=command([binary],build,env,dest/'normal',casefile.read_text()).splitlines();assert len(normal)==len(rows)
   results=dest/'normal.stdout';accept=dest/'rust-accept.txt';renv=env|{'GNUNET_SESSION_CRYPTO_CASES':str(casefile),'GNUNET_SESSION_CRYPTO_RESULTS':str(results),'GNUNET_SESSION_CRYPTO_ACCEPT':str(accept)}
   tested=command(cargo+['test','--manifest-path',rust/'Cargo.toml','--offline','--locked','normal_c_library_vectors','--','--ignored','--nocapture'],repo,renv,dest/'rust-compare')
   assert 'test oracle_tests::normal_c_library_vectors ... ok' in tested and 'test result: ok. 1 passed; 0 failed; 0 ignored;' in tested
   accepted=command([binary],build,env,dest/'c-accept-rust',accept.read_text());assert accepted==accept.with_suffix('.expected').read_text()
   deterministic=[line for line in normal if not line.startswith('EDKEM ')]
   if profile_results:assert deterministic==profile_results[0]['deterministic_rows']
   profile_results.append({'profile':'helper-O'+level,'cases':len(rows),'operations':summary(rows),'actual_rust_outputs_accepted_by_c':len(accepted.splitlines()),'meta':meta,'helper_sha256':sha(binary),'deterministic_rows':deterministic})
  for row in profile_results:row.pop('deterministic_rows')
  # Each negative control must execute the actual Rust comparator and fail
  # its named test, rather than merely fail compilation or select zero tests.
  control=out/'negative-controls';control.mkdir();source_cases=(out/'c-O0/cases.txt').read_text();source_results=(out/'c-O0/normal.stdout').read_text().splitlines()
  controls=[]
  for label,op in [('dh-byte','DH'),('aead-tag','AEAD'),('cake-secret','CAKE'),('missing-result',None)]:
   altered=source_results.copy()
   if op is None:altered.pop()
   else:
    index=next(i for i,line in enumerate(altered) if line.startswith(op+' 1 '));parts=altered[index].split();value=parts[-1];parts[-1]=('0' if value[0]!='0' else '1')+value[1:];altered[index]=' '.join(parts)
   casepath=control/(label+'.cases');resultpath=control/(label+'.expected');casepath.write_text(source_cases);resultpath.write_text('\n'.join(altered)+'\n')
   cenv=env|{'GNUNET_SESSION_CRYPTO_CASES':str(casepath),'GNUNET_SESSION_CRYPTO_RESULTS':str(resultpath)}
   argv=cargo+['test','--manifest-path',str(rust/'Cargo.toml'),'--offline','--locked','normal_c_library_vectors','--','--ignored']
   failed=subprocess.run(argv,cwd=repo,env=cenv,text=True,capture_output=True)
   (control/(label+'.stdout')).write_text(failed.stdout);(control/(label+'.stderr')).write_text(failed.stderr)
   assert failed.returncode!=0 and 'test oracle_tests::normal_c_library_vectors ... FAILED' in failed.stdout and 'test result: FAILED. 0 passed; 1 failed;' in failed.stdout,(label,failed.returncode)
   controls.append({'name':label,'exit_code':failed.returncode,'actual_comparator_rejected':True})
  dump(control/'result.json',controls)

  # Real no_std/noalloc consumers; no workspace files or lock are rewritten.
  embedded=out/'embedded';(embedded/'src').mkdir(parents=True)
  (embedded/'Cargo.toml').write_text('[package]\nname="gnunet-session-embedded-witness"\nversion="0.1.0"\nedition="2024"\n[workspace]\n[dependencies]\ngnunet-session-crypto={path='+json.dumps(str(rust))+'}\n')
  (embedded/'src/lib.rs').write_text('#![no_std]\n#![forbid(unsafe_code)]\npub fn key(input:[u8;32])->[u8;32]{*gnunet_session_crypto::exchange::EcdheSecret::from_bytes(input).public_key().as_bytes()}\n')
  shutil.copy2(rust/'Cargo.lock',embedded/'Cargo.lock')
  command(cargo+['metadata','--manifest-path',embedded/'Cargo.toml','--offline','--format-version','1'],repo,env,out/'embedded-metadata')
  for target in ['thumbv6m-none-eabi','thumbv7em-none-eabi']:command(cargo+['check','--manifest-path',embedded/'Cargo.toml','--target',target,'--offline','--locked'],repo,env,out/('embedded-'+target))
  command([sys.executable,PACKAGE/'tools/inventory.py','--repository',repo,'--source',source,'--output',out/'inventory'],repo,env,out/'inventory-run')
  after=snapshot(discover_paths());dump(out/'inputs-after.json',after);assert before==after
  assert reference_inputs.source_state(source)==receipt['upstream'],'full normal source profile changed'
  for item in receipt['libraries']:assert sha(Path(item['path']))==item['sha256'],'normal library changed'
  generated_after=snapshot(files(rust));dump(out/'generated-after.json',generated_after);assert generated_before==generated_after
  assert {str(p) for p in files(PACKAGE)}=={str(p) for p in paths if p.is_relative_to(PACKAGE)}
  result={'status':'passed','scope':'normal unchanged utility-library primitives and exact public KDF compositions; no C CORE/TRANSPORT daemon or complete handshake execution','revision':head,'toolchain':TOOLCHAIN,'inputs_unchanged':True,'generated_rust_inputs_unchanged':True,'profiles':profile_results,'new_registry_packages':new,'normal_util':{'path':str(util),'sha256':sha(util)},'normal_sodium':{'path':str(sodium),'sha256':sha(sodium)},'normal_linked_libraries':{str(p):sha(p) for p in sorted(linked)},'negative_controls':controls,'ownership':{'negative_cases':14,'positive_controls':1,'receipt':'ownership/result.json','sha256':sha(out/'ownership/result.json')},'normal_dependency_graph_has_no_std_or_alloc_features':True,'production_template_dependencies_and_features_match':True,'udp_source_component':udp_component,'rust_tests':{'unit':24,'independent_public_api':7,'compile_fail_doc':2,'external_oracle_per_helper_profile':1},'embedded':['thumbv6m-none-eabi','thumbv7em-none-eabi'],'inventory_only':True,'remaining':['Elligator0x0022','remaining Elligator HPKE and key-family APIs','full UDP identity/replay/rekey owner','CORE state machine and framing','TCP packet/frame auth binding','remaining public function gaps and partial foundations recorded in inventory']}
  dump(out/'result.json',result);print(json.dumps({'status':'passed','profiles':profile_results,'result':str(out/'result.json')}))
 except Exception as exc:
  dump(out/'failure.json',{'status':'failed','error':repr(exc)});raise
if __name__=='__main__':main()
