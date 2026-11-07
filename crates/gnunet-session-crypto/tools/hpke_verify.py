#!/usr/bin/env python3
"""Fresh normal-C HPKE context differential; never executes any network service."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
sys.dont_write_bytecode=True
from hpke_corpus import base, failures, summary
PIN='346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
BASE=Path(__file__).resolve().parents[1]
PACKAGE=BASE
TEST='hpke::tests::normal_c_public_contexts_and_rust_ciphertexts_accepted_by_c'

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def dump(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def files(root):return sorted(path for path in root.rglob('*') if path.is_file() and not any(part in {'target','.git','__pycache__'} for part in path.relative_to(root).parts))
def snapshot(paths):return {str(path):sha(path) for path in sorted(set(paths))}
def command(argv,cwd,env,output,name,input=None,expected=0):
    proc=subprocess.run([str(x) for x in argv],cwd=str(cwd),env=env,input=input,text=True,capture_output=True,timeout=180)
    (output/(name+'.stdout')).write_text(proc.stdout);(output/(name+'.stderr')).write_text(proc.stderr)
    dump(output/(name+'.json'),{'argv':[str(x) for x in argv],'cwd':str(cwd),'exit_code':proc.returncode,'expected_exit_code':expected,'stdout_sha256':sha(output/(name+'.stdout')),'stderr_sha256':sha(output/(name+'.stderr'))})
    if proc.returncode!=expected:raise ValueError(name+' failed; see captured logs')
    return proc.stdout

def flags(entry):
    args=entry.get('arguments') or shlex.split(entry['command']);out=[];skip=False
    for value in args[1:]:
        if skip:skip=False;continue
        if value in ('-o','-MF','-MT','-MQ'):skip=True;continue
        if value in ('-c','-MD','-MMD') or value==entry['file'] or value.endswith('/crypto_hpke.c') or value.startswith('-O'):continue
        out.append(value)
    return args[0],out

def noalloc(metadata,manifest):
    packages={p['id']:p for p in metadata['packages']};nodes={n['id']:n for n in metadata['resolve']['nodes']};root=next(p['id'] for p in metadata['packages'] if Path(p['manifest_path']).resolve()==manifest)
    pending=[root];observed={}
    while pending:
        ident=pending.pop()
        if ident in observed:continue
        package=packages[ident];features=nodes[ident]['features']
        if {'alloc','std'}&set(features):raise ValueError('normal dependency graph enabled allocation/std: '+package['name'])
        observed[ident]={'name':package['name'],'features':features}
        for dep in nodes[ident]['deps']:
            if not any(item['kind'] is None for item in dep['dep_kinds']):continue
            if any('proc-macro' in target['kind'] for target in packages[dep['pkg']]['targets']):continue
            pending.append(dep['pkg'])
    return observed

def context_ui(args,repo,env,out,ownership):
    spec=importlib.util.spec_from_file_location('hpke_ownership_helpers',BASE/'tools/ownership.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    selected=ownership['selected_rlib'];rlib=Path(selected['path']);before=sha(rlib)
    common=['rustup','run',args.toolchain,'rustc','--edition=2024','--crate-type=lib','--emit=metadata','--error-format=json','--target',ownership['host_target'],'--extern','gnunet_session_crypto='+str(rlib)]
    for directory in selected['dependency_search_paths']:common+=['-L','dependency='+directory]
    cases=[]
    sources={
      'Context_Clone':('E0277','fn bound<T:Clone>(){}\npub fn bad(){bound::<gnunet_session_crypto::hpke::Context>();}\n'),
      'Context_Debug':('E0277','fn bound<T:core::fmt::Debug>(){}\npub fn bad(){bound::<gnunet_session_crypto::hpke::Context>();}\n'),
      'exporter_lifetime':('E0515',"pub fn bad<'a>(r:&gnunet_session_crypto::exchange::EcdheSecret,e:gnunet_session_crypto::exchange::EcdhePublic)->Option<&'a gnunet_session_crypto::Prk>{let ctx=gnunet_session_crypto::hpke::receiver_setup(e,r,b\"info\").ok()?;Some(ctx.exporter_secret())}\n"),
      'clear_moves_secret':('E0382','pub fn bad(){let key=gnunet_session_crypto::exchange::EcdheSecret::from_bytes([7;32]);key.clear();let _public=key.public_key();}\n')}
    for name,(code,source) in sources.items():
        path=out/(name+'.rs');path.write_text(source)
        command(common+['--crate-name','ui_'+name,'-o',out/(name+'.rmeta'),path],repo,env,out,name,expected=1)
        diagnostics=[json.loads(line) for line in (out/(name+'.stderr')).read_text().splitlines() if line.strip()];coded=[d for d in diagnostics if d.get('level')=='error' and d.get('code')]
        if len(coded)!=1 or coded[0]['code']['code']!=code:raise ValueError('wrong UI diagnostic for '+name)
        if not any(span['is_primary'] and Path(span['file_name']).resolve()==path for span in coded[0]['spans']):raise ValueError('unrelated UI failure')
        cases.append({'name':name,'diagnostic':code,'source_sha256':sha(path),'passed':True})
    positive=out/'positive.rs';positive.write_text('pub fn good(r:&gnunet_session_crypto::exchange::EcdheSecret,e:gnunet_session_crypto::exchange::EcdhePublic){if let Ok(ctx)=gnunet_session_crypto::hpke::receiver_setup(e,r,b"info"){let mut bytes=[0;32];let _result=ctx.exporter_secret().expand(&[b"caller context"],&mut bytes);let _sequence=ctx.sequence();}}\n')
    command(common+['--crate-name','ui_positive','-o',out/'positive.rmeta',positive],repo,env,out,'positive')
    if not (out/'positive.rmeta').stat().st_size:raise ValueError('empty positive UI artifact')
    if before!=sha(rlib):raise ValueError('rlib changed during context UI checks')
    dump(out/'result.json',{'status':'passed','cases':cases,'positive_control':True,'rlib_sha256':before})

def inventory(source,repo):
    path=BASE/'hpke-inventory.json';document=json.loads(path.read_text())
    csource=source/'src/lib/util/crypto_hpke.c';header=source/'src/include/gnunet_crypto_lib.h'
    if document['revision']!=PIN or sha(csource)!=document['source_sha256'] or sha(header)!=document['header_sha256']:raise ValueError('HPKE inventory source/header profile changed')
    public=document['public_functions'];internal=document['internal_functions'];text=csource.read_text();lines=text.splitlines()
    definitions=set(re.findall(r'^(GNUNET_CRYPTO_[A-Za-z0-9_]+)\s*\(',text,re.M))
    internal_names={row['name'] for row in internal}
    if len(public)!=28 or document['public_function_count']!=28 or len({row['name'] for row in public})!=28 or definitions-internal_names!={row['name'] for row in public}:raise ValueError('HPKE public function inventory changed or shrank')
    declarations_path=repo/'spec/gnunet/api/declarations.json';declarations={row['id']:row for row in json.loads(declarations_path.read_text())['declarations']}
    for row in public:
        declaration=declarations.get(row['header_id'])
        if not declaration or declaration['name']!=row['name'] or declaration['type']!=row['signature'] or row['verification'] is not None or not lines[row['source_line']-1].strip().startswith(row['name']):raise ValueError('HPKE function mapping differs from source/compiler inventory: '+row['name'])
    return {'public_functions':28,'source_derived_internal_functions':len(internal),'all_function_verification_null':True},declarations_path

def run(args,out):
    repo=args.repository.resolve();source=args.source.resolve();ref=args.reference.resolve();deps=args.deps_prefix.resolve()
    receipt=json.loads(ref.read_text());build=Path(receipt['build']).resolve();prefix=Path(receipt['prefix']).resolve()
    if not receipt['source_unchanged'] or receipt['status']!='passed' or Path(receipt['source']).resolve()!=source or receipt['upstream']['revision']!=PIN:raise ValueError('normal reference receipt mismatch')
    env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1';env.update(receipt['runtime_environment']);env['CARGO_TARGET_DIR']=str(out/'target')
    for name in ('LD_PRELOAD','DYLD_INSERT_LIBRARIES','DYLD_FORCE_FLAT_NAMESPACE'):env.pop(name,None)
    cargo=['rustup','run',args.toolchain,'cargo']
    if command(['git','rev-parse','HEAD'],source,env,out,'git-head').strip()!=PIN:raise ValueError('wrong upstream revision')
    if command(['git','status','--porcelain','--untracked-files=no'],source,env,out,'git-clean').strip():raise ValueError('tracked C source modified')
    helper=repo/'tools/reference/build_reference.py'
    spec=importlib.util.spec_from_file_location('hpke_reference_inputs',helper);reference_inputs=importlib.util.module_from_spec(spec);spec.loader.exec_module(reference_inputs)
    if reference_inputs.source_state(source)!=receipt['upstream']:raise ValueError('normal full tracked source state differs from receipt')
    config=receipt['generated_config'];configpath=Path(config['path']).resolve()
    if configpath!=(build/'gnunet_private_config.h').resolve() or sha(configpath)!=config['sha256']:raise ValueError('normal generated configuration differs from receipt')
    if receipt['kind']!='unmodified-official-c-reference-build':raise ValueError('wrong normal library build profile')
    util=next(Path(row['path']).resolve() for row in receipt['libraries'] if 'libgnunetutil' in row['path'] and not row['symlink'])
    if sha(util)!=next(row['sha256'] for row in receipt['libraries'] if Path(row['path']).resolve()==util and not row['symlink']):raise ValueError('normal util changed')
    for item in receipt['libraries']:
        if sha(Path(item['path']))!=item['sha256']:raise ValueError('declared normal library changed')
    sodium=next(path.resolve() for path in (deps/'lib').glob('libsodium.*') if path.suffix in ('.dylib','.so'))
    linked={util,sodium};pending=list(linked);listings=[]
    while pending:
        library=pending.pop()
        if sys.platform=='darwin':argv=['otool','-L',library]
        elif sys.platform.startswith('linux'):argv=['ldd',library]
        else:raise ValueError('normal linkage inspection supports Linux/macOS')
        text=command(argv,build,env,out,'linkage-'+str(len(listings)));listings.append({'path':str(library),'listing':text})
        for line in text.splitlines()[1:] if sys.platform=='darwin' else text.splitlines():
            entry=line.strip().split(' (',1)[0].split('=>')[-1].strip();path=Path(entry)
            if path.is_absolute() and path.is_file():
                path=path.resolve()
                if path not in linked:linked.add(path);pending.append(path)
    dump(out/'normal-linkage.json',{'libraries':snapshot(linked),'listings':listings,'unhashable_os_shared_cache_paths_remain_in_listings':True})
    command(['git','ls-files'],source,env,out,'git-files')
    inventory_result,declarations_path=inventory(source,repo)
    dump(out/'inventory-review.json',inventory_result)
    def discover_paths():
        cpaths=[source/line for line in subprocess.check_output(['git','ls-files'],cwd=source,text=True).splitlines() if (source/line).is_file()]
        paths=files(PACKAGE)+files(BASE/'reference')+files(BASE/'tools')+cpaths+list(linked)+[declarations_path,helper,ref,build/'gnunet_private_config.h',build/'src/include/gnunet_config.h',build/'compile_commands.json',repo/'Cargo.toml',repo/'Cargo.lock',repo/'rust-toolchain.toml']
        paths += [Path(item['path']) for item in receipt['libraries']]
        for name in ('gnunet-types','gnunet-wire','gnunet-crypto'):paths+=files(repo/'crates'/name)
        paths += [BASE/name for name in ('hpke-inventory.json','HPKE.md','HPKE_API.md','README.md') if (BASE/name).is_file()]
        return paths
    paths=discover_paths()
    before=snapshot(paths);dump(out/'inputs-before.json',before)
    rust=out/'rust';rust.mkdir()
    for directory in ('src','tests','examples'):shutil.copytree(PACKAGE/directory,rust/directory)
    (rust/'Cargo.toml').write_text((PACKAGE/'Cargo.toml.in').read_text().replace('@REPOSITORY@',str(repo)));shutil.copy2(repo/'Cargo.lock',rust/'Cargo.lock')
    metadata=json.loads(command(cargo+['metadata','--manifest-path',rust/'Cargo.toml','--offline','--format-version','1'],repo,env,out,'metadata'))
    dump(out/'normal-noalloc-graph.json',noalloc(metadata,(rust/'Cargo.toml').resolve()))
    baseline=json.loads(command(cargo+['metadata','--manifest-path',repo/'crates/gnunet-session-crypto/Cargo.toml','--offline','--locked','--format-version','1','--no-deps'],repo,env,out,'baseline-metadata'))
    def contract(meta,manifest):
        package=next(p for p in meta['packages'] if Path(p['manifest_path']).resolve()==manifest)
        return package['features'],sorted(package['dependencies'],key=lambda d:json.dumps(d,sort_keys=True))
    if contract(metadata,(rust/'Cargo.toml').resolve())!=contract(baseline,(repo/'crates/gnunet-session-crypto/Cargo.toml').resolve()):raise ValueError('new candidate dependencies/features differ from baseline')
    def registry(lock):
        result={}
        for block in lock.read_text().split('[[package]]')[1:]:
            fields={key:json.loads(value) for key,value in re.findall(r'^(name|version|source|checksum) = ("[^"\n]*")$',block,re.M)}
            if fields.get('source','').startswith('registry+'):
                result[(fields['name'],fields['version'])]=(fields['source'],fields['checksum'])
        return result
    baseline_registry=registry(repo/'Cargo.lock');candidate_registry=registry(rust/'Cargo.lock')
    if any(key not in baseline_registry or baseline_registry[key]!=value for key,value in candidate_registry.items()):raise ValueError('new or changed registry package')
    dump(out/'registry-contract.json',{'new_registry_packages':0,'candidate_registry_package_count':len(candidate_registry)})
    generated_before=snapshot(files(rust));dump(out/'generated-before.json',generated_before)
    command(cargo+['fmt','--manifest-path',rust/'Cargo.toml','--all','--','--check'],repo,env,out,'fmt')
    tested=command(cargo+['test','--manifest-path',rust/'Cargo.toml','--offline','--locked'],repo,env,out,'unit-doc')
    if 'test result: ok. 24 passed; 0 failed; 3 ignored;' not in tested or 'test result: ok. 7 passed; 0 failed; 0 ignored;' not in tested:raise ValueError('actual unit/public API test counts differ')
    names=re.findall(r'#\[test\]\s*fn\s+(\w+)',(PACKAGE/'src/hpke/tests.rs').read_text())
    if len(names)!=8 or any('test hpke::tests::'+name+' ... ok' not in tested for name in names):raise ValueError('new context test omitted')
    command(cargo+['clippy','--manifest-path',rust/'Cargo.toml','--all-targets','--offline','--locked'],repo,env,out,'clippy')
    command(cargo+['doc','--manifest-path',rust/'Cargo.toml','--no-deps','--offline','--locked'],repo,env,out,'doc')
    command(cargo+['check','--manifest-path',rust/'Cargo.toml','--lib','--target','thumbv6m-none-eabi','--offline','--locked'],repo,env,out,'embedded-thumbv6m')
    command([sys.executable,BASE/'tools/ownership.py','--manifest',rust/'Cargo.toml','--target-dir',out/'ownership-target','--output',out/'ownership','--toolchain',args.toolchain],repo,env,out,'ownership-run')
    ownership=json.loads((out/'ownership/result.json').read_text());ui=out/'context-ui';ui.mkdir();context_ui(args,repo,env,ui,ownership)
    entries=json.loads((build/'compile_commands.json').read_text());entry=next(row for row in entries if row['file'].endswith('/crypto_hpke.c'));cc,options=flags(entry)
    command([cc,'--version'],build,env,out,'c-compiler')
    profiles=[]
    for level in ('0','2'):
        dest=out/('helper-O'+level);dest.mkdir();binary=dest/'context'
        command([cc]+options+['-O'+level,BASE/'reference/context.c','-L'+str(util.parent),'-Wl,-rpath,'+str(util.parent),'-L'+str(deps/'lib'),'-lgnunetutil','-lsodium','-o',binary],entry['directory'],env,dest,'build')
        initial=base();observed=command([binary],build,env,dest,'base','\n'.join(initial)+'\n').splitlines();rows=initial+failures(initial,observed)
        casepath=dest/'cases.txt';casepath.write_text('\n'.join(rows)+'\n');normal=command([binary],build,env,dest,'normal',casepath.read_text())
        if len(normal.splitlines())!=len(rows):raise ValueError('C result row count differs')
        renv=env.copy();renv.update({'GNUNET_HPKE_CASES':str(casepath),'GNUNET_HPKE_RESULTS':str(dest/'normal.stdout'),'GNUNET_HPKE_ACCEPT':str(dest/'rust-accept.txt')})
        tested=command(cargo+['test','--manifest-path',rust/'Cargo.toml','--offline','--locked',TEST,'--','--ignored','--nocapture'],repo,renv,dest,'rust-compare')
        if 'test '+TEST+' ... ok' not in tested or 'test result: ok. 1 passed; 0 failed; 0 ignored;' not in tested:raise ValueError('actual normal-C Rust comparator did not run')
        accepted=command([binary],build,env,dest,'c-accept-rust',(dest/'rust-accept.txt').read_text())
        if accepted!=(dest/'rust-accept.expected').read_text() or not accepted.splitlines():raise ValueError('C did not accept actual Rust ciphertexts')
        profiles.append({'profile':'helper-O'+level,'cases':len(rows),'operations':summary(rows),'actual_rust_ciphertexts_accepted_by_c':len(accepted.splitlines()),'helper_sha256':sha(binary),'normal_stdout_sha256':sha(dest/'normal.stdout')})
    controls=[];control=out/'negative-controls';control.mkdir();source_rows=(out/'helper-O0/cases.txt').read_text();results=(out/'helper-O0/normal.stdout').read_text().splitlines()
    for name,column in (('context-key',5),('context-nonce',6),('context-exporter',8),('sequence',7),('ciphertext',None),('missing-row',None)):
        altered=results.copy()
        if name=='missing-row':altered.pop()
        else:
            index=next(i for i,line in enumerate(altered) if line.startswith('ROUND 1 ')) if name=='ciphertext' else next(i for i,line in enumerate(altered) if line.startswith('SETUP 1 1 '))
            parts=altered[index].split();slot=5 if name=='ciphertext' else column;value=parts[slot];parts[slot]=('0' if value[0]!='0' else '1')+value[1:];altered[index]=' '.join(parts)
        casepath=control/(name+'.cases');expected=control/(name+'.results');casepath.write_text(source_rows);expected.write_text('\n'.join(altered)+'\n');cenv=env.copy();cenv.update({'GNUNET_HPKE_CASES':str(casepath),'GNUNET_HPKE_RESULTS':str(expected),'GNUNET_HPKE_ACCEPT':str(control/(name+'.accept'))})
        failed=command(cargo+['test','--manifest-path',rust/'Cargo.toml','--offline','--locked',TEST,'--','--ignored'],repo,cenv,control,name,expected=101)
        if 'test '+TEST+' ... FAILED' not in failed or 'test result: FAILED. 0 passed; 1 failed;' not in failed:raise ValueError('negative control failed for an unrelated reason')
        controls.append({'name':name,'actual_comparator_rejected':True,'exit_code':101})
    after=snapshot(discover_paths())
    if before!=after:raise ValueError('input source/library/tool/manifests changed or file set differs')
    if reference_inputs.source_state(source)!=receipt['upstream']:raise ValueError('full normal source profile changed')
    for item in receipt['libraries']:
        if sha(Path(item['path']))!=item['sha256']:raise ValueError('normal library changed')
    dump(out/'inputs-after.json',after);generated_after=snapshot(files(rust));dump(out/'generated-after.json',generated_after)
    if generated_before!=generated_after:raise ValueError('generated candidate source changed')
    result={'status':'passed','revision':PIN,'scope':'normal unchanged public HPKE contexts; X25519 0x0020 Base/PSK; no handshake/network/daemon claim','inputs_unchanged':True,'generated_inputs_unchanged':True,'profiles':profiles,'unit_tests':{'existing':10,'new_context':8,'additional_gcm':6,'independent_public_api':7,'compile_fail_docs':2,'default_ignored_external_oracles':3},'ownership':{'existing_secret_owner_cases':14,'existing_secret_owner_types':7,'context_and_lifetime_cases':4,'positive_controls':2},'normal_no_std_no_alloc_graph':True,'new_registry_dependencies':0,'negative_controls':controls,'production_c_ffi':False,'inventory':inventory_result,'pending':['Elligator0x0022','AUTH/AuthPSK are declared but not implemented upstream','no upstream public Export function (only stored exporter_secret field)','other HPKE AEAD/KDF suites not present in pinned API'],'differences':['safe short one-shot rejection before C unsigned-underflow path','safe failure erasure; no comparison of C failed outputs as valid bytes','monotonic opaque context has no C-struct clone/rollback/key dump','OneshotLengths explicitly returns total_written and actual C ciphertext-only reported length'],'normal_libraries':snapshot(linked)}
    dump(out/'result.json',result);return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('repository','source','reference','deps-prefix','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--toolchain',default='1.99.1');args=parser.parse_args();out=args.output.resolve();receipt=json.loads(args.reference.read_text())
    for root in (args.repository,args.source,args.deps_prefix,PACKAGE,BASE/'reference',BASE/'tools',Path(receipt['build']),Path(receipt['prefix'])):
        root=root.resolve()
        if out==root or root in out.parents or out in root.parents:raise ValueError('output overlaps input '+str(root))
    out.mkdir(parents=True,exist_ok=False)
    try:result=run(args,out)
    except Exception as error:dump(out/'result.json',{'status':'failed','error_type':type(error).__name__,'error':str(error)});raise
    print(json.dumps({'status':result['status'],'profiles':result['profiles'],'result':str(out/'result.json'),'sha256':sha(out/'result.json')}))
if __name__=='__main__':main()
