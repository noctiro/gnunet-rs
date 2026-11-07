#!/usr/bin/env python3
"""Offline, source-bound GCM12/NIST/exact UDP-component differential.

Python3.9+. No service, network, system configuration, or modified C library.
The C helper calls unchanged original static functions against normal libraries;
this does not start the complete communicator or exercise its peer lifecycle.
"""
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
import tarfile
sys.dont_write_bytecode=True
from gcm_corpus import base,openings,summary
from udp_gcm_source import generate
PIN='346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
BASE=Path(__file__).resolve().parents[1]
PACKAGE=BASE/'candidate' if (BASE/'candidate/Cargo.toml.in').is_file() else BASE
TEST='gcm::tests::normal_c_gcrypt_and_exact_udp_source_components_accept_actual_rust_ciphertexts'
NIST_SHA='c77264d9042f947a5f64a14f8e429a18b789e24ac88da2703a63d99448b50e9a'
APPROVED={('ghash','0.6.0'):'2eecf2d5dc9b66b732b97707a0210906b1d30523eb773193ab777c0c84b3e8d5',('polyval','0.7.3'):'f0fa31d631f2b2cb2a544d0aa321ce847a94764d701ca2becc411138b93d49cd'}

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def dump(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def files(root):return sorted(p for p in root.rglob('*') if p.is_file() and not any(part in {'target','.git','__pycache__'} for part in p.relative_to(root).parts))
def snapshot(paths):return {str(p):sha(p) for p in sorted(set(paths))}
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def command(argv,cwd,env,out,name,input=None,expected=0):
    proc=subprocess.run([str(x) for x in argv],cwd=str(cwd),env=env,input=input,text=True,capture_output=True,timeout=180)
    (out/(name+'.stdout')).write_text(proc.stdout);(out/(name+'.stderr')).write_text(proc.stderr)
    dump(out/(name+'.json'),{'argv':[str(x) for x in argv],'cwd':str(cwd),'exit_code':proc.returncode,'expected_exit_code':expected,'stdout_sha256':sha(out/(name+'.stdout')),'stderr_sha256':sha(out/(name+'.stderr'))})
    if proc.returncode!=expected:raise ValueError(name+' failed; see captured logs')
    return proc.stdout

def flags(entry):
    args=entry.get('arguments') or shlex.split(entry['command']);out=[];skip=False
    for value in args[1:]:
        if skip:skip=False;continue
        if value in ('-o','-MF','-MT','-MQ'):skip=True;continue
        if value in ('-c','-MD','-MMD') or value==entry['file'] or value.endswith('/gnunet-communicator-udp.c') or value.startswith('-O'):continue
        out.append(value)
    return args[0],out

def registry(lock):
    result={}
    for block in lock.read_text().split('[[package]]')[1:]:
        fields={k:json.loads(v) for k,v in re.findall(r'^(name|version|source|checksum) = ("[^"\n]*")$',block,re.M)}
        if fields.get('source','').startswith('registry+'):
            result[(fields['name'],fields['version'])]=(fields['source'],fields['checksum'])
    return result

def noalloc(metadata,manifest):
    packages={p['id']:p for p in metadata['packages']};nodes={n['id']:n for n in metadata['resolve']['nodes']};root=next(p['id'] for p in metadata['packages'] if Path(p['manifest_path']).resolve()==manifest)
    pending=[root];observed={}
    while pending:
        ident=pending.pop()
        if ident in observed:continue
        package=packages[ident];features=nodes[ident]['features']
        if {'alloc','std'}&set(features):raise ValueError('normal dependency graph enabled alloc/std: '+package['name'])
        observed[ident]={'name':package['name'],'features':features}
        for dep in nodes[ident]['deps']:
            if not any(item['kind'] is None for item in dep['dep_kinds']):continue
            if any('proc-macro' in target['kind'] for target in packages[dep['pkg']]['targets']):continue
            pending.append(dep['pkg'])
    return observed

def approved_sources(metadata,out):
    nodes={row['id']:row for row in metadata['resolve']['nodes']};records=[];paths=[]
    for package in metadata['packages']:
        key=(package['name'],package['version'])
        if key not in APPROVED:continue
        root=Path(package['manifest_path']).parent.resolve();archive=root.parents[2]/'cache'/root.parent.name/(root.name+'.crate')
        if sha(archive)!=APPROVED[key]:raise ValueError('cached approved archive differs from registry checksum')
        required={'zeroize'} if key[0]=='ghash' else {'zeroize','hazmat'}
        if not required.issubset(nodes[package['id']]['features']):raise ValueError('approved zeroize/backend features missing')
        checked={}
        with tarfile.open(archive,'r:gz') as source:
            for member in source.getmembers():
                if not member.isfile():continue
                relative=Path(member.name)
                if relative.is_absolute() or '..' in relative.parts or relative.parts[0]!=root.name:raise ValueError('invalid cached archive path')
                actual=root.joinpath(*relative.parts[1:]);data=source.extractfile(member).read();digest=hashlib.sha256(data).hexdigest()
                if not actual.is_file() or sha(actual)!=digest:raise ValueError('expanded approved crate differs from archive: '+str(actual))
                checked[str(actual)]=digest
        actual={str(p) for p in files(root) if p.name not in {'.cargo-ok','.cargo-checksum.json'}}
        if actual!=set(checked):raise ValueError('expanded approved crate has extra/missing files')
        paths += list(map(Path,checked))+[archive]
        records.append({'name':key[0],'version':key[1],'archive':str(archive),'archive_sha256':sha(archive),'expanded_files_equal_archive':checked,'features':nodes[package['id']]['features']})
    if len(records)!=2:raise ValueError('both exact approved crates must be validated')
    dump(out/'approved-registry-sources.json',records);return paths

def ui(args,repo,env,out,ownership,helpers):
    selected=ownership['selected_rlib'];rlib=Path(selected['path']);before=sha(rlib)
    common=['rustup','run',args.toolchain,'rustc','--edition=2024','--crate-type=lib','--emit=metadata','--error-format=json','--target',ownership['host_target'],'--extern','gnunet_session_crypto='+str(rlib)]
    for directory in selected['dependency_search_paths']:common+=['-L','dependency='+directory]
    cases=[]
    for owner in ('gcm::Aes256Gcm','udp::DatagramKey'):
        for trait in ('Clone','core::fmt::Debug'):
            name=owner.split('::')[-1]+'_'+trait.split('::')[-1];path=out/(name+'.rs')
            path.write_text('fn bound<T:'+trait+'>(){}\npub fn bad(){bound::<gnunet_session_crypto::'+owner+'>();}\n')
            command(common+['--crate-name','ui_'+name,'-o',out/(name+'.rmeta'),path],repo,env,out,name,expected=1)
            helpers.expected_error((out/(name+'.stderr')).read_text(),path,owner,trait)
            cases.append({'owner':owner,'trait':trait,'error':'E0277','source_sha256':sha(path),'passed':True})
    positive=out/'positive.rs';positive.write_text('pub fn good(){let key=gnunet_session_crypto::gcm::Aes256Gcm::from_bytes([7;32]);let mut bytes=[1;17];let nonce=[3;12];if let Ok(tag)=key.seal(&nonce,b"explicit",&mut bytes){let _result=key.open(&nonce,b"explicit",&mut bytes,&tag);}let master=gnunet_session_crypto::Prk::from_bytes([9;32]);if let Ok(dg)=gnunet_session_crypto::udp::DatagramKey::derive(&master,1){let _public=(dg.kid(),dg.nonce(),dg.serial());}}\n')
    command(common+['--crate-name','ui_positive','-o',out/'positive.rmeta',positive],repo,env,out,'positive')
    if not (out/'positive.rmeta').stat().st_size or before!=sha(rlib):raise ValueError('empty positive artifact or changed rlib')
    result={'status':'passed','cases':cases,'positive_control':True,'selected_rlib_sha256':before};dump(out/'result.json',result);return result

def run(args,out):
    repo=args.repository.resolve();source=args.source.resolve();ref=args.reference.resolve();deps=args.deps_prefix.resolve()
    receipt=json.loads(ref.read_text());build=Path(receipt['build']).resolve()
    if receipt.get('kind')!='unmodified-official-c-reference-build' or receipt['status']!='passed' or not receipt['source_unchanged'] or Path(receipt['source']).resolve()!=source or receipt['upstream']['revision']!=PIN:raise ValueError('wrong normal build receipt')
    env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1';env.update(receipt['runtime_environment']);env['CARGO_TARGET_DIR']=str(out/'target')
    for name in ('LD_PRELOAD','DYLD_INSERT_LIBRARIES','DYLD_FORCE_FLAT_NAMESPACE','CARGO_BUILD_TARGET','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS'):env.pop(name,None)
    cargo=['rustup','run',args.toolchain,'cargo']
    command(['rustup','run',args.toolchain,'rustc','--version','--verbose'],repo,env,out,'rustc-version')
    helper=repo/'tools/reference/build_reference.py';reference_inputs=load('gcm_reference_inputs',helper)
    if reference_inputs.source_state(source)!=receipt['upstream']:raise ValueError('full C source differs from historical normal receipt')
    config=receipt['generated_config'];configpath=Path(config['path']).resolve()
    if configpath!=(build/'gnunet_private_config.h').resolve() or sha(configpath)!=config['sha256']:raise ValueError('normal generated configuration differs from historical receipt')
    for item in receipt['libraries']:
        if sha(Path(item['path']))!=item['sha256']:raise ValueError('normal library differs from historical receipt')
    util=next(Path(row['path']).resolve() for row in receipt['libraries'] if 'libgnunetutil' in row['path'] and not row['symlink'])
    statistics=next(Path(row['path']).resolve() for row in receipt['libraries'] if 'libgnunetstatistics' in row['path'] and not row['symlink'])
    linked={util,statistics};pending=list(linked);listings=[]
    while pending:
        library=pending.pop()
        if sys.platform=='darwin':argv=['otool','-L',library]
        elif sys.platform.startswith('linux'):argv=['ldd',library]
        else:raise ValueError('normal linkage inspection supports macOS/Linux')
        listing=command(argv,build,env,out,'linkage-'+str(len(listings)));listings.append({'path':str(library),'listing':listing})
        for line in listing.splitlines()[1:] if sys.platform=='darwin' else listing.splitlines():
            path=Path(line.strip().split(' (',1)[0].split('=>')[-1].strip())
            if path.is_absolute() and path.is_file():
                path=path.resolve()
                if path not in linked:linked.add(path);pending.append(path)
    gcrypts=[p for p in linked if p.name.startswith('libgcrypt.')]
    if len(gcrypts)!=1:raise ValueError('normal closure does not identify one gcrypt library')
    gcrypt=gcrypts[0];dump(out/'normal-linkage.json',{'libraries':snapshot(linked),'listings':listings,'unhashable_os_shared_cache_paths_remain_in_listings':True})
    nist_path=BASE/'reference/gcm-nist-selected.json'
    if sha(nist_path)!=NIST_SHA:raise ValueError('finite primary-mirror NIST fixture changed')
    nist=json.loads(nist_path.read_text())
    if nist['selected_row_count']!=50 or nist['shape_count']!=25 or len(nist['vectors'])!=50:raise ValueError('NIST scope shrank')
    baseline=repo/'crates/gnunet-session-crypto'
    ownership_path=baseline/'tools/ownership.py';ownership_helpers=load('gcm_ownership_helpers',ownership_path)
    def discover_paths():
        cpaths=[source/line for line in subprocess.check_output(['git','ls-files'],cwd=source,text=True).splitlines() if (source/line).is_file()]
        paths=files(PACKAGE)+files(BASE/'reference')+files(BASE/'tools')+cpaths+list(linked)+[helper,ref,build/'gnunet_private_config.h',build/'src/include/gnunet_config.h',build/'compile_commands.json',repo/'Cargo.toml',repo/'Cargo.lock',repo/'rust-toolchain.toml',ownership_path,baseline/'Cargo.toml']
        paths += [Path(item['path']) for item in receipt['libraries']]
        for name in ('gnunet-types','gnunet-wire','gnunet-crypto'):paths+=files(repo/'crates'/name)
        paths+=[BASE/name for name in ('GCM.md','GCM_API.md','DEPENDENCIES.md','gcm-inventory.json') if (BASE/name).is_file()]
        return paths
    before=snapshot(discover_paths());dump(out/'inputs-before.json',before)
    registry_inputs=[]
    rust=out/'rust';rust.mkdir()
    for directory in ('src','tests','examples'):shutil.copytree(PACKAGE/directory,rust/directory)
    (rust/'Cargo.toml').write_text((PACKAGE/'Cargo.toml.in').read_text().replace('@REPOSITORY@',str(repo)));shutil.copy2(repo/'Cargo.lock',rust/'Cargo.lock')
    metadata=json.loads(command(cargo+['metadata','--manifest-path',rust/'Cargo.toml','--offline','--format-version','1'],repo,env,out,'metadata'))
    dump(out/'normal-noalloc-graph.json',noalloc(metadata,(rust/'Cargo.toml').resolve()))
    registry_inputs=approved_sources(metadata,out)
    registry_before=snapshot(registry_inputs);dump(out/'approved-registry-before.json',registry_before)
    baseline_meta=json.loads(command(cargo+['metadata','--manifest-path',baseline/'Cargo.toml','--offline','--locked','--format-version','1','--no-deps'],repo,env,out,'baseline-metadata'))
    def contract(meta,manifest,exclude):
        p=next(p for p in meta['packages'] if Path(p['manifest_path']).resolve()==manifest)
        return p['features'],sorted([d for d in p['dependencies'] if d['name'] not in exclude],key=lambda d:json.dumps(d,sort_keys=True))
    if contract(metadata,(rust/'Cargo.toml').resolve(),{'ghash','polyval'})!=contract(baseline_meta,(baseline/'Cargo.toml').resolve(),{'ghash','polyval'}):raise ValueError('unapproved baseline dependency/feature changes')
    baseline_registry=registry(repo/'Cargo.lock');candidate_registry=registry(rust/'Cargo.lock');added={}
    for key,value in candidate_registry.items():
        if key in APPROVED:
            if value!=('registry+https://github.com/rust-lang/crates.io-index',APPROVED[key]):raise ValueError('approved dependency checksum differs')
            if key not in baseline_registry:added['@'.join(key)]=value
        elif baseline_registry.get(key)!=value:raise ValueError('unapproved new/changed registry package: '+str(key))
    if not all(key in candidate_registry for key in APPROVED):raise ValueError('approved GHASH backend absent')
    dump(out/'registry-contract.json',{'approved_new_registry_packages':added,'candidate_registry_package_count':len(candidate_registry),'root_integration_policy_rustsec_review_separate':True})
    generated_before=snapshot(files(rust));dump(out/'generated-before.json',generated_before)
    command(cargo+['fmt','--manifest-path',rust/'Cargo.toml','--package','gnunet-session-crypto','--','--check'],repo,env,out,'fmt')
    tested=command(cargo+['test','--manifest-path',rust/'Cargo.toml','--offline','--locked'],repo,env,out,'unit-doc')
    names=re.findall(r'#\[test\]\s*fn\s+(\w+)',(PACKAGE/'src/gcm/tests.rs').read_text())
    if len(names)!=6 or any('test gcm::tests::'+name+' ... ok' not in tested for name in names):raise ValueError('new GCM test omitted')
    results=re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',tested)
    if len(results)!=3 or any(int(row[1]) for row in results) or int(results[0][0])<24 or int(results[0][2])!=3 or int(results[1][0])<7 or int(results[2][0])<2:raise ValueError('actual unit/public/doc test scope differs')
    command(cargo+['clippy','--manifest-path',rust/'Cargo.toml','--all-targets','--offline','--locked'],repo,env,out,'clippy')
    command(cargo+['doc','--manifest-path',rust/'Cargo.toml','--no-deps','--offline','--locked'],repo,env,out,'doc')
    command(cargo+['check','--manifest-path',rust/'Cargo.toml','--lib','--target','thumbv6m-none-eabi','--offline','--locked'],repo,env,out,'embedded-thumbv6m')
    soft=env.copy();soft['CARGO_TARGET_DIR']=str(out/'soft-target');soft['CARGO_ENCODED_RUSTFLAGS']='--cfg\x1fpolyval_backend="soft"'
    soft_tested=command(cargo+['test','--manifest-path',rust/'Cargo.toml','--offline','--locked','gcm::tests'],repo,soft,out,'software-ghash')
    if any('test gcm::tests::'+name+' ... ok' not in soft_tested for name in names):raise ValueError('software GHASH omitted new test')
    command([sys.executable,ownership_path,'--manifest',rust/'Cargo.toml','--target-dir',out/'ownership-target','--output',out/'ownership','--toolchain',args.toolchain],repo,env,out,'ownership-run')
    ownership=json.loads((out/'ownership/result.json').read_text());uipath=out/'gcm-ui';uipath.mkdir();ui_result=ui(args,repo,env,uipath,ownership,ownership_helpers)
    entries=json.loads((build/'compile_commands.json').read_text());entry=next(row for row in entries if row['file'].endswith('/gnunet-communicator-udp.c'));cc,options=flags(entry)
    command([cc,'--version'],build,env,out,'c-compiler')
    profiles=[]
    for level in ('0','2'):
        dest=out/('helper-O'+level);dest.mkdir();component=generate(source,dest/'component');binary=dest/'udp-gcm'
        command([cc]+options+['-O'+level,'-I'+str(dest/'component'),BASE/'reference/udp_gcm.c',util,statistics,gcrypt,'-Wl,-rpath,'+str(util.parent),'-o',binary],entry['directory'],env,dest,'build')
        initial=base(nist);observed=command([binary],build,env,dest,'base','\n'.join(initial)+'\n').splitlines()
        for i,vector in enumerate(nist['vectors'],1):
            expected='GCM 1 '+(vector['CT'] or '-')+' '+vector['Tag']
            if observed[i]!=expected:raise ValueError('normal gcrypt differs from literal NIST vector '+str(i))
        rows=initial+openings(initial,observed);casepath=dest/'cases.txt';casepath.write_text('\n'.join(rows)+'\n')
        normal=command([binary],build,env,dest,'normal',casepath.read_text())
        if len(normal.splitlines())!=len(rows):raise ValueError('actual C row count differs')
        renv=env.copy();renv.update({'GNUNET_GCM_INPUTS':str(casepath),'GNUNET_GCM_OUTPUTS':str(dest/'normal.stdout'),'GNUNET_GCM_ACCEPT':str(dest/'rust-accept.txt')})
        tested=command(cargo+['test','--manifest-path',rust/'Cargo.toml','--offline','--locked',TEST,'--','--ignored','--nocapture'],repo,renv,dest,'rust-compare')
        if 'test '+TEST+' ... ok' not in tested or 'test result: ok. 1 passed; 0 failed; 0 ignored;' not in tested:raise ValueError('actual named comparator did not run')
        accepted=command([binary],build,env,dest,'c-accept-rust',(dest/'rust-accept.txt').read_text())
        if not accepted.splitlines() or accepted!=(dest/'rust-accept.expected').read_text():raise ValueError('normal C did not accept actual Rust ciphertexts')
        profiles.append({'profile':'helper-O'+level,'cases':len(rows),'operations':summary(rows),'nist_literal_rows':50,'actual_rust_ciphertexts_accepted_by_c':len(accepted.splitlines()),'helper_sha256':sha(binary),'normal_stdout_sha256':sha(dest/'normal.stdout'),'source_component_receipt_sha256':sha(dest/'component/result.json'),'whole_communicator_execution':False})
    controls=[];control=out/'negative-controls';control.mkdir();source_rows=(out/'helper-O0/cases.txt').read_text();results=(out/'helper-O0/normal.stdout').read_text().splitlines()
    for name,column in (('key',2),('nonce12',3),('kid',4),('cmac64',5),('ciphertext',6),('tag16',7),('packet-prefix',8),('missing-row',None)):
        altered=results.copy()
        if name=='missing-row':altered.pop()
        else:
            index=next(i for i,line in enumerate(altered) if line.startswith('UDP 1 '));parts=altered[index].split();value=parts[column];parts[column]=('0' if value[0]!='0' else '1')+value[1:];altered[index]=' '.join(parts)
        casepath=control/(name+'.cases');expected=control/(name+'.results');casepath.write_text(source_rows);expected.write_text('\n'.join(altered)+'\n')
        cenv=env.copy();cenv.update({'GNUNET_GCM_INPUTS':str(casepath),'GNUNET_GCM_OUTPUTS':str(expected),'GNUNET_GCM_ACCEPT':str(control/(name+'.accept'))})
        failed=command(cargo+['test','--manifest-path',rust/'Cargo.toml','--offline','--locked',TEST,'--','--ignored'],repo,cenv,control,name,expected=101)
        if 'test '+TEST+' ... FAILED' not in failed or 'test result: FAILED. 0 passed; 1 failed;' not in failed:raise ValueError('negative control failed for unrelated reason')
        controls.append({'name':name,'actual_named_comparator_rejected':True,'exit_code':101})
    registry_after=snapshot(approved_sources(metadata,out));dump(out/'approved-registry-after.json',registry_after)
    if registry_before!=registry_after:raise ValueError('approved crate sources/archives changed')
    after=snapshot(discover_paths());dump(out/'inputs-after.json',after)
    if before!=after:raise ValueError('source/library/tool/manifests changed or file set differs')
    if reference_inputs.source_state(source)!=receipt['upstream']:raise ValueError('normal full source state changed')
    for item in receipt['libraries']:
        if sha(Path(item['path']))!=item['sha256']:raise ValueError('normal library changed')
    generated_after=snapshot(files(rust));dump(out/'generated-after.json',generated_after)
    if generated_before!=generated_after:raise ValueError('generated candidate changed')
    result={'status':'passed','revision':PIN,'scope':'AES256-GCM nonce12/tag16 and exact unchanged UDP static crypto/layout components; no complete communicator handshake/peer owner','profiles':profiles,'inputs_unchanged':True,'generated_inputs_unchanged':True,'rust_tests':{'actual_summary_rows':re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',(out/'unit-doc.stdout').read_text()),'new_test_names':names,'nist_literal_vectors':50,'nist_shapes':25,'software_backend_executed':True,'embedded_noalloc_check':True},'ownership':{'old_negative_cases':ownership['negative_case_count'],'new_negative_cases':len(ui_result['cases']),'positive_controls':2},'negative_controls':controls,'normal_libraries':snapshot(linked),'approved_dependency_additions':added,'approved_archives_and_expanded_sources_unchanged':True,'production_c_ffi':False,'pending':['Elligator0x0022 initial KEM and purpose-signed confirmation owner','peer/KID replay cache consumption, ACK credit, rekey lifecycle and timers','network MTU/random padding admission and actual communicator transport','generic other GCM nonce/tag widths and other suites','root dependency policy/RustSec integration review'],'differences':['Rust authentication failure erases caller plaintext range; failed C plaintext is never accepted or compared','explicit finite primitive length bounds before mutation; no enormous C-buffer equivalence claim','opaque key owners refuse Clone/Debug; caller nonce/serial uniqueness remains explicit authority'],'erasure_limit':'Explicit local key/H/counter/keystream/tag-mask owners and dependency enabled Drops erase their memory; GHash::new anonymous FieldElement-to-Array conversion temporary and registers have no all-copies erasure guarantee.'}
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
