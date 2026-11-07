#!/usr/bin/env python3
"""Source-bound pure Rust candidate verification; never starts C/network/NSS."""
import argparse,hashlib,json,os,re,subprocess,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
INV=HERE/'official-profile.json'
UPSTREAM=None
API_BUILD=None
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def sources():
    files={INV,ROOT/'Cargo.toml',ROOT/'Cargo.lock',ROOT/'rust-toolchain.toml'}
    for base in [HERE]+[ROOT/'crates'/n for n in ['gnunet-client','gnunet-types','gnunet-wire','gnunet-dns','gnunet-dnsstub']]:
        for path in base.rglob('*'):
            if 'target' in path.relative_to(base).parts:continue
            if path.is_symlink():raise RuntimeError('symlink source: '+str(path))
            if path.is_file() and (path.suffix in {'.rs','.md','.json','.py','.toml'} or path.name=='Cargo.lock'):files.add(path)
    inv=json.loads(INV.read_text())
    for name,expected in inv['source_inputs'].items():
        kind,relative=name.split(':',1)
        path=(UPSTREAM if kind=='upstream' else API_BUILD)/relative
        if digest(path)!=expected:raise RuntimeError('pinned normative input changed: '+name)
        files.add(path)
    return {str(p):digest(p) for p in sorted(files)}
def declared_tests(base):
    names=[]
    for p in base:
        names.extend(re.findall(r'#\[test\](?:\s*#\[[\s\S]*?\])*\s*fn\s+(\w+)',p.read_text()))
    if len(names)!=len(set(names)):raise RuntimeError('duplicate candidate test names')
    return set(names)
def actual_tests(text):return re.findall(r'^test (\S+) \.\.\. ok$',text,re.M)
def main():
    global UPSTREAM,API_BUILD
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['output','upstream','api-build']:parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args();UPSTREAM=args.upstream.resolve();API_BUILD=args.api_build.resolve()
    output=args.output.resolve()
    for source in [HERE,UPSTREAM,API_BUILD]:
        if output.is_relative_to(source) or source.is_relative_to(output):raise RuntimeError('receipt output and sources must be disjoint')
    output.mkdir(parents=True,exist_ok=False)
    TARGET=output/'target'
    commands=[]
    before=sources();(output/'sources-before.json').write_text(json.dumps(before,indent=2)+'\n')
    def run(name,argv,expect=0,env=None):
        start=time.time();p=subprocess.run([str(a) for a in argv],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        (output/(name+'.stdout')).write_bytes(p.stdout);(output/(name+'.stderr')).write_bytes(p.stderr)
        item={'name':name,'argv':[str(a) for a in argv],'cwd':str(ROOT),'exit_code':p.returncode,'elapsed_seconds':time.time()-start}
        commands.append(item)
        if (expect==0 and p.returncode!=0) or (expect!=0 and p.returncode==0):raise RuntimeError(name+' unexpected exit '+str(p.returncode))
        return p.stdout.decode('utf-8','replace')+'\n'+p.stderr.decode('utf-8','replace')
    common=['--manifest-path',HERE/'Cargo.toml','--target-dir',TARGET,'--offline','--locked','--no-default-features','-p','gnunet-resolver-service-core']
    run('toolchain',['rustc','+1.99.1','-Vv']);run('cargo-version',['cargo','+1.99.1','-V'])
    run('fmt',['cargo','+1.99.1','fmt','--manifest-path',HERE/'Cargo.toml','--','--check'])
    runtime=run('candidate-tests',['cargo','+1.99.1','test',*common,'--tests'])
    expected=declared_tests(list((HERE/'src').glob('*.rs'))+list((HERE/'tests').glob('*.rs')))
    actual=actual_tests(runtime)
    if len(actual)!=len(expected) or {n.split('::')[-1] for n in actual}!=expected:raise RuntimeError('candidate executed-test set differs from source')
    doc=run('rustdoc-tests',['cargo','+1.99.1','test',*common,'--doc'])
    docnames=actual_tests(doc)
    # Rustdoc prints a separate compile-fail suffix, parse both actual groups.
    docnames=re.findall(r'^test (.+?) \.\.\. ok$',doc,re.M)
    if len(docnames)!=4 or sum('compile fail' in n for n in docnames)!=2:raise RuntimeError('rustdoc controls missing')
    inherited=run('existing-resolver-tests',['cargo','+1.99.1','test','--manifest-path',ROOT/'crates/gnunet-client/Cargo.toml','--target-dir',TARGET,'--offline','--locked','-p','gnunet-client','--test','resolver'])
    inherited_expected=declared_tests([ROOT/'crates/gnunet-client/tests/resolver.rs'])
    inherited_actual=actual_tests(inherited)
    if set(inherited_actual)!=inherited_expected or len(inherited_actual)!=len(inherited_expected):raise RuntimeError('existing resolver test set incomplete')
    run('clippy',['cargo','+1.99.1','clippy',*common,'--all-targets','--','-D','warnings'])
    env=os.environ.copy();env['RUSTDOCFLAGS']='-D warnings'
    run('docs',['cargo','+1.99.1','doc',*common,'--no-deps'],env=env)
    run('thumb',['cargo','+1.99.1','check',*common,'--target','thumbv6m-none-eabi'])
    meta=run('metadata',['cargo','+1.99.1','metadata','--manifest-path',HERE/'Cargo.toml','--offline','--locked','--no-default-features','--format-version','1'])
    metadata=json.loads((output/'metadata.stdout').read_text())
    tree=run('production-tree',['cargo','+1.99.1','tree','--manifest-path',HERE/'Cargo.toml','--offline','--locked','--no-default-features','-p','gnunet-resolver-service-core','--edges','normal','--prefix','none','--format','{p}|{f}'])
    tree=(output/'production-tree.stdout').read_text()
    allowed={'gnunet-resolver-service-core','gnunet-client','gnunet-types','gnunet-wire','gnunet-dns','gnunet-dnsstub'}
    used=set()
    for line in tree.splitlines():
        if not line.strip():continue
        package,features=line.removesuffix(' (*)').split('|',1)
        if features.strip():raise RuntimeError('unexpected enabled feature '+line)
        used.add(package.split()[0])
    if used!=allowed:raise RuntimeError('unexpected/missing production dependency '+str(used))
    if any(p['source'] is not None for p in metadata['packages'] if p['name'] in used):raise RuntimeError('unexpected registry dependency')
    store=run('storage',['cargo','+1.99.1','run',*common,'--example','storage'])
    storage=json.loads((output/'storage.stdout').read_text())
    if not storage.get('constructed') or not storage.get('stop_released') or storage['max_record_bytes']!=65535 or storage['pair_vector_reserved_bytes']>=24*1024*1024:raise RuntimeError('fullwidth construction proof failed')
    # Use Cargo's actual artifact dependency graph; modification-time guesses can
    # select a different feature/profile incarnation of the same crate.
    run('ui-artifacts',['cargo','+1.99.1','build',*common,'--lib','--message-format=json'])
    libraries={}
    for line in (output/'ui-artifacts.stdout').read_text().splitlines():
        artifact=json.loads(line)
        if artifact.get('reason')=='compiler-artifact':
            for name in artifact['filenames']:
                if name.endswith('.rlib'):libraries[artifact['target']['name']]=name
    deps=TARGET/'debug/deps'
    rust=['rustc','+1.99.1','--edition=2024','--crate-type=lib','--emit=metadata','--error-format=json','-L','dependency='+str(deps),'--extern','gnunet_resolver_service_core='+libraries['gnunet_resolver_service_core'],'--extern','gnunet_types='+libraries['gnunet_types']]
    ui=[]
    for name,code in [('staging_no_authority','E0599'),('effect_after_release','E0502'),('controls',None)]:
        text=run('ui-'+name,[*rust,HERE/'tests/ui'/ (name+'.rs'),'-o',output/(name+'.rmeta')],expect=1 if code else 0)
        diagnostics=[]
        for line in (output/('ui-'+name+'.stderr')).read_text().splitlines():
            try:d=json.loads(line)
            except json.JSONDecodeError:continue
            if d.get('level')=='error' and d.get('code') is not None:diagnostics.append(d['code']['code'])
        if diagnostics!=([code] if code else []):raise RuntimeError('wrong compile error '+name+':'+str(diagnostics))
        ui.append({'case':name,'expected_code':code,'actual_codes':diagnostics,'success':True})
    status=json.loads((HERE/'api-status.json').read_text());baseline=json.loads(INV.read_text())
    if len(status['features'])!=45 or {x['id'] for x in status['features']}!={x['id'] for x in baseline['features']}:raise RuntimeError('45ID set mismatch')
    originals={x['id']:x for x in baseline['features']}
    for f in status['features']:
        if f['verification'] is not None or any(f[k]!=originals[f['id']][k] for k in ['requirement','upstream_source','group']):raise RuntimeError('requirement mutation/promotion')
        for ref in f['test_references']:
            path,fn=ref.split('::',1);path=ROOT/path.removeprefix('workspace:') if path.startswith('workspace:') else HERE/path
            if fn.split('::')[-1] not in re.findall(r'fn\s+(\w+)',path.read_text()):raise RuntimeError('missing referenced test '+ref)
    after=sources();(output/'sources-after.json').write_text(json.dumps(after,indent=2)+'\n')
    if before!=after:raise RuntimeError('source changed during verification')
    result={'schema':1,'success':True,'scope':'Pure Rust borrowed Resolver core candidate; no running Resolver daemon, C process or network proof','commands':commands,'candidate_runtime_test_count':len(actual),'candidate_runtime_test_names':actual,'rustdoc_count':len(docnames),'rustdoc_names':docnames,'inherited_pure_client_test_count':len(inherited_actual),'inherited_pure_client_test_names':inherited_actual,'ui_diagnostics':ui,'storage':storage,'exact_feature_ids_retained':45,'verification_promotion':False,'source_unchanged':True,'source_inputs_sha256':digest(output/'sources-before.json'),'no_host_dependencies_or_enabled_features':True,'source_edited':False,'c_or_network_processes_executed':False,'artifact_sha256':{p.name:digest(p) for p in sorted(output.iterdir()) if p.is_file()}}
    (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'success':True,'candidate_tests':len(actual),'rustdoc':len(docnames),'inherited_pure_client_tests':len(inherited_actual),'result':str(output/'result.json'),'result_sha256':digest(output/'result.json')}))
if __name__=='__main__':main()
