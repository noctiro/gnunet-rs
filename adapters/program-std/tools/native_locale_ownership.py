#!/usr/bin/env python3
"""Exact-error controls for native locale ownership/capability boundaries."""
import argparse,hashlib,json,subprocess,shutil
from pathlib import Path
from _common import require_disjoint_output
p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--target-dir',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--toolchain',default='1.99.1');a=p.parse_args();m=a.manifest.resolve();o=a.output.resolve()
o=require_disjoint_output(o,[m.parent,Path(__file__).resolve().parent,a.target_dir.resolve()])
o.mkdir(parents=True)
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
metadata=json.loads(subprocess.check_output(['cargo','+'+a.toolchain,'metadata','--offline','--locked','--manifest-path',str(m),'--format-version','1']))
lock=Path(metadata['workspace_root'])/'Cargo.lock'
# The exact selected local package may be a standalone package or a member.
def snapshot():return {str(f):sha(f) for f in [Path(__file__),m,lock,*sorted((m.parent/'src').rglob('*'))] if f.is_file()}
before=snapshot();argv=['cargo','+'+a.toolchain,'build','--offline','--locked','--lib','--manifest-path',str(m),'--target-dir',str(a.target_dir.resolve()),'--message-format=json'];r=subprocess.run(argv,capture_output=True);(o/'build.stdout').write_bytes(r.stdout);(o/'build.stderr').write_bytes(r.stderr)
if r.returncode:raise RuntimeError('actual native build failed')
rows=[json.loads(line)for line in r.stdout.splitlines()];art=[row for row in rows if row.get('reason')=='compiler-artifact'and Path(row.get('manifest_path',''))==m and row['target']['name']=='gnunet_native'and'lib'in row['target']['kind']]
if len(art)!=1:raise RuntimeError('ambiguous actual native package artifact')
rlibs=[Path(f)for f in art[0]['filenames']if f.endswith('.rlib')]
if len(rlibs)!=1:raise RuntimeError('ambiguous actual native rlib')
rlib=rlibs[0];original_sha=sha(rlib);shutil.copyfile(rlib,o/'gnunet_native.rlib')
dependency_dirs=sorted({str(Path(f).parent) for row in rows if row.get('reason')=='compiler-artifact' for f in row.get('filenames',[]) if f.endswith('.rlib')})
cases={
 'capability_requires_explicit_unsafe_acquisition':('E0133','pub fn bad(){let _result=gnunet_native::locale::ThreadLocale::acquire();}\n'),
 'capability_private_state_cannot_be_forged':('E0451','pub fn bad()->gnunet_native::locale::ThreadLocale{gnunet_native::locale::ThreadLocale{_private:()}}\n'),
 'locale_raw_ownership_does_not_escape':('E0616','pub fn bad(locale:gnunet_native::locale::LocaleSnapshot){let _raw=locale.handle;}\n'),
 'owned_explicit_context_positive':(None,'pub fn good(token:gnunet_native::locale::ThreadLocale)->gnunet_native::locale::CaseContext{fn check<T:Send+Sync>(){}check::<gnunet_native::locale::CaseContext>();gnunet_native::locale::CaseContext::current_thread(token)}\n')}
results=[]
for name,(expected,body)in cases.items():
 src=o/(name+'.rs');src.write_text('//! Finite compile-only native locale public API ownership control.\n#![deny(warnings)]\n/// Only the declared ownership operation is being compiled.\n'+body)
 cmd=['rustc','+'+a.toolchain,'--edition=2024','--crate-type=lib','--error-format=json','--extern','gnunet_native='+str(rlib),*[arg for directory in dependency_dirs for arg in ['-L','dependency='+directory]],str(src),'-o',str(o/(name+'.rlib'))];run=subprocess.run(cmd,capture_output=True);(o/(name+'.stdout')).write_bytes(run.stdout);(o/(name+'.stderr')).write_bytes(run.stderr)
 ds=[json.loads(line)for line in run.stderr.decode().splitlines()if line.startswith('{')];codes=[d['code']['code']for d in ds if d.get('level')=='error'and d.get('code')]
 passed=(run.returncode==0 and not codes)if expected is None else(run.returncode!=0 and codes==[expected]);results.append({'name':name,'argv':cmd,'expected':expected,'actual_codes':codes,'returncode':run.returncode,'passed':passed,'source_sha256':sha(src)})
 if not passed:raise RuntimeError('unexpected compiler control '+repr(results[-1]))
if before!=snapshot()or sha(rlib)!=original_sha:raise RuntimeError('native input/artifact changed')
(o/'blobs').mkdir()
for f,digest in before.items():
 dst=o/'blobs'/digest
 if not dst.exists():shutil.copyfile(f,dst)
(o/'result.json').write_text(json.dumps({'status':'passed','scope':'3 exact compile authority/privacy negatives + real SendSync owned-context positive; no C/native runtime execution','build_argv':argv,'cases':results,'inputs':before,'inputs_unchanged':True,'rlib':str(rlib),'rlib_sha256':original_sha,'retained_rlib_sha256':sha(o/'gnunet_native.rlib'),'toolchain':subprocess.check_output(['rustc','+'+a.toolchain,'-Vv'],text=True)},indent=2)+'\n')
