#!/usr/bin/env python3
"""Fresh unchanged normal Meson block libraries/plugins, never modify old receipts."""
import argparse,hashlib,json,os,pathlib,shutil,subprocess,sys,time
import common as actual_common
from common import disjoint,require

def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--source',type=pathlib.Path,required=True);p.add_argument('--baseline',type=pathlib.Path,required=True);p.add_argument('--reference-helper',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--hello-profile',choices=['normal','deterministic'],default='normal');a=p.parse_args();a.output=a.output.resolve();base=json.loads(a.baseline.read_text());disjoint(a.output,[a.source,a.baseline.parent,pathlib.Path(__file__).resolve().parent,a.reference_helper.resolve().parent]);a.output.mkdir(exist_ok=False,parents=True);sys.dont_write_bytecode=True;sys.path.insert(0,str(a.reference_helper.resolve().parent));import build_reference as actual_reference
 require(pathlib.Path(actual_reference.__file__).resolve()==a.reference_helper.resolve(),'actual imported reference helper differs from requested file')
 source_state=actual_reference.source_state
 builder_paths={'builder':pathlib.Path(__file__).resolve(),'common':pathlib.Path(actual_common.__file__).resolve(),'reference-helper':pathlib.Path(actual_reference.__file__).resolve()}
 builder_inputs=[{'role':role,'path':str(path),'sha256':sha(path)}for role,path in builder_paths.items()]
 actual_common.checked_builder_inputs(builder_inputs,builder_paths)
 before=source_state(a.source);require((base['status'] == 'passed' and base['source_unchanged'] and (base['upstream'] == before) and (before['revision'] == '346358e26d4dcc2dc4f51bef5d52dca29c7d8165')), 'verification invariant failed: build_normal.py:9')
 build=a.output/'build';prefix=a.output/'prefix';env=os.environ.copy();env.update(base['build_environment']);env['CPPFLAGS']=env.get('CPPFLAGS','')+(' -DHELLO_DETERMINISTIC_PID_DERIVATION=1' if a.hello_profile=='deterministic' else '');commands=[];start=time.monotonic()
 def run(label,argv):
  proc=subprocess.run(list(map(str,argv)),env=env,capture_output=True,timeout=300);(a.output/(label+'.stdout')).write_bytes(proc.stdout);(a.output/(label+'.stderr')).write_bytes(proc.stderr);commands.append({'label':label,'argv':list(map(str,argv)),'exit_code':proc.returncode});require((proc.returncode == 0), proc.stderr.decode(errors='replace')[-3000:]);print(label,flush=True)
 setup=next(row['argv']for row in base['commands']if row['name']=='meson-setup').copy();env['PATH']=str(pathlib.Path(setup[0]).parent)+os.pathsep+env.get('PATH','');setup[2]=str(build);setup[3]=str(a.source);setup=[str(prefix)if value=='__unused__'else('--prefix='+str(prefix)if value.startswith('--prefix=')else value)for value in setup];run('setup',setup)
 targets=['gnunetblock','gnunetblockgroup','gnunet_plugin_block_test','gnunet_plugin_block_dht','gnunet_plugin_block_fs','gnunet_plugin_block_gns','gnunet_plugin_block_dns','gnunet_plugin_block_regex','gnunet_plugin_block_revocation','gnunet_plugin_block_seti_test','gnunet_plugin_block_setu_test'];run('compile',[setup[0],'compile','-C',build,'-j','2',*targets])
 (prefix/'lib/gnunet').mkdir(parents=True);libraries=[];plugins=[]
 for path in sorted(build.rglob('libgnunet*.dylib')):
  if not path.is_file()or path.is_symlink():continue
  dest=prefix/'lib'/('gnunet/'if'libgnunet_plugin_block_'in path.name else'')/path.name;shutil.copyfile(path,dest);row={'built_path':str(path),'path':str(dest),'sha256':sha(dest)};(plugins if'libgnunet_plugin_block_'in path.name else libraries).append(row)
 # Preserve needed unversioned linker aliases, only to built copied libraries.
 for path in build.rglob('libgnunet*.dylib'):
  if not path.is_symlink()or not path.exists():continue
  target=path.resolve().name;dest=prefix/'lib'/path.name
  if (prefix/'lib'/target).is_file()and not dest.exists():dest.symlink_to(target)
 require((len(plugins) == 9), (len(plugins), plugins));require(({'libgnunetblock.0.dylib', 'libgnunetblockgroup.0.dylib'} <= set((row['path'].split('/')[-1] for row in libraries))), libraries)
 after=source_state(a.source);require((after == before), 'verification invariant failed: build_normal.py:25')
 actual_common.checked_builder_inputs(builder_inputs,builder_paths)
 result={'status':'passed','kind':'fresh-unmodified-normal-block-meson-build','scope':'Only official BLOCK/group and nine installed plugins plus actual transitive normal libraries; no C source or old build mutated.','source':str(a.source),'upstream':before,'source_unchanged':True,'hello_profile':a.hello_profile,'build':str(build),'prefix':str(prefix),'libraries':libraries,'plugins':plugins,'compile_commands':{'path':str(build/'compile_commands.json'),'sha256':sha(build/'compile_commands.json')},'generated_config':{'path':str(build/'gnunet_private_config.h'),'sha256':sha(build/'gnunet_private_config.h')},'baseline':{'path':str(a.baseline),'sha256':sha(a.baseline)},'build_environment':{key:env[key]for key in ['CPPFLAGS','LDFLAGS','PKG_CONFIG_PATH']},'builder_sha256':next(row['sha256']for row in builder_inputs if row['role']=='builder'),'builder_inputs':builder_inputs,'builder_inputs_unchanged':True,'commands':commands,'seconds':time.monotonic()-start,'runtime_environment':{'DYLD_LIBRARY_PATH':str(prefix/'lib'),'LD_LIBRARY_PATH':str(prefix/'lib'),'GNUNET_PREFIX':str(prefix)}};(a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'result':str(a.output/'result.json')}))
if __name__=='__main__':main()
