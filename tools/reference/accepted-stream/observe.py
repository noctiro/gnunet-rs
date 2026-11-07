#!/usr/bin/env python3
"""Canonical-versus-raw accepted TCP observation using real unchanged C util."""
import argparse,hashlib,itertools,json,os,re,shlex,shutil,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
PACKAGE=Path(__file__).resolve().parent
PIN='346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def files(root):return {p.resolve()for p in root.rglob('*')if p.is_file()and not {'target','.git','__pycache__'}.intersection(p.relative_to(root).parts)}
def observations(crows,rrows):
 expected_c=set(itertools.product(['v4','v6'],['default','off','on'],['address','null-address'],['O0','O2']))
 expected_r=set(itertools.product(['v4','v6'],['default','off','on'],['poll','wrapper','canonical']))
 if len(crows)!=24 or {(r['family'],r['preset'],r['accept_mode'],r['optimization'])for r in crows}!=expected_c:raise ValueError('exact24 unique C profiles required')
 if len(rrows)!=18 or {(r['family'],r['preset'],r['accept_mode'])for r in rrows}!=expected_r:raise ValueError('exact18 unique Rust profiles required')
 for row in crows:
  accepted=row['accepted']
  if row['actor']!='normal-c'or row['actual_payload']is not True or not 0<=row['accepted_fd']<row['fd_setsize']or accepted['type']!=1 or accepted['nodelay']==0 or accepted['nonblocking']!=1 or accepted['cloexec']!=1:raise ValueError('actual C accepted socket evidence missing')
  if sys.platform=='darwin'and accepted['nosigpipe']!=1:raise ValueError('actual C Darwin NOSIGPIPE was not initialized')
  if row['preset']=='off'and row['listener']['nodelay']!=0:raise ValueError('actual C listener-off control missing')
 for row in rrows:
  accepted=row['accepted']
  if row['actor']!='rust-public'or row['actual_payload']is not True or not 0<=row['accepted_fd']<row['fd_setsize']or accepted['nonblocking']!=1 or accepted['cloexec']!=1 or accepted['type']!=1:raise ValueError('actual Rust accepted socket evidence missing')
  if row['accept_mode']=='wrapper'and row['before_wrapper']!=accepted:raise ValueError('pure constructor changed options')
 differences=[]
 for row in rrows:
  peer=next(c for c in crows if c['family']==row['family']and c['preset']==row['preset']and c['optimization']=='O2'and c['accept_mode']=='address');rust=row['accepted'];native=rust['native_readonly_duplicate'];boolean={'nodelay','nonblocking','cloexec','keepalive','reuseaddr','linger_on'};semantic=lambda key,value:bool(value)if key in boolean else value;fields={k:{'normal_c':semantic(k,peer['accepted'][k]),'rust_public':semantic(k,rust[k]),'normal_c_native_raw':peer['accepted'][k],'rust_typed_value':rust[k]}for k in ['nodelay','nonblocking','cloexec','keepalive','reuseaddr','type','linger_on','linger_seconds']if semantic(k,peer['accepted'][k])!=semantic(k,rust[k])}
  if peer['accepted']['nosigpipe']!=native['nosigpipe']:fields['nosigpipe']={'normal_c':peer['accepted']['nosigpipe'],'rust_public':native['nosigpipe']}
  if fields:differences.append({'family':row['family'],'preset':row['preset'],'accept_mode':row['accept_mode'],'fields':fields})
 if any(row['accept_mode']=='canonical'for row in differences):raise ValueError('canonical native option mismatch')
 if len(differences)!=8 or not any('nodelay'in row['fields']for row in differences):raise ValueError('raw/pure constructor controls changed')
 return differences
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for key in ['repository','source','reference','output']:p.add_argument('--'+key,type=Path,required=True)
 p.add_argument('--workspace',type=Path,required=True)
 a=p.parse_args();workspace=a.workspace.resolve();repo,source,refpath,out=[getattr(a,k).resolve()for k in ['repository','source','reference','output']]
 normal=json.loads(refpath.read_text());assert normal['upstream']['revision']==PIN
 for protected in [PACKAGE,workspace,repo,source,refpath.parent,Path(normal['prefix']),Path(normal['build'])]:
  if out==protected or out.is_relative_to(protected)or protected.is_relative_to(out):raise ValueError('output overlaps source/reference')
 out.mkdir(mode=0o700,exist_ok=False);sys.path.insert(0,str(repo/'adapters/arm-std/tools'));import reference
 checked,normal_inputs=reference.load(refpath,source,repo);assert checked==normal
 setups=[r for r in normal['commands']if r['name']=='meson-setup'];assert len(setups)==1 and setups[0]['exit_code']==0 and setups[0]['argv'][1]=='setup'and Path(setups[0]['argv'][2]).resolve()==Path(normal['build']).resolve()
 if 'source'in normal:assert Path(normal['source']).resolve()==source
 if sys.platform!='darwin':raise ValueError('the eight raw-option difference controls require this observed Darwin profile; other Unix execution is pending')
 commands=[];artifacts={};cargo=['cargo','+1.99.1'];env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_'))};env.update(normal['runtime_environment'],CARGO_BUILD_JOBS='1',CARGO_TARGET_DIR=str(out/'target'),LC_ALL='C')
 def command(label,argv,cwd=repo,timeout=180):
  if any(sha(path)!=expected for path,expected in artifacts.items()):raise ValueError('fresh binary changed before process')
  started=time.monotonic();done=subprocess.run(list(map(str,argv)),cwd=cwd,env=env,capture_output=True,timeout=timeout);(out/(label+'.stdout')).write_bytes(done.stdout);(out/(label+'.stderr')).write_bytes(done.stderr);commands.append({'label':label,'argv':list(map(str,argv)),'cwd':str(cwd),'exit':done.returncode,'seconds':time.monotonic()-started,'stdout_sha256':sha(out/(label+'.stdout')),'stderr_sha256':sha(out/(label+'.stderr'))})
  if any(sha(path)!=expected for path,expected in artifacts.items()):raise ValueError('fresh binary changed during process')
  if done.returncode:raise RuntimeError(label+' failed: '+done.stderr.decode())
  return done
 try:
  metadata=json.loads(command('root-metadata',cargo+['metadata','--manifest-path',repo/'Cargo.toml','--offline','--locked','--format-version=1']).stdout)
  def discover():
   ref,inputs=reference.load(refpath,source,repo);assert ref==normal and inputs==normal_inputs
   paths=files(PACKAGE)|files(workspace)|{repo/'Cargo.toml',repo/'Cargo.lock',repo/'rust-toolchain.toml',repo/'rustfmt.toml',repo/'adapters/arm-std/tools/reference.py',source/'src/lib/util/network.c',source/'src/include/gnunet_network_lib.h'}|{Path(x)for x in normal_inputs}
   for package in metadata['packages']:
    if package['source']is None:paths|=files(Path(package['manifest_path']).resolve().parent)
   return {str(path):sha(path)for path in sorted(paths,key=lambda x:os.fsencode(x))}
  before=discover();(out/'inputs-before.json').write_text(json.dumps(before,indent=2)+'\n')
  crate=workspace
  generated={str(x):sha(x)for x in files(crate)}
  command('rust-format',cargo+['fmt','--manifest-path',crate/'Cargo.toml','-p','gnunet-native','-p','gnunet-service-runtime','-p','gnunet-ipc-unix','-p','canonical-accept-probe','--check'])
  # Formatting belongs to generation; freeze those exact bytes before build.
  generated={str(x):sha(x)for x in files(crate)}
  command('rust-build',cargo+['build','--manifest-path',crate/'Cargo.toml','--offline','--locked','-p','canonical-accept-probe','-j','1'])
  command('rust-clippy',cargo+['clippy','--manifest-path',crate/'Cargo.toml','--offline','--locked','-p','gnunet-native','-p','gnunet-service-runtime','-p','gnunet-ipc-unix','-p','gnunet-resolver-broker','-p','canonical-accept-probe','--all-targets','-j','2','--','-D','warnings'])
  binary=out/'target/debug/canonical-accept-probe';artifacts[str(binary)]=sha(binary)
  db=json.loads(Path(normal['compile_commands']['path']).read_text());entry=next(r for r in db if r['file'].endswith('/network.c'));original=entry.get('arguments')or shlex.split(entry['command']);actual_source=Path(entry['file']);actual_source=(actual_source if actual_source.is_absolute()else Path(entry['directory'])/actual_source).resolve();assert actual_source==(source/'src/lib/util/network.c').resolve(),'compiler source must match validated pinned tree';base=[];index=1
  while index<len(original):
   value=original[index]
   if value in ['-MQ','-MF','-MT','-o']:index+=2;continue
   if value in ['-c','-MD','-MMD']or value.endswith('/network.c')or re.fullmatch('-O[0-9sgz]',value):index+=1;continue
   base.append(value);index+=1
  prefix=Path(normal['prefix']);crows=[];rrows=[]
  for optimization in ['O0','O2']:
   c=out/('normal-c-'+optimization);argv=[original[0],*base,'-'+optimization,str(PACKAGE/'probe/probe.c'),'-L'+str(prefix/'lib'),'-lgnunetutil','-Wl,-rpath,'+str(prefix/'lib'),'-o',str(c)];command('compile-'+optimization,argv,cwd=entry['directory']);artifacts[str(c)]=sha(c)
   for family,preset,mode in itertools.product(['v4','v6'],['default','off','on'],['address','null-address']):
    label='c-'+optimization+'-'+family+'-'+preset+'-'+mode;done=command(label,[c,family,preset,mode]);row=json.loads(done.stdout);row['optimization']=optimization;crows.append(row)
  inspector=out/'normal-c-O2'
  for family,preset,mode in itertools.product(['v4','v6'],['default','off','on'],['poll','wrapper','canonical']):
   done=command('rust-'+family+'-'+preset+'-'+mode,[binary,family,preset,mode,inspector]);rrows.append(json.loads(done.stdout))
  differences=observations(crows,rrows)
  after=discover();(out/'inputs-after.json').write_text(json.dumps(after,indent=2)+'\n');assert before==after and generated=={str(x):sha(x)for x in files(crate)}and all(sha(path)==value for path,value in artifacts.items())
  result={'status':'passed-canonical-and-raw-observation','scope':'actual unchanged normal C util public create/bind/listen/accept and actual candidate Rust public raw/canonical poll_connection and pure constructor; owned IPv4/IPv6 loopback only; no daemon/source mutation','normal_C_rows':crows,'actual_Rust_rows':rrows,'normal_C_count':24,'Rust_count':18,'differences':differences,'source_pin':PIN,'normal_reference':{'path':str(refpath),'sha256':sha(refpath)},'inputs_unchanged':True,'generated_inputs_unchanged':True,'fresh_artifacts_sha256':artifacts,'fresh_artifacts_checked_before_after_every_process':True,'commands':commands,'inherited_fd_inspector_scope':'Independent query child reads a private duplicate of the same accepted/listener socket. Child descriptor flags are not used as evidence of parent CLOEXEC; Rust safe fcntl queries the original. No option is changed by inspector.','unexecuted_negative_source_policies':['FD_SETSIZE rejection','CLOEXEC fcntl failure logging and continue','nonblocking failure close','Darwin NOSIGPIPE failure close','TCP_NODELAY failure logging and continue'],'native_boolean_comparison':'Darwin native TCP_NODELAY/SO_REUSEADDR enabled values observed as4; semantic nonzero truth is compared with socket2 bool while retaining every raw native value. Raw4 versus bool1 is not reported as a behavioral difference.','workspace_source_path':str(workspace),'no_full_network_owner_promotion':True};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'normal_C':24,'Rust':18,'difference_profiles':len(differences),'result':str(out/'result.json')}))
 except BaseException as e:
  (out/'failure.json').write_text(json.dumps({'status':'failed','error':str(e),'commands':commands},indent=2)+'\n');raise
if __name__=='__main__':main()
