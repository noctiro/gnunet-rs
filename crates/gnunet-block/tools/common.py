"""Fail-closed source/library/profile and output boundaries shared by test tools."""
import hashlib,importlib.util,json,pathlib,subprocess,shlex,types
PIN='346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
PLUGINS={'test','dht','fs','gns','dns','regex','revocation','seti_test','setu_test'}
def require(condition,message='verification invariant failed'):
 if not condition:raise ValueError(message)
def trace_differences(rows,left,right):
 require(bool(rows),'empty comparison corpus')
 require(len(left)==len(rows)and len(right)==len(rows),'actual trace count differs from complete corpus')
 return [{'label':row['label'],'line':row.get('line'),'c':cv,'rust':rv}for row,cv,rv in zip(rows,left,right)if cv!=rv]

def sha(path):return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
def disjoint(output,protected):
 out=pathlib.Path(output).resolve()
 for item in protected:
  path=pathlib.Path(item).resolve()
  if out==path or out in path.parents or path in out.parents:raise ValueError('output overlaps protected input: '+str(path))
def checked_rows(rows):
 if not rows:raise ValueError('empty source/library binding')
 names=[str(pathlib.Path(row['path']).resolve())for row in rows]
 if len(names)!=len(set(names)):raise ValueError('duplicate source/library binding')
 for row in rows:
  if sha(row['path'])!=row['sha256']:raise ValueError('input hash mismatch: '+str(row['path']))
def successful(process,label):
 if process.returncode!=0:raise ValueError(f'{label}: actual child exited {process.returncode}')
BUILDER_ROLES={'builder','common','reference-helper'}
def reviewed_builder_inputs(reference_helper):
 tools=pathlib.Path(__file__).resolve().parent
 return{'builder':tools/'build_normal.py','common':tools/'common.py','reference-helper':pathlib.Path(reference_helper).resolve()}

def checked_builder_inputs(rows,reviewed):
 """Check original executed paths plus same-byte current reviewed role sources."""
 require(isinstance(rows,list)and len(rows)==3,'nonempty complete three-role builder_inputs required')
 require(set(reviewed)==BUILDER_ROLES,'complete reviewed builder source roles required')
 require(all(isinstance(row,dict)and set(row)=={'role','path','sha256'}and isinstance(row['role'],str)for row in rows),'exact builder input row schema required')
 roles=[row['role']for row in rows]
 require(set(roles)==BUILDER_ROLES and len(set(roles))==len(roles),'unique complete actual builder input roles required')
 actual=[];result={}
 for row in rows:
  require(isinstance(row['path'],str)and isinstance(row['sha256'],str),'builder input path/hash must be strings')
  original=pathlib.Path(row['path'])
  require(original.is_absolute()and original==original.resolve(),'actual builder input must preserve canonical absolute executed path')
  require(original.is_file(),'actual builder source unavailable: '+str(original))
  require(sha(original)==row['sha256'],'actual builder input source changed: '+row['role'])
  current=pathlib.Path(reviewed[row['role']]).resolve()
  require(current.is_file()and sha(current)==row['sha256'],'current reviewed builder role differs from actual source: '+row['role'])
  actual.append(str(original))
  result[row['role']]={'actual_path':str(original),'reviewed_path':str(current),'sha256':row['sha256'],'actual_path_preserved':True}
 require(len(set(actual))==len(actual),'duplicate actual builder input path')
 return result

def normal(receipt,helper):
 path=pathlib.Path(receipt).resolve();r=json.loads(path.read_text());module=types.ModuleType('fixed_normal_reference');module.__file__=str(pathlib.Path(helper).resolve());exec(compile(pathlib.Path(helper).read_bytes(),str(helper),'exec'),module.__dict__)
 if r.get('status')!='passed' or r.get('kind')!='fresh-unmodified-normal-block-meson-build' or r.get('source_unchanged')is not True:raise ValueError('not a successful normal BLOCK build')
 state=module.source_state(pathlib.Path(r['source']))
 if state!=r['upstream']or state['revision']!=PIN or state['tag']!='v0.29.1':raise ValueError('normal source revision/state mismatch')
 profile=r['hello_profile']
 if profile not in ['normal','deterministic']:raise ValueError('unknown HELLO profile')
 expected={'libgnunet_plugin_block_'+name+'.dylib'for name in PLUGINS}
 if {pathlib.Path(x['path']).name for x in r['plugins']}!=expected or len(r['plugins'])!=9:raise ValueError('installed plugin set mismatch')
 libraries={pathlib.Path(x['path']).name for x in r['libraries']}
 if not {'libgnunetblock.0.dylib','libgnunetblockgroup.0.dylib','libgnunetutil.23.dylib','libgnunethello.0.dylib','libgnunetgnsrecord.1.dylib','libgnunetregexblock.1.dylib'}<=libraries:raise ValueError('normal library closure incomplete')
 rows=r['libraries']+r['plugins']+[r['compile_commands'],r['generated_config']]
 checked_rows(rows)
 for row in r['libraries']+r['plugins']:
  if sha(row['built_path'])!=row['sha256']:raise ValueError('staged library differs from actual normal build')
 commands=json.loads(pathlib.Path(r['compile_commands']['path']).read_text());hello=[x for x in commands if x['file'].endswith('/hello-uri.c')]
 if len(hello)!=1:raise ValueError('HELLO compiler input absent/ambiguous')
 command=hello[0].get('arguments')or shlex.split(hello[0]['command'])
 flag='-DHELLO_DETERMINISTIC_PID_DERIVATION=1'
 if (flag in command)!=(profile=='deterministic'):raise ValueError('declared HELLO profile differs from actual compiler flags')
 setup=[x for x in r['commands']if x.get('label')=='setup']
 require(len(setup)==1 and setup[0]['exit_code']==0,'unique actual successful normal setup required')
 argv=setup[0]['argv'];require(argv[1]=='setup'and pathlib.Path(argv[2]).resolve()==pathlib.Path(r['build']).resolve()and pathlib.Path(argv[3]).resolve()==pathlib.Path(r['source']).resolve()and '--prefix='+r['prefix']in argv,'normal setup source/build/prefix differs')
 require(r.get('builder_inputs_unchanged')is True,'actual builder source pre/post equality must be recorded')
 bindings=checked_builder_inputs(r.get('builder_inputs'),reviewed_builder_inputs(helper))
 require(r.get('builder_sha256')==bindings['builder']['sha256'],'legacy builder hash differs from actual three-role source binding')
 require(sha(r['baseline']['path'])==r['baseline']['sha256'],'normal baseline receipt changed')
 for name in ('DYLD_LIBRARY_PATH','LD_LIBRARY_PATH'):
  require(pathlib.Path(r['runtime_environment'][name]).resolve()==pathlib.Path(r['prefix']).resolve()/'lib','normal runtime library prefix differs')
 require(pathlib.Path(r['runtime_environment']['GNUNET_PREFIX']).resolve()==pathlib.Path(r['prefix']).resolve(),'normal GNUnet prefix differs')
 return r,state,module.source_state

def reference_inputs(r,helper):
 rows=r['libraries']+r['plugins']+[r['compile_commands'],r['generated_config'],r['baseline']]
 bindings=checked_builder_inputs(r.get('builder_inputs'),reviewed_builder_inputs(helper))
 paths={pathlib.Path(path).resolve()for binding in bindings.values()for path in(binding['actual_path'],binding['reviewed_path'])}
 paths|={pathlib.Path(x['path']).resolve()for x in rows}
 paths|={p.resolve()for p in pathlib.Path(r['build']).rglob('*.h')if p.is_file()}
 queue=[pathlib.Path(x['path']).resolve()for x in r['libraries']+r['plugins']];seen=set()
 while queue:
  current=queue.pop()
  if current in seen:continue
  seen.add(current);result=subprocess.run(['/usr/bin/otool','-L',str(current)],capture_output=True);successful(result,'normal dynamic provider inspection')
  for line in result.stdout.decode().splitlines()[1:]:
   name=line.strip().split(' (',1)[0]
   if name.startswith('@rpath/'):candidates=[pathlib.Path(r['prefix'])/'lib'/name[len('@rpath/'):],pathlib.Path(r['prefix'])/'lib/gnunet'/name[len('@rpath/'):]]
   elif name.startswith(('@loader_path/','@executable_path/')):candidates=[current.parent/name.split('/',1)[1]]
   else:candidates=[pathlib.Path(name)]
   found=next((p.resolve()for p in candidates if p.is_file()),None)
   if found is None:
    require(name.startswith(('/usr/lib/','/System/Library/')),'unresolved non-system normal provider: '+name);continue
   paths.add(found)
   if found not in seen:queue.append(found)
 return{str(p):sha(p)for p in sorted(paths)}


def require_probe(c,receipt,reference_helper,tools):
 tools=pathlib.Path(tools).resolve();receipt=pathlib.Path(receipt).resolve()
 require(c.get('status')=='passed','successful actual C probe build required')
 require(pathlib.Path(c['receipt']['path']).resolve()==receipt and c['receipt']['sha256']==sha(receipt),'C probe must bind exact requested normal receipt')
 for field,path in [('source',tools/'probe.c'),('builder',tools/'build_probe.py'),('common',tools/'common.py'),('reference_helper',pathlib.Path(reference_helper).resolve())]:
  require(pathlib.Path(c[field]['path']).resolve()==path and c[field]['sha256']==sha(path),'actual maintained C probe source/tool identity differs: '+field)
 require(bool(c['compiler_header_inputs'])and bool(c['normal_reference_inputs'])and bool(c['compiler_artifacts']),'nonempty actual compiler/provider/artifact closure required')
 require(str((tools/'probe.c').resolve())in c['compiler_header_inputs'],'actual compiler did not bind maintained probe source')
 commands=[row for row in c['commands']if row.get('label')=='build']
 require(len(commands)==1 and commands[0]['exit']==0,'actual successful C probe compilation absent')
 checked_rows([c['binary'],c['compiler']])
