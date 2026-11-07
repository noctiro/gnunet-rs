import os,sys,json,subprocess,shutil,hashlib,argparse
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from normal_reference import load,compile_probe
from _common import sha,require_disjoint_output
from validation import validate_configuration_locale
BASE=Path(__file__).resolve().parents[1];p=argparse.ArgumentParser()
for key in ['repo','source','reference','rust','library','output']:p.add_argument('--'+key,type=Path,required=True)
a=p.parse_args();o=a.output.resolve()
o=require_disjoint_output(o,[BASE,a.repo,a.source,a.reference.resolve().parent,a.rust.resolve().parent])
if o.exists():raise SystemExit('fresh output required')
o.mkdir(parents=True)
repo=a.repo.resolve();source=a.source.resolve();reference=a.reference.resolve();library=a.library.resolve();r,normal=load(reference,source,repo);tools=Path(__file__).resolve().parent
inputs={str(path):sha(path) for path in [Path(__file__),Path(__file__).with_name('normal_reference.py'),library,BASE/'reference/configuration_locale.c',a.rust.resolve()]}
(out_blobs:=o/'blobs').mkdir()
for name,digest in inputs.items():shutil.copyfile(name,out_blobs/digest)
rust=o/'rust-observer';shutil.copy2(a.rust.resolve(),rust);c=o/'normal-observer';compiled=compile_probe(BASE/'reference/configuration_locale.c',c,r,strict_fixture=True);catalogs=o/'owned-empty-catalogs';catalogs.mkdir();actors={str(x):sha(x) for x in [rust,c]}
env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','OWNED_','DYLD_','LD_'))and k not in ['LANG','LC_ALL','LANGUAGE','LC_MESSAGES']};env.update(r['runtime_environment']);env={k:v for k,v in env.items()if not k.lower().startswith('owned_locale_var')}
profiles=['C','en_US.UTF-8','en_US.ISO8859-1','tr_TR.ISO8859-9','tr_TR.UTF-8','de_DE.ISO8859-1']
cases=[(mode,locale,[])for locale in profiles for mode in ['switch','choice-paths']]+[('float',locale,[f])for locale in ['C','en_US.ISO8859-1','de_DE.ISO8859-1']for f in ['0','-0','1.25','\v1.25','0x1.8p+1','INF','NaN','nan(payload)','1e','0x','+','.',' ','12x','1.25 e','1,25']]
cases += [('float-reset',locale,[f]) for locale in ['C','en_US.ISO8859-1','de_DE.ISO8859-1'] for f in ['1.25','1,25','+','nan(payload)']]
cases += [(mode,locale,[])for locale in profiles for mode in ['byte-table','parse-number','thread-numeric']]
cases += [('set-float',locale,[str(i)])for locale in ['C','de_DE.ISO8859-1'] for i in range(10)]
include=o/'owned-include.conf';include.write_bytes(b'[own\xc9]\nk\xd6 = include-owned\n')
cases += [(mode,locale,[str(include) if mode!='include-matching'else str(o/'owned-include*.conf')])for locale in profiles for mode in ['include','include-secret','include-matching']]
cases += [('dollar',locale,[])for locale in profiles]
rows=[]
for index,(mode,locale,extra)in enumerate(cases):
 current=env.copy();current['LC_ALL']=locale;observed=[]
 for label,binary,argv in [('c',c,[mode,locale,*extra]),('rust',rust,[mode,locale,str(library),str(catalogs),*extra])]:
  child=subprocess.run([str(binary),*argv],env=current,capture_output=True,timeout=5);(o/(str(index)+'-'+label+'.stdout')).write_bytes(child.stdout);(o/(str(index)+'-'+label+'.stderr')).write_bytes(child.stderr)
  if child.returncode or child.stderr:
   (o/'failure.json').write_text(json.dumps({'status':'failed','index':index,'mode':mode,'locale':locale,'actor':label,'returncode':child.returncode,'stdout_hex':child.stdout.hex(),'stderr_hex':child.stderr.hex(),'inputs':inputs,'normal_inputs':normal,'actors':actors},indent=2)+'\n')
   raise RuntimeError((index,label,'actor failure',child.returncode,child.stderr))
  observed.append({'actor':label,'returncode':child.returncode,'stdout_hex':child.stdout.hex(),'stderr_hex':child.stderr.hex()})
 rows.append({'index':index,'mode':mode,'locale':locale,'input':extra,'equal':observed[0]['stdout_hex']==observed[1]['stdout_hex'],'actors':observed})
after={name:sha(Path(name))for name in inputs};_,normal_after=load(reference,source,repo)
if inputs!=after or normal!=normal_after or any(sha(Path(name))!=digest for name,digest in actors.items()):raise RuntimeError('input changed')
result={'status':'observed_difference'if any(not row['equal'] for row in rows)else'passed','scope':'ordinary defined-safe normal C public CONFIG operations vs explicit native locale Rust candidate; inputs are finite in-range float or lexical failures, no overflowing scanf, malformed relative-time/base32 or pointer UB','rows':rows,'profiles':len(rows),'compiled':compiled,'normal_inputs':normal,'inputs':inputs,'actors':actors,'inputs_unchanged':True,'C_undefined_input_executed':False}
if result['status']=='passed':result['acceptance']=validate_configuration_locale(result)
(o/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'status':result['status'],'rows':len(rows),'differences':[{'index':x['index'],'mode':x['mode'],'locale':x['locale'],'input':x['input'],'actors':x['actors']} for x in rows if not x['equal']]},indent=2))
