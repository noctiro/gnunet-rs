#!/usr/bin/env python3
"""Compile small probes using an actual unchanged normal Meson compile unit."""
import argparse,hashlib,json,pathlib,re,shlex,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ['gnunet-source','reference-build','reference-library','idn2-library','unistring-library','output']:p.add_argument('--'+name,type=pathlib.Path,required=True)
 a=p.parse_args();out=a.output.resolve();assert not out.is_relative_to(ROOT) and not ROOT.is_relative_to(out),'Probe output and source must be disjoint';out.mkdir(parents=True,exist_ok=True)
 source=a.gnunet_source.resolve();commands=a.reference_build.resolve()/'compile_commands.json';units=json.loads(commands.read_text());target=source/'src/lib/util/dnsparser.c';matching=[]
 for u in units:
  directory=pathlib.Path(u['directory']);f=pathlib.Path(u['file']);f=(directory/f).resolve() if not f.is_absolute() else f.resolve()
  if f==target:matching.append(u)
 assert len(matching)==1,'Exactly one actual dnsparser compile unit is required'
 u=matching[0];directory=pathlib.Path(u['directory']).resolve();argv=u.get('arguments') or shlex.split(u['command']);flags=[];i=0
 while i<len(argv):
  x=argv[i]
  if x in ('-o','-MF','-MQ','-MT','-c'):i+=2;continue
  if x in ('-MD','-MMD','-MP'):i+=1;continue
  flags.append(x);i+=1
 assert '-DNDEBUG' not in flags,'The reference probes require active assertions'
 libs=[a.reference_library.resolve(),a.idn2_library.resolve(),a.unistring_library.resolve()]
 results=[]
 for name in ['probe','frontend_probe','native_pack']:
  file=ROOT/'tools'/(name+'.c');binary=out/{'probe':'c-probe','frontend_probe':'frontend-probe','native_pack':'native-pack-probe'}[name]
  macro_cmd=[*flags,'-E','-dM',str(file)]
  macros=subprocess.run(macro_cmd,cwd=directory,capture_output=True,text=True)
  if macros.returncode:raise RuntimeError(macros.stderr)
  if re.search(r'^#define NDEBUG(?:\s|$)',macros.stdout,re.M):raise ValueError('Probe assertions must be enabled after all actual headers/configuration')
  macro_file=out/(name+'-macros.txt');macro_file.write_text(macros.stdout)
  cmd=[*flags,str(file),*[str(x) for x in libs],*['-Wl,-rpath,'+str(x.parent) for x in libs],'-o',str(binary)]
  r=subprocess.run(cmd,cwd=directory,capture_output=True,text=True)
  results.append({'argv':cmd,'cwd':str(directory),'exit_code':r.returncode,'stderr':r.stderr,'source_sha256':sha(file),'preprocessor':{'argv':macro_cmd,'path':str(macro_file),'sha256':sha(macro_file),'assertions_enabled':True},'binary':str(binary),'binary_sha256':sha(binary) if r.returncode==0 else None})
  if r.returncode:raise RuntimeError(r.stderr)
 receipt={'compile_commands':{'path':str(commands),'sha256':sha(commands)},'compile_unit':u,'source':{'path':str(target),'sha256':sha(target)},'libraries':{str(x):sha(x) for x in libs},'commands':results}
 (out/'c-build.json').write_text(json.dumps(receipt,indent=2)+'\n')
 print(json.dumps({'status':'compiled-actual-normal-library-probes','output':str(out)}))
if __name__=='__main__':main()
