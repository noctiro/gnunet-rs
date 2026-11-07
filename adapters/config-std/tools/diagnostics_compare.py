#!/usr/bin/env python3
"""Defined-safe normal public CONFIG diagnostics versus synchronous Rust events.
No relative-time/base32 malformed inputs, C NULL format operands or fault signals.
All paths and files are descendants of a fresh caller-selected output directory.
"""
import argparse,json,os,re,shutil,subprocess,time
from pathlib import Path
from _common import sha,require_disjoint_output,source_files
from normal_reference import load,compile_probe
from logging_compare import date_boundary
BASE=Path(__file__).resolve().parents[1]
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def snapshot(base):
 return {str(path.resolve()):sha(path)for path in source_files(base,{'target','.git'})}

def render(template,args):
 values=[]
 for arg in args:
  if arg.startswith(b'b'):values.append(bytes.fromhex(arg[1:].decode()))
  elif arg[:1]in[b'u',b'i']:values.append(int(arg[1:]))
  elif arg.startswith(b'e'):values.append(os.strerror(int(arg[1:])).encode())
  else:raise ValueError('unsupported/undefined native format operand: '+repr(arg))
 output=bytearray();position=0;last=0
 for match in re.finditer(rb'%([sud%])',template):
  output.extend(template[last:match.start()]);kind=match[1]
  if kind==b'%':output.extend(b'%')
  else:
   value=values[position];position+=1
   if kind==b's':
    if not isinstance(value,bytes):raise ValueError('source string operand mismatch')
    output.extend(value.split(b'\0')[0])
   else:output.extend(str(value).encode())
  last=match.end()
 output.extend(template[last:])
 if b'%'in re.sub(rb'%[sud%]',b'',template)or position!=len(values):raise ValueError('unreviewed source format')
 return bytes(output)
def canonical(stdout,label,pid,before,after,source_files,extra):
 rows=[];dates=[];sites=[]
 for line in stdout.splitlines():
  if line==b'PID '+str(pid).encode()or re.fullmatch(rb'PROFILE [0-9]+',line):continue
  if line.startswith(b'R '):
   kind,component,date,body=line[2:].split(b' ',3);component=bytes.fromhex(component.decode());date=bytes.fromhex(date.decode());body=bytes.fromhex(body.decode());stem,actual=component.rsplit(b'-',1)
   if actual!=str(pid).encode():raise ValueError('native component PID mismatch')
   dates.append(date_boundary(date,before,after));kind=int(kind)
   loc=re.search(rb' at ([^\n]+):([0-9]+) with error: ',body)
   if loc:
    original=loc[1];basename=Path(os.fsdecode(original)).name.encode()
    if source_files.get(basename)!=original:raise ValueError('native __FILE__ differs from real compile database')
    body=body[:loc.start(1)]+basename+body[loc.end(1):]
   loc=re.search(rb'Assertion failed at ([^\n]+):([0-9]+)\.\n',body)
   if loc:
    original=loc[1];basename=Path(os.fsdecode(original)).name.encode()
    if source_files.get(basename)!=original or loc[2]not in[b'3298',b'2345']:raise ValueError('native assertion filename/line differs from repeated-load profile')
    body=body[:loc.start(1)]+basename+body[loc.end(1):]
   rows.append(['R',kind,stem.hex(),body.hex()])
  elif line.startswith(b'E '):
   kind,component,file,function,number,template,*arguments=line[2:].split(b' ');kind=int(kind);sites.append({'file_hex':file.decode(),'function_hex':function.decode(),'line':int(number),'template_hex':template.decode(),'args':[a.decode()for a in arguments]})
   if kind==16 and not extra:continue
   body=render(bytes.fromhex(template.decode()),arguments);stem=b'owned-config'if component==b'-'else bytes.fromhex(component.decode());rows.append(['R',kind,stem.hex(),body.hex()])
  else:rows.append(line.decode())
 return rows,dates,sites

def main():
 p=argparse.ArgumentParser()
 for key in['repo','source','reference','rust','output']:p.add_argument('--'+key,type=Path,required=True)
 a=p.parse_args();r,normal=load(a.reference,a.source,a.repo);out=require_disjoint_output(a.output,[BASE,a.repo,a.source,a.reference.resolve().parent,Path(r['build']),Path(r['prefix'])]);out.mkdir(parents=True)
 result={'status':'not-run'};observed=[]
 try:
  inputs=snapshot(BASE);inputs[str(a.rust.resolve())]=sha(a.rust);c=out/'normal-config-diagnostics';compiled=compile_probe(BASE/'reference/diagnostics.c',c,r);save(out/'compile.json',compiled);csha=sha(c);rust=out/'rust-config-diagnostics';shutil.copy2(a.rust,rust);rustsha=sha(rust)
  db=json.loads(Path(r['compile_commands']['path']).read_text());files={}
  for name in['configuration.c','disk.c']:
   rows=[v for v in db if v['file'].endswith('/'+name)]
   if len(rows)!=1:raise ValueError('native TU ambiguous')
   files[name.encode()]=os.fsencode(rows[0]['file'])
  env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_','OWNED_'))and k not in['JOURNAL_STREAM','DYLD_INSERT_LIBRARIES','DYLD_FORCE_FLAT_NAMESPACE','LD_PRELOAD']};env.update(r['runtime_environment']);env['LC_ALL']='C';home=out/'home';home.mkdir();defaults=out/'base';defaults.mkdir();env.update(HOME=str(home),XDG_CONFIG_HOME=str(home),GNUNET_BASE_CONFIG=str(defaults))
  cases=[('no-section','deserialize','key=value\n','-'),('bad-line','deserialize','[own]\nbroken\n','-'),('bad-directive','deserialize','@INLINE file\n','-'),('unknown-directive','deserialize','@NOPE@ value\n','-'),('bad-secret','deserialize','@INLINE-SECRET@ only\n','-'),('inline-no-source','deserialize','@INLINE@ owned.conf\n','-'),('choice','choice','perhaps','-'),('filename','filename','-','-'),('dollar-default','dollar','${OWNED_CONFIG_UNSET_XYZ:-fallback}/tail','-'),('dollar-brace','dollar','${OWNED_CONFIG_UNSET_XYZ','-')]
  cases += [(name,mode,None,option)for name,mode,option in [('valid','parse','-'),('nested-bad','parse','-'),('direct-cycle','parse','-'),('indirect-cycle','parse','-'),('glob','parse','-'),('secret-absent','parse','-'),('secret-restricted','parse','-'),('secret-get','secret-get','-'),('missing','parse','-'),('directory','parse','-'),('sorted-skips','from','-'),('load-bad','load','-'),('load-repeat','load-repeat','-'),('diff-project','diff-project','-'),('clean-not-parsed','clean','not-parsed'),('clean-changed','clean','changed'),('clean-unlinked','clean','unlinked'),('write-blocked','write','-'),('write-directory','write','-'),('write-create','write','-')]]
  for name,mode,text,option in cases:
   directory=out/name;directory.mkdir();fixture=directory/'owned';actors=[];extra=None
   for label,binary in[('c',c),('rust',rust)]:
    if fixture.exists():shutil.rmtree(fixture)
    fixture.mkdir();path=fixture/'main.conf'
    if text is not None:value=text
    else:
     path.write_bytes(b'[own]\nkey=value\n');value=str(path)
     if name=='nested-bad':path.write_bytes(b'@INLINE@ child.conf\n');(fixture/'child.conf').write_bytes(b'[own]\nbroken\n')
     elif name=='direct-cycle':path.write_bytes(b'@INLINE@ main.conf\n')
     elif name=='indirect-cycle':path.write_bytes(b'@INLINE@ child.conf\n');(fixture/'child.conf').write_bytes(b'@INLINE@ main.conf\n')
     elif name=='glob':path.write_bytes(b'@INLINE-MATCHING@ fragment*.conf\n');(fixture/'fragment01.conf').write_bytes(b'[own]\na=one\n');(fixture/'fragment02.conf').write_bytes(b'[own]\nbroken\n')
     elif name=='secret-absent':path.write_bytes(b'@INLINE-SECRET@ secret child.conf\n');(fixture/'child.conf').write_bytes(b'[other]\nkey=value\n')
     elif name=='secret-restricted':path.write_bytes(b'@INLINE-SECRET@ secret child.conf\n');(fixture/'child.conf').write_bytes(b'@INLINE@ other.conf\n')
     elif name=='secret-get':path.write_bytes(b'@INLINE-SECRET@ secret absent.conf\n')
     elif name=='missing':path.unlink()
     elif name=='directory':path.unlink();path.mkdir()
     elif name=='sorted-skips':path.unlink();path=fixture;value=str(path);(fixture/'01.conf').write_bytes(b'[own]\na=one\n');(fixture/'02.ignore').write_bytes(b'ignored\n');(fixture/'03.conf').write_bytes(b'[own]\na=two\n')
     elif name=='load-bad':path.write_bytes(b'@UNKNOWN@ whatever\n')
     elif name=='write-blocked':path.unlink();(fixture/'parent').write_bytes(b'owned ordinary file');value=str(fixture/'parent'/'out.conf')
     elif name=='write-directory':path.unlink();path.mkdir()
     elif name=='write-create':path.unlink();value=str(fixture/'fresh'/'other'/'out.conf')
    before=time.time_ns()//1000;child=subprocess.Popen([str(binary),mode,value,option],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE);stdout,stderr=child.communicate(timeout=5);after=time.time_ns()//1000;(directory/(label+'.stdout')).write_bytes(stdout);(directory/(label+'.stderr')).write_bytes(stderr)
    if child.returncode:raise ValueError(('participant failure',name,label,child.returncode,stderr))
    if label=='c':
     profiles=re.findall(rb'^PROFILE ([0-9]+)$',stdout,re.M)
     if len(profiles)!=1:raise ValueError('native profile missing')
     extra=int(profiles[0])
    stable,dates,sites=canonical(stdout,label,child.pid,before,after,files,extra);actors.append({'actor':label,'events':stable,'dates':dates,'sites':sites,'stderr_hex':stderr.hex()})
   equal=actors[0]['events']==actors[1]['events']and actors[0]['stderr_hex']==actors[1]['stderr_hex'];observed.append({'name':name,'mode':mode,'matched':equal,'actors':actors});save(out/'progress.json',observed)
   if not equal:raise ValueError(('actual diagnostics mismatch',name))
  _,after=load(a.reference,a.source,a.repo);current=snapshot(BASE);current[str(a.rust.resolve())]=sha(a.rust)
  if inputs!=current or normal!=after or sha(c)!=csha or sha(rust)!=rustsha:raise ValueError('actual source/participant changed')
  result={'status':'passed','profiles':len(observed),'scope':'normal unchanged public CONFIG diagnostics and actual Rust synchronous events; severity/component/message/order/status; actual C PID/time/native __FILE__ individually validated; no PROGRAM composition credit','rows':observed,'inputs':inputs,'normal_inputs':normal,'compiled':compiled,'rust':{'path':str(rust),'sha256':rustsha},'inputs_unchanged':True}
 except Exception as e:result={'status':'failed','error':str(e),'rows':observed};raise
 finally:save(out/'result.json',result)
 print(json.dumps({'status':result['status'],'profiles':len(observed)}))
if __name__=='__main__':main()
