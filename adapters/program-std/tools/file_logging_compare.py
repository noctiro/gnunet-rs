#!/usr/bin/env python3
"""Normal public log_setup filesystem failures versus actual native Rust owner.
Every actual timestamp/PID/source location is checked separately; only the
compiler-dependent __FILE__ field is projected after exact profile validation.
"""
import argparse,json,os,re,shutil,subprocess,time
from pathlib import Path
from _common import sha,require_disjoint_output
from normal_reference import load,compile_probe
from logging_compare import date_boundary
BASE=Path(__file__).resolve().parents[1]
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def canonical(data,pid,before,after,cfile):
 rows=[];dates=[]
 for line in data.splitlines():
  if line==b'PID '+str(pid).encode():rows.append(['PID','actual']);continue
  if line.startswith(b'R '):
   kind,component,date,body=line[2:].split(b' ',3);component=bytes.fromhex(component.decode());date=bytes.fromhex(date.decode());body=bytes.fromhex(body.decode());stem,actual=component.rsplit(b'-',1)
   if actual!=str(pid).encode()or stem not in[b'owned-errors',b'util-disk']:raise ValueError('actual source component/PID mismatch')
   dates.append(date_boundary(date,before,after))
   match=re.search(rb" at ([^\n]*):([0-9]+) with error: ",body)
   if match:
    filename,number=match.groups();basename=Path(os.fsdecode(filename)).name.encode();expected=(cfile.get(basename)if cfile is not None else basename)
    if filename!=expected or (basename,number)not in[(b'common_logging.c',b'418'),(b'disk.c',b'478'),(b'disk.c',b'498'),(b'disk.c',b'649')]:raise ValueError(('actual compile-profile diagnostic location mismatch',filename,number,expected))
    body=body[:match.start(1)]+b'<actual bound '+basename+b'>'+body[match.end(1):]
   rows.append(['R',int(kind),stem.decode(),body.hex()])
  else:rows.append(line.decode())
 return rows,dates

def main():
 p=argparse.ArgumentParser()
 for key in['repo','source','reference','rust','output']:p.add_argument('--'+key,type=Path,required=True)
 a=p.parse_args();r,normal=load(a.reference,a.source,a.repo);out=require_disjoint_output(a.output,[BASE,a.repo,a.source,a.reference.resolve().parent,Path(r['build']),Path(r['prefix'])]);out.mkdir(parents=True);protected=[Path(__file__),BASE/'tools/logging_compare.py',BASE/'reference/file_logging.c',*list((BASE/'src').rglob('*.rs')),a.rust];inputs={str(v.resolve()):sha(v)for v in protected};c=out/'normal-file-logging';compiled=compile_probe(BASE/'reference/file_logging.c',c,r);save(out/'compile.json',compiled);csha=sha(c)
 compile_db=json.loads(Path(r['compile_commands']['path']).read_text());rows=[v for v in compile_db if v['file'].endswith('/common_logging.c')]
 if len(rows)!=1:raise ValueError('normal logging translation unit ambiguous')
 cfile={name.encode():os.fsencode(next(row['file']for row in compile_db if row['file'].endswith('/'+name)))for name in ['common_logging.c','disk.c']};env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_','OWNED_'))and k not in['JOURNAL_STREAM','DYLD_INSERT_LIBRARIES','DYLD_FORCE_FLAT_NAMESPACE','LD_PRELOAD']};env.update(r['runtime_environment']);env['LC_ALL']='C';observed=[];result={'status':'not-run'}
 try:
  profiles=[(mode,level,None)for mode in ['directory','blocked','cached','recover','append','rotate']for level in ['NONE','ERROR','DEBUG']]+[('blocked','DEBUG',';disk[.]c$;GNUNET_DISK_directory_test;485;INFO/;;;;NONE'),('blocked','DEBUG',';disk[.]c$;GNUNET_DISK_directory_create;606;ERROR/;;;;NONE'),('long-parent','DEBUG',None)]
  for index,(mode,level,force)in enumerate(profiles):
    current=env.copy()
    if force is not None:current['GNUNET_FORCE_LOG']=force
    directory=out/(str(index)+'-'+mode+'-'+level);directory.mkdir();fixture=directory/'owned';actors=[];extra=None
    for label,binary in[('c',c),('rust',a.rust)]:
     if fixture.exists():shutil.rmtree(fixture)
     fixture.mkdir();parent=fixture/'parent';file=parent/'log'
     if mode=='directory':parent.mkdir();file.mkdir()
     elif mode=='append':parent.mkdir();file.write_bytes(b'PREFIX\n')
     elif mode=='rotate':parent.mkdir()
     elif mode=='long-parent':parent=fixture/('p'*256);file=parent/'log'
     else:parent.write_bytes(b'ordinary owned file')
     started=time.time_ns()//1000;child=subprocess.Popen([str(binary),mode,level,str(file),str(parent)]+([str(extra)]if label=='rust'else[]),env=current,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE);stdout,stderr=child.communicate(timeout=4);ended=time.time_ns()//1000;(directory/(label+'.stdout')).write_bytes(stdout);(directory/(label+'.stderr')).write_bytes(stderr)
     if child.returncode:raise ValueError(('actual process failure',mode,level,label,child.returncode,stderr))
     stable,dates=canonical(stdout,child.pid,started,ended,cfile if label=='c'else None)
     if label=='c':
      profiles=re.findall(rb'^PROFILE ([0-9]+)$',stdout,re.M)
      if len(profiles)!=1:raise ValueError('actual C extra profile missing')
      extra=int(profiles[0])
     files={str(v.relative_to(fixture)):v.read_bytes().hex()for v in fixture.rglob('*')if v.is_file()};
     if mode=='rotate'and set(files)!={'parent/log.'+str(i)for i in range(2,6)}:raise ValueError('actual rotation did not keep three previous and one current file')
     actors.append({'actor':label,'events':stable,'dates':dates,'stderr_hex':stderr.hex(),'files':files});
    equal=all(actors[0][key]==actors[1][key]for key in['events','stderr_hex','files']);observed.append({'mode':mode,'level':level,'force_policy':force,'matched':equal,'actors':actors});save(out/'progress.json',observed)
    if not equal:raise ValueError(('normal file diagnostic mismatch',mode,level))
  _,after=load(a.reference,a.source,a.repo)
  if normal!=after or inputs!={str(v.resolve()):sha(v)for v in protected}or sha(c)!=csha:raise ValueError('actual input changed')
  result={'status':'passed','profiles':len(observed),'scope':'normal unchanged public log_setup directory/open failures and source cached failure, physical stderr recovery and append; actual PID/time/source filename fields validated; only bound compiler __FILE__ projection differs','rows':observed,'inputs':inputs,'normal_inputs':normal,'compiled':compiled,'normal_log_source_files':{key.decode():os.fsdecode(value)for key,value in cfile.items()},'inputs_unchanged':True}
 except Exception as e:result={'status':'failed','error':str(e),'rows':observed};raise
 finally:save(out/'result.json',result)
 print(json.dumps({'status':result['status'],'profiles':len(observed)}))
if __name__=='__main__':main()
