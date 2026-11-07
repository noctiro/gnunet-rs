#!/usr/bin/env python3
"""Original fixed C TUs compiled with ENABLE_NLS=1 vs actual Rust PROGRAM.
This is a declared enabled-NLS source-component profile, separate from the
unchanged normal Meson library's NLS0 evidence. No source/library is rewritten.
"""
import argparse,json,os,re,shlex,shutil,subprocess,time
from pathlib import Path
from _common import sha,require_disjoint_output
from normal_reference import load,compile_probe
from logging_compare import DATE,date_boundary
from native_gettext_compare import po
BASE=Path(__file__).resolve().parents[1]
TUS=['program.c','getopt.c','getopt_helpers.c','common_logging.c','speedup.c','configuration.c','disk.c','strings.c']
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def flags(row):
 argv=row.get('arguments')or shlex.split(row['command']);result=[];i=1
 while i<len(argv):
  v=argv[i]
  if v in['-o','-MQ','-MF','-MT']:i+=2;continue
  if v in['-c','-MD','-MMD']or v==row['file']:i+=1;continue
  result.append(v);i+=1
 return argv[0],result

def po_extra():
 messages={"Use %s to get a list of options.\n":"FR utilisez %s café\n","%s: unrecognized option `--%s'\n":"FR %s option inconnue <%s> café\n","%s: invalid option -- %c\n":"FR %s option inconnue %c café\n","You must pass a number to the `%s' option.\n":"FR nombre requis pour <%s> café\n","Your input for the '%s' option has to be a non negative number\n":"FR nombre positif pour <%s> café\n","Owned number":"Nombre café","print this help":"Aide café","print the version number":"Version café","configure logging to use LOGLEVEL":"Niveau café","configure logging to write logs to FILENAME":"Fichier journal café","use configuration file FILENAME":"Configuration café","Arguments mandatory for long options are also mandatory for short options.\n":"Arguments longs et courts obligatoires café.\n","Unreadable configuration file `%s', exiting ...\n":"FR fichier illisible <%s> café\n","Failed to parse configuration file `%s'\n":"FR configuration analyse impossible <%s> café\n","Malformed configuration file `%s', exiting ...\n":"FR configuration incorrecte <%s> café\n", "Failed to expand `$HOME': environment variable `HOME' not set":"FR HOME absent café", "Configuration value '%s' for '%s' in section '%s' is not in set of legal choices\n":"FR valeur <%s> pour <%s> section <%s> invalide café\n", "`%s' failed on file `%s' at %s:%d with error: %s\n":"FR <%s> fichier <%s> at %s:%d with error: %s café\n"}
 def quote(v):return '"'+v.replace('\\','\\\\').replace('"','\\"').replace('\n','\\n')+'"'
 data=po('gnunet').decode('latin1')
 for source,target in messages.items():data+='\nmsgid '+quote(source)+'\nmsgstr '+quote(target)+'\n'
 return data.encode('latin1')
def stderr_projection(data,pid,before,after,sourcefile=None,logical_offset=0):
 lines=[];dates=[]
 for line in data.splitlines(keepends=True):
  location=re.search(rb' at ([^\n]*):([0-9]+) with error: ',line)
  if location:
   actual,number=location.groups();expected=os.fsencode(sourcefile)if sourcefile is not None else b'common_logging.c'
   if actual!=expected or number!=b'418':raise ValueError(('source filename/line outside bound open profile',actual,number,expected))
   line=line[:location.start(1)]+b'<actual bound common_logging.c>'+line[location.end(1):]

  match=re.match(DATE+rb' (owned|util|util-disk|util-strings|util-program|util-speedup)-([0-9]+) ',line)
  if match:
   date=line[:match.end(5)];shift=logical_offset if line[match.end():].startswith((b'DEBUG Speeding up execution time by ',b'DEBUG Stopped execution speed up'))else 0;actual=date_boundary(date,before+shift,after+shift);actual['actual_source_logical_offset']=shift;dates.append(actual)
   if match[7]!=str(pid).encode():raise ValueError('actual standard logger PID mismatch')
   lines.append(b'<actual-bound-native-date> '+match[6]+b'-<actual-pid> '+line[match.end():])
  else:lines.append(line)
 return b''.join(lines),dates

def main():
 p=argparse.ArgumentParser()
 for key in['repo','source','reference','rust','library','include','output']:p.add_argument('--'+key,type=Path,required=True)
 p.add_argument('--msgfmt',default='msgfmt');p.add_argument('--nls0',action='store_true');a=p.parse_args();r,normal=load(a.reference,a.source,a.repo);library=a.library.resolve(strict=True);header=(a.include/'libintl.h').resolve(strict=True);msgfmt=Path(shutil.which(a.msgfmt)or a.msgfmt).resolve(strict=True);ninja=Path(r['build'])/'build.ninja';edges=[line for line in ninja.read_text().splitlines()if line.startswith('build src/lib/util/libgnunetutil.')and ': c_LINKER 'in line];dependencies=[Path(v)for line in edges for v in shlex.split(line.split(' | ',1)[1])if '/libunistring' in v and not v.endswith('.a')];
 if len(dependencies)!=1:raise ValueError('actual normal util Unicode dependency missing/ambiguous')
 unistring=dependencies[0].resolve(strict=True);out=require_disjoint_output(a.output,[BASE,a.repo,a.source,Path(r['build']),Path(r['prefix']),a.reference.resolve().parent,library.parent,a.include,a.rust.parent]);out.mkdir(parents=True);protected=[Path(__file__),BASE/'tools/native_gettext_compare.py',BASE/'tools/logging_compare.py',BASE/'tools/normal_reference.py',BASE/'reference/program_nls.c',*list((BASE/'src').rglob('*.rs')),library,header,msgfmt,unistring,ninja,a.rust,*[a.source/'src/lib/util'/name for name in TUS]];inputs={str(v.resolve()):sha(v)for v in protected};save(out/'inputs-before.json',inputs);db=json.loads(Path(r['compile_commands']['path']).read_text());common_files=[v['file']for v in db if v['file'].endswith('/common_logging.c')];
 if len(common_files)!=1:raise ValueError('normal logging file missing/ambiguous')
 cfile=common_files[0];objects=[];commands=[];env=os.environ.copy();rust=out/'rust-program-nls';shutil.copyfile(a.rust,rust);rust.chmod(0o700)
 if a.nls0:
  c=out/'c-program-nls0';compiled=compile_probe(BASE/'reference/program_nls.c',c,r);commands.append(compiled);save(out/'compile.json',commands)
 else:
  for name in TUS:
   selected=[v for v in db if v['file'].endswith('/'+name)]
   if len(selected)!=1:raise ValueError('original source compile TU missing/ambiguous '+name)
   row=selected[0];cc,options=flags(row);obj=out/(name+'.o');argv=[cc,'-I'+str(a.include),*options,'-DENABLE_NLS=1','-DPACKAGE="gnunet"','-c',row['file'],'-o',str(obj)];compiled=subprocess.run(argv,cwd=row['directory'],capture_output=True,timeout=30);(out/(name+'.compile.stdout')).write_bytes(compiled.stdout);(out/(name+'.compile.stderr')).write_bytes(compiled.stderr);commands.append({'argv':argv,'cwd':row['directory'],'exit':compiled.returncode,'source':str(a.source/'src/lib/util'/name),'source_sha256':sha(a.source/'src/lib/util'/name)})
   if compiled.returncode:raise ValueError('original NLS1 component failed compile '+name)
   objects.append(obj)
  cc,options=flags(next(v for v in db if v['file'].endswith('/arm_api.c')));c=out/'c-program-nls';prefix=Path(r['prefix']);argv=[cc,'-I'+str(a.include),*options,'-DENABLE_NLS=1','-DPACKAGE="gnunet"',str(BASE/'reference/program_nls.c'),*map(str,objects),str(library),str(unistring),'-L'+str(prefix/'lib'),'-lgnunetarm','-lgnunetutil','-Wl,-rpath,'+str(prefix/'lib'),'-o',str(c)];cwd=next(v['directory']for v in db if v['file'].endswith('/arm_api.c'));linked=subprocess.run(argv,cwd=cwd,capture_output=True,timeout=30);(out/'link.stdout').write_bytes(linked.stdout);(out/'link.stderr').write_bytes(linked.stderr);commands.append({'argv':argv,'cwd':cwd,'exit':linked.returncode});save(out/'compile.json',commands)
  if linked.returncode:raise ValueError('actual original component link failed')
 catalog=out/'catalogs'/'fr'/'LC_MESSAGES';catalog.mkdir(parents=True);source=out/'gnunet.po';source.write_bytes(po_extra());compiled=subprocess.run([str(msgfmt),'--check','-o',str(catalog/'gnunet.mo'),str(source)],capture_output=True,timeout=10);(out/'msgfmt.stderr').write_bytes(compiled.stderr)
 if compiled.returncode:raise ValueError('actual source-component catalog compile failed')
 base=out/'empty-base';base.mkdir();env={k:v for k,v in env.items()if not k.startswith(('GNUNET_','LISTEN_','OWNED_','DYLD_','LD_'))and k not in['LANG','LANGUAGE','LC_ALL','LC_MESSAGES','OUTPUT_CHARSET','POSIXLY_CORRECT']};env.update(r['runtime_environment']);env.update(LC_ALL='en_US.UTF-8',LANGUAGE='fr',GNUNET_BASE_CONFIG=str(base),OWNED_NLS_DIRECTORY=str(out/'catalogs'),OWNED_NLS_LIBRARY=str(library),OWNED_CONFIG_MARKER='owned-program-nls-never-'+str(os.getpid()));actors={str(c):sha(c),str(rust):sha(rust)};rows=[];result={'status':'not-run'}
 if a.nls0:env['OWNED_NLS_DISABLED']='1'
 profiles=[('help',['--help']),('unknown',['--unknown']),('numeric-error',['-u','12x']),('negative-uint',['-u','-1']),('exclusive-help',['-u','7','--help']),('valid-version',['--version']),('main',['-c','@CONFIG','-L','ERROR']),('missing-config',['-c','@MISSING','-L','ERROR']),('parse-bad',['-c','@CONFIG','-L','DEBUG']),('nested-bad',['-c','@CONFIG','-L','DEBUG']),('secret-restricted',['-c','@CONFIG','-L','DEBUG']),('glob-bad',['-c','@CONFIG','-L','DEBUG']),('home-helper-missing',['-c','~/owned-helper-never','-L','ERROR']),('logfile-append',['-c','@CONFIG','-L','ERROR','-l','@LOGFILE']),('logfile-directory',['-c','@CONFIG','-L','ERROR','-l','@LOGFILE']),('logfile-parent-file',['-c','@CONFIG','-L','ERROR','-l','@LOGFILE']),('force-logfile-home-missing',['-c','@CONFIG','-L','WARNING']),('typed-choice',['-c','@CONFIG','-L','ERROR']),('scheduled-speedup',['-c','@CONFIG','-L','ERROR']),('inaccessible-testing-arm',['-c','@CONFIG','-L','WARNING'])]
 try:
  for name,args in profiles:
   directory=out/name;directory.mkdir();home=directory/'home';home.mkdir();fixture=directory/'owned';fixture.mkdir();config=fixture/'owned.conf';config.write_bytes(b'[owned]\nvalue = yes\n');missing=fixture/'does-not-exist.conf';
   if name=='inaccessible-testing-arm':config.write_bytes(b'@INLINE-SECRET@ testing missing-testing.conf\n@INLINE-SECRET@ arm missing-arm.conf\n')
   if name=='scheduled-speedup':config.write_bytes(b'[testing]\nSPEEDUP_INTERVAL=10001us\nSPEEDUP_DELTA=2s\n')
   if name=='typed-choice':config.write_bytes(b'[owned]\nvalue=maybe\n')
   if name=='parse-bad':config.write_bytes(b'[owned]\nbroken\n')
   elif name=='nested-bad':config.write_bytes(b'@INLINE@ child.conf\n');(fixture/'child.conf').write_bytes(b'[owned]\nbroken\n')
   elif name=='secret-restricted':config.write_bytes(b'@INLINE-SECRET@ owned child.conf\n');(fixture/'child.conf').write_bytes(b'@INLINE@ other.conf\n')
   elif name=='glob-bad':config.write_bytes(b'@INLINE-MATCHING@ fragment*.conf\n');(fixture/'fragment01.conf').write_bytes(b'[owned]\na=accepted\n');(fixture/'fragment02.conf').write_bytes(b'[owned]\nbroken\n')
   logfile=fixture/'logfile';
   if name=='logfile-directory':logfile.mkdir()
   elif name=='logfile-parent-file':(fixture/'parent').write_bytes(b'owned ordinary file');logfile=fixture/'parent'/'log'
   args=[str(config)if v=='@CONFIG'else str(missing)if v=='@MISSING'else str(logfile)if v=='@LOGFILE'else v for v in args];current=env.copy();current.update(HOME=str(home),XDG_CONFIG_HOME=str(directory/'xdg'));observed=[]
   if name=='home-helper-missing':current.pop('HOME',None);current.pop('XDG_CONFIG_HOME',None);current['OWNED_PRELOG']='1'
   if name=='force-logfile-home-missing':current.pop('HOME',None);current.pop('XDG_CONFIG_HOME',None);current['GNUNET_FORCE_LOGFILE']='~/owned-force-logfile-never'
   if name=='typed-choice':current['OWNED_TASK_CHOICE']='1'
   if name=='scheduled-speedup':current['OWNED_SCHEDULED']='1';current['GNUNET_FORCE_LOG']='util-speedup;;;;DEBUG/;;;;ERROR'

   for label,binary in[('c',c),('rust',rust)]:
    if name=='logfile-append':logfile.write_bytes(b'PREFIX\n')
    started=time.time_ns()//1000;child=subprocess.Popen([b'owned-nls']+list(map(os.fsencode,args)),executable=os.fsencode(binary),cwd=directory,env=current,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE);stdout,stderr=child.communicate(timeout=4);ended=time.time_ns()//1000;(directory/(label+'.stdout')).write_bytes(stdout);(directory/(label+'.stderr')).write_bytes(stderr)
    if child.returncode:raise ValueError(('actual enabled component failed',name,label,child.returncode,stderr))
    logical_offset=0
    if name=='scheduled-speedup':
     offsets=re.findall(rb'^OFFSET (-?[0-9]+)$',stdout,re.M)
     if offsets!=[b'2000000']:raise ValueError(('actual scheduled source offset missing',label,offsets))
     logical_offset=int(offsets[0])
    projected,dates=stderr_projection(stderr,child.pid,started,ended,cfile if label=='c'else None,logical_offset);file_projection=b'';file_dates=[]
    if name=='logfile-append':
     raw=logfile.read_bytes();(directory/(label+'.logfile')).write_bytes(raw);file_projection,file_dates=stderr_projection(raw,child.pid,started,ended)
     if not raw.startswith(b'PREFIX\n')or b'owner data%name'not in file_projection:raise ValueError('actual append owner route missing')
    observed.append({'actor':label,'stdout_hex':stdout.hex(),'stderr_projected_hex':projected.hex(),'actual_dates':dates,'file_projected_hex':file_projection.hex(),'actual_file_dates':file_dates})
   equal=all(observed[0][k]==observed[1][k]for k in['stdout_hex','stderr_projected_hex','file_projected_hex']);rows.append({'name':name,'matched':equal,'observed':observed});save(out/'progress.json',rows)
   if not equal:raise ValueError(('actual NLS1 source component mismatch',name))
   joined=bytes.fromhex(observed[0]['stdout_hex'])+bytes.fromhex(observed[0]['stderr_projected_hex'])+bytes.fromhex(observed[0]['file_projected_hex'])
   if not a.nls0 and name not in ['valid-version','logfile-directory','logfile-parent-file']and b'caf\xc3\xa9'not in joined:raise ValueError('actual translated route not exercised '+name)
  _,after=load(a.reference,a.source,a.repo)
  if normal!=after or inputs!={str(v.resolve()):sha(v)for v in protected}or actors!={v:sha(Path(v))for v in actors}:raise ValueError('actual source/library/actor changed')
  result={'status':'passed','scope':('Unchanged normal GNUnet public PROGRAM library NLS0; Rust actual same parser/config/logging/file/helper/direct-main routes'if a.nls0 else'Original fixed official PROGRAM/GETOPT/common_logging/speedup/CONFIG/DISK/STRINGS TUs compiled ENABLE_NLS=1, actual standard gettext backend; separate enabled source-component profile, not unchanged normal NLS0-library credit'),'profiles':len(rows),'rows':rows,'commands':commands,'inputs':inputs,'actors':actors,'normal_inputs':normal,'inputs_unchanged':True,'normal_GNUnet_NLS0_credit':a.nls0,'undefined_C_time_base32_or_format_executed':False}
 except Exception as e:result={'status':'failed','error':str(e),'rows':rows,'commands':commands};raise
 finally:save(out/'result.json',result)
 print(json.dumps({'status':result['status'],'profiles':len(rows),'normal_GNUnet_NLS0_credit':a.nls0}))
if __name__=='__main__':main()
