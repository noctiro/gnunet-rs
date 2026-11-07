#!/usr/bin/env python3
"""Explicit standard gettext backend comparison, not NLS0 GNUnet evidence.
Compiler/header/library/msgfmt and actual actors are bound before/after. All
catalogs, environments and children are owned by this fresh output directory.
No malformed C format is executed: unsafe translation is observed only as data.
"""
import argparse,json,os,re,shutil,subprocess
from pathlib import Path
from _common import sha,require_disjoint_output
BASE=Path(__file__).resolve().parents[1]
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def po(domain):
 values=[('', 'Content-Type: text/plain; charset=ISO-8859-1\nPlural-Forms: nplurals=2; plural=(n > 1);\n'),('Owned help',('PROJET'if domain=='owned-project'else'GN')+' café'),('ERROR','ERREUR café'),("Option `%s' can't be used with other options.\n",'FR option <%s> café\n'),("Message `%.*s' repeated %u times in the last %s\n",'FR <%.*s> %u fois %s café\n'),('unsafe source %s','DATA %n café')]
 def quote(v):return '"'+v.replace('\\','\\\\').replace('"','\\"').replace('\n','\\n')+'"'
 result=[]
 for source,target in values:result.extend(['msgid '+quote(source),'msgstr '+quote(target),''])
 result.extend(['msgid "one item"','msgid_plural "many items"','msgstr[0] "un objet café"','msgstr[1] "plusieurs objets café"','']);return '\n'.join(result).encode('latin1')
def main():
 p=argparse.ArgumentParser()
 for key in['repo','rust','library','include','output']:p.add_argument('--'+key,type=Path,required=True)
 p.add_argument('--abi',choices=['libintl','libc'],default='libintl');p.add_argument('--cc',default='cc');p.add_argument('--msgfmt',default='msgfmt');a=p.parse_args();library=a.library.resolve(strict=True);header=(a.include/'libintl.h').resolve(strict=True);cc=Path(shutil.which(a.cc)or a.cc).resolve(strict=True);msgfmt=Path(shutil.which(a.msgfmt)or a.msgfmt).resolve(strict=True);out=require_disjoint_output(a.output,[BASE,a.repo,library.parent,a.include,a.rust.parent]);out.mkdir(parents=True);protected=[Path(__file__),BASE/'tools/_common.py',BASE/'reference/native_gettext.c',*list((BASE/'src').rglob('*.rs')),BASE/'Cargo.toml',BASE/'Cargo.lock',library,header,cc,msgfmt,a.rust];inputs={str(v.resolve()):sha(v)for v in protected};save(out/'inputs-before.json',inputs);rust=out/'rust-native-gettext';shutil.copyfile(a.rust,rust);rust.chmod(0o700);c=out/'c-native-gettext';command=[str(cc),'-std=c11','-O2','-Wall','-Wextra','-I'+str(a.include),str(BASE/'reference/native_gettext.c'),str(library),'-o',str(c)];compiled=subprocess.run(command,capture_output=True,timeout=30);(out/'compile.stdout').write_bytes(compiled.stdout);(out/'compile.stderr').write_bytes(compiled.stderr);save(out/'compile.json',{'argv':command,'exit':compiled.returncode});
 if compiled.returncode:raise ValueError('actual standard backend caller did not compile')
 catalogs=out/'catalogs';language=catalogs/'fr'/'LC_MESSAGES';language.mkdir(parents=True)
 for domain in['gnunet','owned-project']:
  source=out/(domain+'.po');source.write_bytes(po(domain));dest=language/(domain+'.mo');r=subprocess.run([str(msgfmt),'--check','-o',str(dest),str(source)],capture_output=True,timeout=10);(out/(domain+'.msgfmt.stderr')).write_bytes(r.stderr)
  if r.returncode:raise ValueError(('actual msgfmt failed',domain,r.stderr))
 native_locales=subprocess.check_output(['locale','-a']).splitlines();save(out/'available-locales.json',[v.decode('ascii')for v in native_locales]);required=[b'en_US.UTF-8',b'en_US.ISO8859-1']
 if any(v not in native_locales for v in required):raise ValueError('required actual UTF8/ISO8859-1 native encoding profiles unavailable')
 env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_','OWNED_','DYLD_','LD_'))and k not in['LANG','LANGUAGE','LC_ALL','LC_MESSAGES','OUTPUT_CHARSET']};rows=[];result={'status':'not-run'};actors={str(c):sha(c),str(rust):sha(rust)};catalog_hashes={str(v):sha(v)for v in out.rglob('*.mo')}
 profiles=[('C','C','fr'),('utf8-fr','en_US.UTF-8','fr'),('latin1-fr','en_US.ISO8859-1','fr'),('fallback-order','en_US.UTF-8','zz:fr'),('territory-modifier','en_US.UTF-8','fr_FR.UTF-8@euro'),('invalid-environment','owned-locale-never-installed','fr')]
 keys={'SELECTED','LOCALE','DOMAIN','GET','DGET','FALLBACK','NGET0','DNGET0','NGET1','DNGET1','NGET2','DNGET2','FORMAT','BULK','UNSAFE_FORMAT_DATA_ONLY'}
 try:
  for name,lc,lang in profiles:
   current=env.copy();current.update(LC_ALL=lc,LANGUAGE=lang,OWNED_NLS_ABSENT=str(out/'definitely-absent-standard-backend.dylib'));directory=out/name;directory.mkdir();observed=[]
   for label,binary in[('c',c),('rust',rust)]:
    argv=[str(binary),str(catalogs)]if label=='c'else[str(binary),str(library),str(catalogs),a.abi];run=subprocess.run(argv,env=current,stdin=subprocess.DEVNULL,capture_output=True,timeout=4);(directory/(label+'.stdout')).write_bytes(run.stdout);(directory/(label+'.stderr')).write_bytes(run.stderr)
    if run.returncode or run.stderr:raise ValueError(('actual standard backend actor failed',name,label,run.returncode,run.stderr))
    parsed={}
    for line in run.stdout.splitlines():
     key,value=line.split(b' ',1);key=key.decode('ascii')
     if key in parsed:raise ValueError('duplicate actual row '+key)
     parsed[key]=value.decode('ascii')
    if not keys.issubset(parsed):raise ValueError('actual getter/format rows missing')
    if label=='rust':
     expected_unsafe=int(b'%n'in bytes.fromhex(parsed['UNSAFE_FORMAT_DATA_ONLY']))
     if parsed.get('RUST_ABSENT_REJECTED')!='1':raise ValueError('actual absent loader error/unwind control missing')
     if parsed.get('RUST_UNSAFE_REJECTED')!=str(expected_unsafe)or parsed.get('RUST_RC_RETAINS_CAPABILITY')!='1'or parsed.get('RUST_LAST_RC_RELEASED')!='1'or parsed.get('RUST_AFTER_INSTALLER_DROP')!=parsed['GET']:raise ValueError('actual Rust unsafe-format/handle lifetime control missing')
    elif set(parsed)!=keys:raise ValueError('unexpected C rows')
    observed.append({'actor':label,'rows':parsed})
   equal=all(observed[0]['rows'][key]==observed[1]['rows'][key]for key in keys)
   if not equal:raise ValueError(('actual enabled standard backend mismatch',name))
   data=bytes.fromhex(observed[0]['rows']['GET'])
   if name=='utf8-fr'and data!='PROJET café'.encode('utf8'):raise ValueError('actual UTF8 conversion not exercised')
   if name=='latin1-fr'and data!='PROJET café'.encode('latin1'):raise ValueError('actual ISO8859-1 output not exercised')
   rows.append({'name':name,'matched':True,'locale':lc,'language':lang,'observed':observed});save(out/'progress.json',rows)
  if inputs!={str(v.resolve()):sha(v)for v in protected}or actors!={v:sha(Path(v))for v in actors}or catalog_hashes!={str(v):sha(v)for v in out.rglob('*.mo')}:raise ValueError('actual backend/source/catalog/actor changed')
  result={'status':'passed','scope':'explicit enabled standard gettext native boundary, source-selected locale/textdomain/gettext/dgettext/ngettext/dngettext/encoding and typed Rust format rendering; NOT normal NLS0 libgnunet evidence','profiles':len(rows),'rows':rows,'inputs':inputs,'actors':actors,'catalogs':catalog_hashes,'inputs_unchanged':True,'normal_GNUnet_NLS0_credit':False,'unsafe_C_formats_executed':False}
 except Exception as e:result={'status':'failed','error':str(e),'rows':rows};raise
 finally:save(out/'result.json',result)
 print(json.dumps({'status':result['status'],'profiles':len(rows),'normal_GNUnet_NLS0_credit':False}))
if __name__=='__main__':main()
