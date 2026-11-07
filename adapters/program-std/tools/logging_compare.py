#!/usr/bin/env python3
"""Normal unmodified logging public APIs versus actual Rust owned logger.
Clock/PID fields are validated individually; process fd2 installation is not
credited to the owned Rust diagnostic port. All files/children belong to output.
"""
import argparse,calendar,datetime,hashlib,json,os,re,subprocess,time
from pathlib import Path
from normal_reference import load,compile_probe
from _common import sha,require_disjoint_output
BASE=Path(__file__).resolve().parents[1]
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
DATE=rb'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})[.]([0-9]{6})([+-])([0-9]{2})([0-9]{2})'
def date_boundary(raw,before,after):
    match=re.fullmatch(DATE,raw)
    if not match:raise ValueError(('invalid native date structure',raw))
    parts=datetime.datetime.strptime(match[1].decode(),'%Y-%m-%dT%H:%M:%S');epoch=calendar.timegm(parts.timetuple())*1000000+int(match[2]);minutes=int(match[4])*60+int(match[5])
    if minutes>24*60:raise ValueError('invalid timezone numeric field')
    epoch-=minutes*60000000*(1 if match[3]==b'+'else -1)
    if not before<=epoch<=after:raise ValueError(('timestamp outside actual subprocess wall interval',epoch,before,after,raw))
    return {'epoch_us':epoch,'date':raw.decode(),'offset_minutes':minutes*(1 if match[3]==b'+'else -1),'in_actual_wall_interval':True}
def canonical(stdout,stderr,pid,before,after,mode):
    lines=stdout.splitlines();header=lines.pop(0);profile=lines.pop(0)
    if header!=b'PID '+str(pid).encode()or not re.fullmatch(rb'PROFILE [0-9]+',profile):raise ValueError('actual native PID/profile missing')
    observations=[];dates=[]
    for line in lines:
        if line.startswith(b'R '):
            tag,kind,component,date,message=line[2:].split(b' ',4);component=bytes.fromhex(component.decode());date=bytes.fromhex(date.decode());message=bytes.fromhex(message.decode());dates.append(date_boundary(date,before,after))
            stem,suffix=component.rsplit(b'-',1)
            if suffix!=str(pid).encode():raise ValueError('custom component carries another PID')
            observations.append(['R',int(tag),int(kind),stem.hex(),message.hex()])
        else:observations.append(line.decode())
    return {'profile':int(profile.split()[1]),'observations':observations,'stderr_hex':stderr.hex()},dates

def actor(binary,mode,level,env,directory,rust_extra=None,file_force=False,journal=False):
    directory.mkdir();env=env.copy();args=[str(binary),mode,level]
    if rust_extra is not None:args.append(str(int(rust_extra)))
    if mode=='file':
        requested=directory/'requested-[]';args.append(str(requested))
        if file_force:env['GNUNET_FORCE_LOGFILE']=str(directory/'forced-[]')
    if journal:env['JOURNAL_STREAM']=''
    before=time.time_ns()//1000;proc=subprocess.Popen(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.DEVNULL);stdout,stderr=proc.communicate(timeout=4);after=time.time_ns()//1000
    (directory/'stdout').write_bytes(stdout);(directory/'stderr').write_bytes(stderr)
    if proc.returncode:raise ValueError(('actual logger returned failure',proc.returncode,stderr))
    stable,dates=canonical(stdout,stderr,proc.pid,before,after,mode);file_observations=[]
    if mode=='file':
        file=directory/(('forced-'if file_force else'requested-')+str(proc.pid))
        if not file.is_file()or(file_force and list(directory.glob('requested-*'))):raise ValueError('actual [] PID/force-file precedence missing')
        data=file.read_bytes();lines=data.splitlines();
        if not lines or lines.pop(0)!=b'diagnostic-port':raise ValueError('explicit/native diagnostic destination missing')
        for line in lines:
            if line==b'* ready':file_observations.append(['MESSAGE','ready']);continue
            prefix=None
            if journal:
                match=re.fullmatch(rb'(\([0-9A-Z]{26}\) )?(ERROR|WARNING) (.*)',line)
                if not match:raise ValueError(('journal structure',line))
                scope,kind,body=match.groups();stem=None
            else:
                match=re.fullmatch(DATE+rb' (owned-program|other)-([0-9]+)(\([0-9A-Z]{26}\))? (ERROR|WARNING) (.*)',line)
                if not match:raise ValueError(('standard native structure',line))
                groups=match.groups();date=b''.join([groups[0],b'.',groups[1],groups[2],groups[3],groups[4]]);dates.append(date_boundary(date,before,after));stem=groups[5].decode();component_pid=groups[6]
                if component_pid!=str(proc.pid).encode():raise ValueError('standard prefix PID is not actual subprocess PID')
                scope,kind,body=groups[7:]
            scope=(scope or b'').strip()
            if body.startswith(b'Message `repeat\' repeated '):
                duration=re.fullmatch(rb"Message `repeat' repeated 1001 times in the last ([0-9]+) (\xc2\xb5s|ms|s)",body)
                if not duration:raise ValueError(('bulk source shape/count',body))
                value=int(duration[1]);unit=duration[2];us=value*({b'\xc2\xb5s':1,b'ms':1000,b's':1000000}[unit])
                if us>after-before:raise ValueError('bulk duration exceeds actual process wall interval')
                body=b"Message `repeat' repeated 1001 times in observed elapsed duration"
            file_observations.append([stem,scope.decode(),kind.decode(),body.hex()])
        if len(file_observations)!=4:raise ValueError('all standard/scoped/message/bulk effects required')
        stable['file_observations']=file_observations
    save(directory/'canonical.json',stable);save(directory/'actual_fields.json',{'pid':proc.pid,'before_us':before,'after_us':after,'dates':dates,'date_validation_count':len(dates)})
    return stable

def main():
    ap=argparse.ArgumentParser()
    for name in ['repo','source','reference','rust','output']:ap.add_argument('--'+name,type=Path,required=True)
    args=ap.parse_args();receipt,normal=load(args.reference,args.source,args.repo);out=require_disjoint_output(args.output,[BASE,args.repo,args.source,args.reference.resolve().parent,Path(receipt['build']),Path(receipt['prefix'])]);out.mkdir(parents=True)
    inputs=[Path(__file__),BASE/'reference/logging.c',BASE/'examples/logging-observer.rs',args.rust,args.reference];before_inputs={str(p.resolve()):sha(p)for p in inputs};save(out/'inputs-before-compile.json',before_inputs);c=out/'normal-logging';compiled=compile_probe(BASE/'reference/logging.c',c,receipt);save(out/'compile.json',compiled)
    if before_inputs!={str(p.resolve()):sha(p)for p in inputs}:raise ValueError('tool/caller/reference/Rust changed during compile')
    binary_before=sha(c);env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_'))and k not in ['JOURNAL_STREAM','LD_PRELOAD','DYLD_INSERT_LIBRARIES','DYLD_FORCE_FLAT_NAMESPACE']};env.update(receipt['runtime_environment']);env['LC_ALL']='C';rows=[]
    profiles=[('default','-',None,None),('none','NONE',None,None),('error','ERROR',None,None),('mixed-info','iNfO',None,None),('invalid-positive-threshold','not-a-level',None,None),('ordinary-override','-',None,';;;;DEBUG'),('cli-ignores-ordinary','ERROR',None,';;;;DEBUG'),('force-overrides-cli','ERROR','owned;unit[.]c$;probe;10-20;DEBUG/;;;;NONE',None),('first-forced-match','ERROR',';;;;WARNING/;;;;DEBUG',None),('valid-prefix-invalid-regex','-',';;;;INFO/[;;;;DEBUG/;;;;NONE',None),('native-leading-star-is-literal','-','*;;;;DEBUG/;;;;NONE',None),('strtol-trailing-junk','-',';;;10junk;DEBUG/;;;;NONE',None),('reversed-range','-',';;;20-10;DEBUG/;;;;NONE',None),('malformed-fragment-progress','-','broken/;;;;INFO',None),('extra-separator-diagnostics','-',';;;;;INFO',None)]
    try:
        for name,level,force,ordinary in profiles:
            directory=out/name;directory.mkdir();current=env.copy()
            if force is not None:current['GNUNET_FORCE_LOG']=force
            if ordinary is not None:current['GNUNET_LOG']=ordinary
            cv=actor(c,'policy',level,current,directory/'c');rv=actor(args.rust,'policy',level,current,directory/'rust',cv['profile']>0);rows.append({'name':name,'kind':'policy','matched':cv==rv,'c':cv,'rust':rv});save(out/'progress.json',rows)
            if cv!=rv:raise ValueError('actual native policy mismatch '+name)
        for name,mode,force,journal in [('custom-order-scope-raw','custom',False,False),('file-standard-scope-bulk','file',False,False),('force-file','file',True,False),('journal-message-scope','file',False,True)]:
            directory=out/name;directory.mkdir();cv=actor(c,mode,'DEBUG',env,directory/'c',file_force=force,journal=journal);rv=actor(args.rust,mode,'DEBUG',env,directory/'rust',cv['profile']>0,file_force=force,journal=journal);rows.append({'name':name,'kind':mode,'matched':cv==rv,'c':cv,'rust':rv});save(out/'progress.json',rows)
            if cv!=rv:raise ValueError('actual native logger mismatch '+name)
        _,normal_after=load(args.reference,args.source,args.repo);unchanged=normal==normal_after and sha(c)==binary_before and before_inputs=={str(p.resolve()):sha(p)for p in inputs}
        if not unchanged:raise ValueError('actual reference/caller/tool/binary changed')
        result={'status':'passed','profiles':len(rows),'scope':'normal unmodified public logger APIs versus actual owned Rust policy/formatter/file/callback engine; timestamp/calendar/zone/microsecond/PID fields independently bounded; no process-global fd2/locale/PROGRAM completion credit','normal_inputs':normal,'compiled':compiled,'normal_binary_unchanged':True,'caller_inputs_unchanged':True,'rows':rows,'process_global_install_credited':False}
    except Exception as error:result={'status':'failed','error':str(error),'rows':rows};raise
    finally:save(out/'result.json',result)
    print(json.dumps({'status':result['status'],'profiles':len(rows),'process_global_install_credited':False}))
if __name__=='__main__':main()
