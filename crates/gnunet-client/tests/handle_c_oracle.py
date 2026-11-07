#!/usr/bin/env python3
"""Original C pending-action coalescing versus the actual Rust handle owner.

The controlled scheduler/MQ remains busy while the action sequence is admitted.
This is queue/API component evidence, not complete C callback/daemon evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

PIN='346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
ROOT=Path(__file__).resolve().parents[3]
CASES={
 'saturation-across-get':[('set','a',20,False),('get','s','a'),('update','a',-30,True),('update','a',10,False)],
 'zero-merged-update':[('update','a',-1,False),('update','a',1,True),('update','a',0,False)],
 'zero-call-no-action':[('update','a',0,True)],
 'replace-update-with-set':[('update','a',7,True),('set','a',9,False)],
 'case-sensitive-names':[('set','a',1,False),('get','other','x'),('set','A',2,False),('update','a',4,True)],
 'setter-fifo-position':[('set','a',1,False),('set','b',2,False),('set','a',3,True)],
 'cancel-queued-get':[('set','a',1,False),('get','s','a'),('get','s','b'),('cancel',0),('update','a',2,True)],
 'negative-minimum':[('set','a',(1<<63)+5,False),('update','a',-(1<<63),True)],
 'positive-wrap':[('set','a',(1<<64)-1,False),('update','a',1,True)],
 'negative-clamp':[('set','a',1,True),('update','a',-2,False)],
 'get-wildcards':[('get','','')],
}
INPUTS=('src/service/statistics/statistics_api.c','src/service/statistics/statistics.h','src/include/gnunet_common.h','src/include/gnunet_container_lib.h','src/include/gnunet_statistics_service.h','src/include/gnunet_util_lib.h')
TRACE_TEST='original_c_pending_queue_coalescing_matches_rust'


def digest(data):return hashlib.sha256(data).hexdigest()
def body(source,prefix,structure=False):
 start=source.index(prefix);opening=source.index('{',start);depth=0
 tokens=re.compile(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|/\*.*?\*/|//[^\n]*|[{}]''',re.S)
 for token in tokens.finditer(source,opening):
  if token.group()=='{':depth+=1
  elif token.group()=='}':
   depth-=1
   if depth==0:return source[start:token.end()+int(structure)]
 raise ValueError('unclosed C declaration')
def macro(source,name):
 start=source.index('#define '+name);return source[start:source.index('\n\n',start)]
def cstr(value):return '"'+''.join('\\%03o'%b for b in value.encode())+'"'


def program(contents):
 api=contents[INPUTS[0]];header=contents[INPUTS[1]];common=contents[INPUTS[2]];container=contents[INPUTS[3]]
 notices='\n'.join(value[:value.index('*/')+2] for value in contents.values())
 shim=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
enum GNUNET_GenericReturnValue{GNUNET_SYSERR=-1,GNUNET_NO=0,GNUNET_OK=1};
#define GNUNET_YES GNUNET_OK
#define GNUNET_assert assert
#define GNUNET_break(x) ((void)(x))
#define LOG(...) ((void)0)
#define GNUNET_malloc(n) calloc(1,n)
#define GNUNET_new(type) ((type*)calloc(1,sizeof(type)))
#define GNUNET_free free
#define GNUNET_strdup strdup
#define GNUNET_PACKED __attribute__((packed))
struct GNUNET_TIME_Absolute{uint64_t abs_value_us;};
struct GNUNET_TIME_Relative{uint64_t rel_value_us;};
#define GNUNET_TIME_UNIT_SECONDS ((struct GNUNET_TIME_Relative){1000000})
#define GNUNET_TIME_UNIT_MILLISECONDS ((struct GNUNET_TIME_Relative){1000})
static struct GNUNET_TIME_Relative GNUNET_TIME_relative_multiply(struct GNUNET_TIME_Relative value,unsigned factor){value.rel_value_us*=factor;return value;}
static struct GNUNET_TIME_Absolute GNUNET_TIME_relative_to_absolute(struct GNUNET_TIME_Relative value){return (struct GNUNET_TIME_Absolute){value.rel_value_us};}
typedef int(*GNUNET_STATISTICS_Iterator)(void*,const char*,const char*,uint64_t,int);
typedef void(*GNUNET_STATISTICS_Callback)(void*,int);
struct GNUNET_CONFIGURATION_Handle{bool disabled;};
struct GNUNET_MQ_Handle{unsigned queue_length;};
static struct GNUNET_MQ_Handle busy_mq={1};
static int GNUNET_CONFIGURATION_get_value_yesno(const struct GNUNET_CONFIGURATION_Handle*cfg,const char*s,const char*k){(void)s;(void)k;return cfg->disabled;}
'''
 types='\n'.join([body(common,'struct GNUNET_MessageHeader\n',True),body(header,'struct GNUNET_STATISTICS_SetMessage\n',True),body(api,'enum ActionType\n',True)]+[body(api,'struct '+name+'\n',True)for name in ('GNUNET_STATISTICS_WatchEntry','GNUNET_STATISTICS_GetHandle','GNUNET_STATISTICS_Handle')])
 shims=r'''
/* The MQ is held busy: schedule_action cannot dispatch a pending action. */
static void schedule_action(void*cls){struct GNUNET_STATISTICS_Handle*h=cls;assert(h->mq&&h->mq->queue_length>0&&!h->backoff_task);}
static int iterator(void*c,const char*s,const char*n,uint64_t v,int p){(void)c;(void)s;(void)n;(void)v;(void)p;return GNUNET_OK;}
'''
 funcs=[macro(contents[INPUTS[5]],'GNUNET_MAX_MESSAGE_SIZE'),macro(container,'GNUNET_CONTAINER_DLL_insert_tail('),macro(container,'GNUNET_CONTAINER_DLL_remove('),macro(api,'SET_TRANSMIT_TIMEOUT'),body(api,'struct GNUNET_STATISTICS_Handle *\nGNUNET_STATISTICS_create'),body(api,'struct GNUNET_STATISTICS_GetHandle *\nGNUNET_STATISTICS_get'),body(api,'void\nGNUNET_STATISTICS_get_cancel'),body(api,'static void\nadd_setter_action'),body(api,'void\nGNUNET_STATISTICS_set'),body(api,'void\nGNUNET_STATISTICS_update')]
 harness=r'''
static void hex(const char*s){while(*s)printf("%02x",(unsigned char)*s++);}
static void emit(const char*label,const struct GNUNET_STATISTICS_Handle*h){
 if(!h->action_head){printf("empty|%s\n",label);return;}
 for(const struct GNUNET_STATISTICS_GetHandle*a=h->action_head;a;a=a->next){
  const char*kind=a->type==ACTION_SET?"set":a->type==ACTION_UPDATE?"update":"get";
  printf("action|%s|%s|",label,kind);hex(a->subsystem);putchar('|');hex(a->name);
  printf("|%"PRIu64"|%d\n",a->value,a->make_persistent);
 }
}
int main(void){struct GNUNET_CONFIGURATION_Handle cfg={0};
'''
 for label,actions in CASES.items():
  harness+='{struct GNUNET_STATISTICS_Handle*h=GNUNET_STATISTICS_create("s",&cfg);h->mq=&busy_mq;struct GNUNET_STATISTICS_GetHandle*g[8]={0};unsigned gi=0;(void)g;(void)gi;\n'
  for action in actions:
   if action[0]=='set':harness+='GNUNET_STATISTICS_set(h,'+cstr(action[1])+',UINT64_C('+str(action[2])+'),'+str(int(action[3]))+');\n'
   elif action[0]=='update':harness+='GNUNET_STATISTICS_update(h,'+cstr(action[1])+',(int64_t)UINT64_C('+str(action[2]%(1<<64))+'),'+str(int(action[3]))+');\n'
   elif action[0]=='get':harness+='g[gi++]=GNUNET_STATISTICS_get(h,'+cstr(action[1])+','+cstr(action[2])+',NULL,iterator,NULL);\n'
   else:harness+='GNUNET_STATISTICS_get_cancel(g['+str(action[1])+']);\n'
  harness+='emit('+cstr(label)+',h);}\n'
 harness+='cfg.disabled=true;printf("disabled|%d\\n",NULL==GNUNET_STATISTICS_create("ignored",&cfg));return 0;}\n'
 return notices+shim+types+shims+'\n'.join(funcs)+harness


def rust_test():
 text='''//! Actual Rust pending-action trace compared with original pinned C functions.
#![expect(clippy::panic_in_result_fn,reason="Differential queue test compares independently executed original C action snapshots")]
use gnunet_client::{statistics::Selector,statistics_handle::{StatisticsHandle,OutboundKind,GetId}};
use gnunet_types::{Error,AbsoluteTime};
use std::fmt::Write;
type H=StatisticsHandle<32,128,4,32,32>;
fn hex(bytes:&[u8])->String{let mut out=String::new();for byte in bytes{out.push_str(&format!("{byte:02x}"));}out}
fn snapshot(label:&str,h:&mut H,e:gnunet_client::statistics_handle::ConnectionEpoch,trace:&mut String)->Result<(),Box<dyn std::error::Error>>{
 let mut count=0;
 loop{let mut out=[0;256];let Some(frame)=h.next_request(e,&mut out)?else{break;};
 let (kind,value,persistent,start)=match frame.kind{
  OutboundKind::Mutation{relative,persistent}=>(if relative{"update"}else{"set"},u64::from_be_bytes(out[8..16].try_into()?),u8::from(persistent),16),
  OutboundKind::Get(_)=>("get",0,0,4),_=>return Err(Error::Unsupported.into()),};
 let names=&out[start..frame.len];let split=names.iter().position(|b|*b==0).ok_or(Error::Malformed)?;
 writeln!(trace,"action|{label}|{kind}|{}|{}|{value}|{persistent}",hex(&names[..split]),hex(&names[split+1..names.len()-1]))?;
 h.on_frame_written(e,frame.transmit)?;
 if matches!(frame.kind,OutboundKind::Get(_)){h.receive(e,b"\\0\\x04\\0\\xab",AbsoluteTime::from_micros(0))?;h.take_completion();}
 count+=1;
 }if count==0{writeln!(trace,"empty|{label}")?;}Ok(())
}
#[test]
fn original_c_pending_queue_coalescing_matches_rust()->Result<(),Box<dyn std::error::Error>>{
 let mut trace=String::new();
'''
 for label,actions in CASES.items():
  text+='\n{let mut h=H::new(b"s",true)?.ok_or(Error::Unavailable)?;h.set(b"_anchor",0,false)?;let e=h.begin_connection(AbsoluteTime::from_micros(0))?;let anchor=h.next_request(e,&mut[0;256])?.ok_or(Error::NotReady)?;\n'
  if any(action[0]=='cancel'for action in actions):text+='let mut gets=Vec::<GetId>::new();\n'
  for action in actions:
   if action[0]=='set':text+='h.set(b'+json.dumps(action[1])+','+str(action[2])+'u64,'+str(action[3]).lower()+')?;\n'
   elif action[0]=='update':text+='h.update(b'+json.dumps(action[1])+','+str(action[2])+'i64,'+str(action[3]).lower()+')?;\n'
   elif action[0]=='get':
    call='h.get(Selector{subsystem:b'+json.dumps(action[1])+',name:b'+json.dumps(action[2])+'})?'
    text+=('gets.push('+call+');\n')if any(item[0]=='cancel'for item in actions)else(call+';\n')
   else:text+='h.get_cancel(gets['+str(action[1])+'])?;\n'
  if any(action[0]=='cancel'for action in actions):text+='drop(gets);'
  text+='h.on_frame_written(e,anchor.transmit)?;snapshot('+json.dumps(label)+',&mut h,e,&mut trace)?;}\n'
 text+='''writeln!(trace,"disabled|{}",u8::from(H::new(b"ignored",false)?.is_none()))?;
 assert_eq!(trace,include_str!("fixtures/handle_queue.txt"));
 if let Some(path)=std::env::var_os("GNUNET_HANDLE_QUEUE_TRACE"){std::fs::write(path,trace)?;}
 Ok(())
}
'''
 return text


def source_state(source):
 revision=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
 if revision!=PIN:raise ValueError('wrong fixed reference revision')
 subprocess.run(['git','-C',str(source),'diff','--quiet','HEAD','--',*INPUTS],check=True)
 return {'revision':revision,'files':{name:digest((source/name).read_bytes())for name in INPUTS}}
def rust_state():
 paths=[]
 for directory in ('crates/gnunet-client','crates/gnunet-types','crates/gnunet-wire'):
  paths.extend(p for p in (ROOT/directory).rglob('*')if p.is_file()and'__pycache__'not in p.parts and'target'not in p.parts)
 paths.extend(ROOT/name for name in ('Cargo.toml','Cargo.lock','rust-toolchain.toml'))
 return {str(p.relative_to(ROOT)):digest(p.read_bytes())for p in sorted(paths)}
def checked_rows(data):
 rows=data.decode('ascii').splitlines();labels=set();seen=set()
 for row in rows:
  p=row.split('|')
  if p[0]=='disabled':
   if p!=['disabled','1']:raise ValueError('wrong disabled observation')
  elif p[0]=='empty':
   if len(p)!=2 or p[1]not in CASES:raise ValueError('invalid empty queue observation')
   labels.add(p[1])
  elif p[0]=='action':
   if len(p)!=7 or p[1]not in CASES or p[2]not in {'set','update','get'}or not p[5].isdigit()or p[6]not in {'0','1'}:raise ValueError('malformed actual action observation')
   for hexfield in p[3:5]:
    if len(hexfield)%2 or re.fullmatch('[0-9a-f]*',hexfield)is None:raise ValueError('malformed actual selector')
   labels.add(p[1])
  else:raise ValueError('unexpected actual C/Rust observation')
  if row in seen:raise ValueError('duplicate actual action observation')
  seen.add(row)
 if labels!=set(CASES)or'disabled|1'not in seen:raise ValueError('missing/empty actual queue checks')
 return rows

def execute_c(source,folder,report):
 source_path=folder/'oracle.c';source_path.write_text(program({name:(source/name).read_text()for name in INPUTS}));outputs=[]
 for name,flags in [('optimized',['-O2']),('wrapping',['-O0','-fwrapv'])]:
  binary=folder/('oracle-'+name)
  argv=['cc','-std=c11',*flags,'-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-sign-compare',str(source_path),'-o',str(binary)]
  result=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  (folder/(name+'.compile.stderr.txt')).write_bytes(result.stderr)
  report['commands'].append({'argv':argv,'exit_code':result.returncode,'stderr':name+'.compile.stderr.txt','stderr_sha256':digest(result.stderr)})
  if result.returncode:raise ValueError('actual C owner did not compile: '+result.stderr.decode())
  data=subprocess.check_output([str(binary)],timeout=10);checked_rows(data);outputs.append(data)
  (folder/(name+'.trace.txt')).write_bytes(data)
  report['commands'].append({'argv':[str(binary)],'exit_code':0,'stdout':name+'.trace.txt','stdout_sha256':digest(data),'binary_sha256':digest(binary.read_bytes())})
 if outputs[0]!=outputs[1]:raise ValueError('C pending action behavior differs between optimized and wrapping profiles')
 report['c_source_sha256']=digest(source_path.read_bytes());return outputs[0]

def receipt(source,folder):
 folder.mkdir(parents=True,exist_ok=False);report={'schema':1,'status':'failed','kind':'official-statistics-pending-action-differential','scope':'Original C create/set/update/get/get_cancel and pending setter coalescing; controlled busy MQ/scheduler, not complete callbacks/daemon/reconnect evidence.','full_c_daemon':False,'commands':[],'executed_checks':0}
 try:
  report['upstream']=source_state(source);before=rust_state();report['rust_inputs']=before
  c=execute_c(source,folder,report);fixture=Path(__file__).with_name('fixtures')/'handle_queue.txt'
  if c!=fixture.read_bytes():raise ValueError('C pending action trace differs from fixture')
  argv=['cargo','test','-p','gnunet-client','--test','handle_c_queue','--locked','--no-run','--message-format=json']
  built=subprocess.run(argv,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
  (folder/'rust-build.stdout.txt').write_bytes(built.stdout);(folder/'rust-build.stderr.txt').write_bytes(built.stderr)
  report['commands'].append({'argv':argv,'exit_code':built.returncode,'stdout':'rust-build.stdout.txt','stdout_sha256':digest(built.stdout),'stderr_sha256':digest(built.stderr)})
  if built.returncode:raise ValueError('actual Rust queue trace test failed compilation')
  artifacts=[json.loads(line)for line in built.stdout.decode().splitlines()if line.startswith('{')]
  artifacts=[a for a in artifacts if a.get('reason')=='compiler-artifact'and a.get('target',{}).get('name')=='handle_c_queue'and a.get('executable')]
  if len(artifacts)!=1:raise ValueError('actual Rust test binary missing or ambiguous')
  binary=folder/'rust-queue.snapshot';shutil.copyfile(artifacts[0]['executable'],binary);binary.chmod(0o700);binary_hash=digest(binary.read_bytes())
  env=dict(os.environ,GNUNET_HANDLE_QUEUE_TRACE=str(folder/'rust.trace.txt'));argv=[str(binary),'--exact',TRACE_TEST,'--nocapture'];tested=subprocess.run(argv,cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
  (folder/'rust-test.stdout.txt').write_bytes(tested.stdout);(folder/'rust-test.stderr.txt').write_bytes(tested.stderr)
  report['commands'].append({'argv':argv,'exit_code':tested.returncode,'stdout':'rust-test.stdout.txt','stdout_sha256':digest(tested.stdout),'stderr_sha256':digest(tested.stderr),'binary_sha256':binary_hash})
  if tested.returncode or b'running 1 test'not in tested.stdout or b'test result: ok. 1 passed; 0 failed'not in tested.stdout:raise ValueError('actual Rust queue test did not execute successfully')
  rust=(folder/'rust.trace.txt').read_bytes();rows=checked_rows(rust)
  if checked_rows(c)!=rows:raise ValueError('actual C and Rust pending action traces differ')
  report['executed_checks']=len(rows);report['compiler_profiles']=2;report['trace_sha256']=digest(rust)
  report['source_unchanged']=rust_state()==before and source_state(source)==report['upstream']
  report['binary_unchanged']=digest(binary.read_bytes())==binary_hash
  if not report['source_unchanged']or not report['binary_unchanged']:raise ValueError('queue evidence inputs changed during run')
  report['status']='passed'
 except Exception as error:report['failure']=type(error).__name__+': '+str(error)
 (folder/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'executed_checks':report['executed_checks'],'evidence':str(folder/'result.json')}));return 0 if report['status']=='passed'else 1

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',required=True,type=Path);parser.add_argument('--output',type=Path);parser.add_argument('--write',action='store_true');args=parser.parse_args();source=args.source.resolve()
 if args.output:
  if args.write:parser.error('--write and --output are separate operations')
  return receipt(source,args.output.resolve())
 source_state(source)
 with tempfile.TemporaryDirectory(prefix='gnunet-handle-queue-')as work:data=execute_c(source,Path(work),{'commands':[]})
 fixture=Path(__file__).with_name('fixtures')/'handle_queue.txt'
 if args.write:
  fixture.parent.mkdir(exist_ok=True);fixture.write_bytes(data);Path(__file__).with_name('handle_c_queue.rs').write_text(rust_test())
 elif data!=fixture.read_bytes():raise ValueError('actual C queue fixture differs')
 print(json.dumps({'status':'passed','executed_checks':len(checked_rows(data)),'compiler_profiles':2,'sha256':digest(data)}));return 0
if __name__=='__main__':raise SystemExit(main())
