#!/usr/bin/env python3
"""Source-bound original C CLOCK-MQ/IO component; not a daemon substitute."""
import argparse,hashlib,importlib.util,json,os,platform,re,shlex,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repository',type=Path,required=True)
parser.add_argument('--source',type=Path,required=True)
parser.add_argument('--reference',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
REPO=args.repository.resolve();SOURCE=args.source.resolve();REF=args.reference.resolve()
extract_path=REPO/'crates/gnunet-client/tests/handle_c_oracle.py'
spec=importlib.util.spec_from_file_location('queue_extractor',extract_path);extract=importlib.util.module_from_spec(spec);spec.loader.exec_module(extract)
files={name:(SOURCE/name).read_text() for name in ['src/service/statistics/statistics_api.c','src/lib/util/client.c','src/lib/util/mq.c','src/lib/util/time.c']}
S=files['src/service/statistics/statistics_api.c'];M=files['src/lib/util/mq.c'];C=files['src/lib/util/client.c'];T=files['src/lib/util/time.c']
parts=[];bindings=[]
def add(source,prefix,structure=False,wrapper=None):
 starts=[m.start() for m in re.finditer(re.escape(prefix),source)]
 start=next((pos for pos in starts if structure or source.find('{',pos)<source.find(';',pos)),None)
 if start is None:raise ValueError('no definition: '+prefix)
 text=extract.body(source[start:],prefix,structure)
 path=next(k for k,v in files.items() if v is source)
 bindings.append({'source':path,'prefix':prefix,'sha256':hashlib.sha256(text.encode()).hexdigest(),'complete_body':True,'byte_start':len(source[:start].encode()),'byte_length':len(text.encode()),'observing_wrapper':wrapper})
 if wrapper:
  name=prefix.split('\n')[-1].split(' (')[0]
  parts.append('#define '+name+' original_'+name+'\n'+text+'\n#undef '+name+'\n'+wrapper)
 else:parts.append(text)

def generate():
 header='''/* Original GNUnet components compiled for finite source-bound observations. */\n'''+''.join(v[:v.index('*/')+2]+'\n' for v in files.values())+'''
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
'''
 for source,prefix in [(M,'struct GNUNET_MQ_Envelope\n'),(M,'struct GNUNET_MQ_Handle\n'),(M,'struct GNUNET_MQ_DestroyNotificationHandle\n'),(C,'struct ClientState\n')]:add(source,prefix,True)
 types='\n'.join(parts);parts.clear()
 ports=(ROOT/'ports.c').read_text()
 for prefix in ['struct GNUNET_TIME_Relative\nGNUNET_TIME_relative_get_unit_','struct GNUNET_TIME_Relative\nGNUNET_TIME_relative_get_millisecond_','struct GNUNET_TIME_Relative\nGNUNET_TIME_relative_get_second_','struct GNUNET_TIME_Relative\nGNUNET_TIME_relative_get_minute_','bool\nGNUNET_TIME_relative_is_forever','struct GNUNET_TIME_Relative\nGNUNET_TIME_relative_min','struct GNUNET_TIME_Relative\nGNUNET_TIME_relative_max','struct GNUNET_TIME_Relative\nGNUNET_TIME_relative_multiply','struct GNUNET_TIME_Absolute\nGNUNET_TIME_relative_to_absolute']:add(T,prefix)
 for prefix in ['unsigned int\nGNUNET_MQ_get_length','void\nGNUNET_MQ_notify_sent','struct GNUNET_MQ_Envelope *\nGNUNET_MQ_msg_','void\nGNUNET_MQ_send','void\nGNUNET_MQ_discard','static void\nimpl_send_continue','void\nGNUNET_MQ_destroy_notify_cancel','void\nGNUNET_MQ_destroy','void\nGNUNET_MQ_inject_error']:add(M,prefix)
 add(M,'void\nGNUNET_MQ_impl_send_in_flight',wrapper='void GNUNET_MQ_impl_send_in_flight(struct GNUNET_MQ_Handle*mq){inflight_calls++;original_GNUNET_MQ_impl_send_in_flight(mq);}')
 add(M,'void\nGNUNET_MQ_impl_send_continue',wrapper='void GNUNET_MQ_impl_send_continue(struct GNUNET_MQ_Handle*mq){continue_calls++;original_GNUNET_MQ_impl_send_continue(mq);}')
 for prefix in ['static void\ntransmit_ready','static void\nconnection_client_send_impl']:add(C,prefix)
 return header+types+'\n'+S+'\n#undef LOG\n#define LOG(...) ((void)0)\n'+ports+'\n'+'\n'.join(parts)+'\n'+(ROOT/'cases.c').read_text()

def main():
 reference=json.loads(REF.read_text());out=args.output.resolve();out.mkdir(exist_ok=False);program=generate();(out/'component.c').write_text(program);r={'kind':'original-c-statistics-clock-mq-io-component','status':'failed','full_c_daemon':False,'scope':'Complete original C function bodies, real normal util helpers, recording virtual scheduler/clock, finite MQ connector and send-return seam; no invented daemon or remote acknowledgement.','original_statistics_translation_unit':{'path':'src/service/statistics/statistics_api.c','sha256':hashlib.sha256(S.encode()).hexdigest(),'complete_unmodified':True},'original_functions':bindings,'commands':[],'compiler_version':subprocess.check_output(['cc','--version'],text=True),'platform':platform.platform(),'upstream':reference['upstream'],'seams':['exact absolute clock capability','recorded scheduler capabilities, invoking original callback bodies','GNUNET_CLIENT_connect finite unavailable or normal MQ queue_for_callbacks capability','network send finite return classes','MQ in-flight and continuation call counters forwarding the complete original bodies'],'harness_inputs':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),ROOT/'ports.c',ROOT/'cases.c',extract_path]},'dependency_inputs':{}}
 try:
  source_checker_path=REPO/'tools/reference/build_reference.py'
  source_spec=importlib.util.spec_from_file_location('clock_reference_source',source_checker_path);source_checker=importlib.util.module_from_spec(source_spec);source_spec.loader.exec_module(source_checker)
  r['harness_inputs'][str(source_checker_path)]=hashlib.sha256(source_checker_path.read_bytes()).hexdigest()
  r['reference_source_before']=source_checker.source_state(SOURCE);assert r['reference_source_before']==reference['upstream']
  assert reference['status']=='passed' and reference['upstream']['revision']=='346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
  assert Path(reference['source']).resolve()==SOURCE
  checked=[*reference['libraries'],reference['generated_config']]
  for item in checked:
   assert hashlib.sha256(Path(item['path']).read_bytes()).hexdigest()==item['sha256'],item['path']
  r['normal_reference_inputs']={item['path']:item['sha256'] for item in checked}
  r['source_sha256']={name:hashlib.sha256(content.encode()).hexdigest() for name,content in files.items()};assert all((SOURCE/name).read_bytes()==content.encode() for name,content in files.items());r['reference_receipt_sha256']=hashlib.sha256(REF.read_bytes()).hexdigest();r['program_sha256']=hashlib.sha256(program.encode()).hexdigest();env={**os.environ,**reference['runtime_environment']};outputs=[]
  for profile,flags in [('optimized',['-O2']),('wrapping',['-O0','-fwrapv'])]:
   binary=out/profile;depfile=out/(profile+'.d');argv=['cc','-MD','-MF',str(depfile),'-std=c11','-DHAVE_CONFIG_H','-D_GNU_SOURCE',*(['-DDARWIN','-D_APPLE_C_SOURCE'] if platform.system()=='Darwin' else []),*flags,'-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-unused-function','-Wno-sign-compare','-I'+reference['build']+'/src/include','-I'+reference['build'],'-I'+str(SOURCE/'src/include'),'-I'+str(SOURCE/'src/service/statistics'),*shlex.split(reference['build_environment']['CPPFLAGS']),str(out/'component.c'),*shlex.split(reference['build_environment']['LDFLAGS']),'-L'+reference['prefix']+'/lib','-Wl,-rpath,'+reference['prefix']+'/lib','-lgnunetutil','-o',str(binary)];scan=argv[:argv.index(str(out/'component.c'))+1];scan[scan.index('-MD')]='-M';scan[scan.index('-MF')+1]=str(out/(profile+'.pre.d'));scan_result=subprocess.run(scan,capture_output=True);(out/(profile+'.dependencies.log')).write_bytes(scan_result.stdout+scan_result.stderr);r['commands'].append({'argv':scan,'exit_code':scan_result.returncode});assert scan_result.returncode==0,scan_result.stderr.decode(errors='replace')
   predeps=shlex.split((out/(profile+'.pre.d')).read_text().replace('\\\n',' ').split(':',1)[1]);prehash={str(Path(name).resolve()):hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in predeps}
   p=subprocess.run(argv,capture_output=True);(out/(profile+'.compile.log')).write_bytes(p.stdout+p.stderr);r['commands'].append({'argv':argv,'exit_code':p.returncode})
   if p.returncode:raise ValueError(profile+' compile failed: '+p.stderr.decode(errors='replace')[-6000:])
   deptext=depfile.read_text().replace('\\\n',' ')
   for name in shlex.split(deptext.split(':',1)[1]):
    dependency=Path(name).resolve();actual=hashlib.sha256(dependency.read_bytes()).hexdigest();assert prehash[str(dependency)]==actual;r['dependency_inputs'][str(dependency)]=actual
   p=subprocess.run([binary],env=env,capture_output=True,timeout=20);(out/(profile+'.trace')).write_bytes(p.stdout);(out/(profile+'.stderr')).write_bytes(p.stderr);r['commands'].append({'argv':[str(binary)],'exit_code':p.returncode,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'trace_sha256':hashlib.sha256(p.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest()})
   if p.returncode:raise ValueError(profile+' execution failed: '+p.stderr.decode(errors='replace')[-3000:])
   outputs.append(p.stdout)
  if outputs[0]!=outputs[1]:raise ValueError('two compiler profiles differ')
  r['trace_rows']=len(outputs[0].splitlines());r['source_unchanged']=r['source_sha256']=={name:hashlib.sha256((SOURCE/name).read_bytes()).hexdigest() for name in files};assert r['source_unchanged'];r['normal_reference_unchanged']=all(hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest for path,digest in r['normal_reference_inputs'].items());r['dependencies_unchanged']=all(hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest for path,digest in r['dependency_inputs'].items());assert r['normal_reference_unchanged'] and r['dependencies_unchanged'];r['reference_source_after']=source_checker.source_state(SOURCE);assert r['reference_source_after']==r['reference_source_before'];r['status']='passed'
 except Exception as e:r['failure']=str(e)
 (out/'result.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'status':r['status'],'rows':r.get('trace_rows'),'report':str(out/'result.json'),'failure':r.get('failure')}));return 0 if r['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
