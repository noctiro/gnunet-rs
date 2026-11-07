#!/usr/bin/env python3
"""Exact official kill body with finite write-return seam and real owned kill/wait.
This explicitly source-extracted component is not an unchanged normal-lib kill or
an actual interrupted one-byte write syscall claim. Creation/run/wait use normal util.
"""
import argparse,hashlib,json,pathlib,subprocess,sys
from reference import load,compile_probe,sha
from _common import require_disjoint_output

def main():
 p=argparse.ArgumentParser()
 for name in ['repo','source','reference','output']:p.add_argument('--'+name,type=pathlib.Path,required=True)
 a=p.parse_args();package=pathlib.Path(__file__).resolve().parents[1];reference,normal=load(a.reference,a.source,a.repo)
 out=require_disjoint_output(a.output,[package,a.repo,a.source,a.reference.resolve().parent,pathlib.Path(reference['build']),pathlib.Path(reference['prefix'])]);out.mkdir(mode=0o700)
 source=a.source/'src/lib/util/os_process.c';text=source.read_text()
 structure=text[text.index('struct GNUNET_Process\n{'):text.index('\n};',text.index('struct GNUNET_Process\n{'))+3]
 start=text.index('enum GNUNET_GenericReturnValue\nGNUNET_process_kill (');end=text.index('\n\n\npid_t\nGNUNET_process_get_pid',start);body=text[start:end]
 macros=text[text.index('#define LOG(kind,'):text.index('#define GNUNET_OS_CONTROL_PIPE')]
 header='''#include "platform.h"
#include "gnunet_util_lib.h"
#include <signal.h>
static unsigned calls;
static int interrupted;
static ssize_t finite_write(const struct GNUNET_DISK_FileHandle *handle,const void *bytes,size_t n){
 if(!handle||n!=1||*(const unsigned char*)bytes!=15)_exit(91);
 calls++;if(interrupted){errno=EINTR;return -1;}return 0;
}
'''
 main='''
#undef GNUNET_DISK_file_write
#undef GNUNET_process_kill
int main(int argc,char**argv){
 if(argc!=2)return 90;interrupted=!strcmp(argv[1],"eintr");signal(SIGPIPE,SIG_IGN);
 GNUNET_log_setup("process-finite-write-component","ERROR",NULL);
 struct GNUNET_Process *proc=GNUNET_process_create(GNUNET_OS_USE_PIPE_CONTROL);
 const char *args[]={"sleep","30",NULL};
 if(GNUNET_OK!=GNUNET_process_run_command_argv(proc,"/bin/sleep",args))return 92;
 int result=source_process_kill(proc,15);
 enum GNUNET_OS_ProcessStatusType type;unsigned long code;
 if(GNUNET_OK!=GNUNET_process_wait(proc,true,&type,&code))return 93;
 GNUNET_process_destroy(proc);
 if(result!=GNUNET_OK||calls!=1||type!=GNUNET_OS_PROCESS_SIGNALED||code!=15)return 94;
 printf("{\\"write_class\\":\\"%s\\",\\"write_calls\\":%u,\\"actual_signal\\":%lu,\\"native_kill_fallback\\":true}\\n",interrupted?"eintr":"zero",calls,code);return 0;
}
'''
 generated=out/'component.c';generated.write_text(header+structure+'\n'+macros+'\n#define GNUNET_DISK_file_write finite_write\n#define GNUNET_process_kill source_process_kill\n'+body+main)
 before={str(path):sha(path)for path in [pathlib.Path(__file__).resolve(),pathlib.Path(__file__).with_name('reference.py'),pathlib.Path(__file__).with_name('_common.py'),source]}
 binary=out/'component';compilation=compile_probe(generated,binary,reference);binary_sha=sha(binary);rows=[]
 import os
 env=os.environ.copy();env.update(reference['runtime_environment'])
 for label in ['eintr','zero']:
  result=subprocess.run([str(binary),label],env=env,capture_output=True,timeout=5);(out/(label+'.stdout')).write_bytes(result.stdout);(out/(label+'.stderr')).write_bytes(result.stderr);assert result.returncode==0,(label,result.returncode,result.stderr)
  row=json.loads(result.stdout);assert row=={'write_class':label,'write_calls':1,'actual_signal':15,'native_kill_fallback':True};rows.append(row)
 after_ref,after_normal=load(a.reference,a.source,a.repo);assert reference==after_ref and normal==after_normal and all(sha(path)==digest for path,digest in before.items()) and sha(binary)==binary_sha
 result={'status':'passed','kind':'source-extracted-process-kill-finite-write-seams','scope':'2 exact official kill body write-return classes plus real normal-util process_create/run/wait and actual native kill; not normal-library kill nor actual EINTR syscall','cases':rows,'case_count':2,'source':str(source),'source_sha256':sha(source),'structure_sha256':hashlib.sha256(structure.encode()).hexdigest(),'function_sha256':hashlib.sha256(body.encode()).hexdigest(),'generated_sha256':sha(generated),'binary_sha256':binary_sha,'compilation':compilation,'inputs':before,'normal_inputs':normal,'inputs_unchanged':True}
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':'passed','seam_cases':2,'result':str(out/'result.json')}))
if __name__=='__main__':main()
