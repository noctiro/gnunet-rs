#!/usr/bin/env python3
"""Build test-only public C API actor from the normal Meson compile configuration."""
import argparse,hashlib,json,pathlib,subprocess,shlex,shutil
from workspace_bridge import helper as workspace_helper
from common import normal,disjoint,successful,require,reference_inputs

def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--normal-receipt',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--reference-helper',type=pathlib.Path,required=True);a=p.parse_args();r,state,source_state=normal(a.normal_receipt,a.reference_helper);disjoint(a.output,[pathlib.Path(__file__).resolve().parent,r['source'],r['build'],r['prefix'],a.normal_receipt.parent]);a.output.mkdir(parents=True,exist_ok=False)
 for row in r['libraries']+r['plugins']+[r['compile_commands'],r['generated_config']]:require((sha(row['path']) == row['sha256']), row)
 entries=json.loads(pathlib.Path(r['compile_commands']['path']).read_text());entry=next(x for x in entries if x['file'].endswith('/block.c'));argv=entry.get('arguments') or shlex.split(entry['command']);flags=[];i=1
 while i<len(argv):
  if argv[i] in ('-o','-MF','-MT','-MQ') :i+=2;continue
  if argv[i] in ('-c','-MD','-MMD') :i+=1;continue
  if argv[i].endswith('.c'):i+=1;continue
  flags.append(argv[i]);i+=1
 source=pathlib.Path(__file__).resolve().parent/'probe.c';prefix=pathlib.Path(r['prefix']);binary=a.output/'probe';command=[argv[0],*flags,str(source),'-L'+str(prefix/'lib'),'-lgnunetblock','-lgnunetblockgroup','-lgnunethello','-lgnunetutil','-Wl,-rpath,'+str(prefix/'lib'),'-o',str(binary)]
 before=reference_inputs(r,a.reference_helper);shared=workspace_helper();commands=shared.Commands(a.output,pathlib.Path(a.reference_helper).resolve().parents[2],r['runtime_environment']);compiler_path=shutil.which(command[0],path=commands.env.get('PATH'));require(compiler_path is not None,'actual C compiler executable unresolved');compiler_path=commands.bind(compiler_path);compiler_version=commands.run('compiler-version',[compiler_path,'--version']).decode();compiler={'path':str(compiler_path),'sha256':sha(compiler_path),'version':compiler_version};commands.compile_c('build',command,entry['directory']);commands.bind(binary);commands.check_artifacts();require(reference_inputs(r,a.reference_helper)==before,'normal reference/provider closure changed during C actor compile');require((source_state(pathlib.Path(r['source'])) == state), 'verification invariant failed: build_probe.py:17')
 result={'status':'passed','command':command,'cwd':entry['directory'],'receipt':{'path':str(a.normal_receipt),'sha256':sha(a.normal_receipt)},'source':{'path':str(source),'sha256':sha(source)},'binary':{'path':str(binary),'sha256':sha(binary)},'builder':{'path':str(pathlib.Path(__file__).resolve()),'sha256':sha(__file__)},'normal_source':state,'compiler':compiler,'compiler_artifacts':commands.artifacts,'compiler_header_inputs':commands.headers,'normal_reference_inputs':before,'commands':commands.rows,'common':{'path':str(pathlib.Path(__file__).resolve().parent/'common.py'),'sha256':sha(pathlib.Path(__file__).resolve().parent/'common.py')},'reference_helper':{'path':str(a.reference_helper.resolve()),'sha256':sha(a.reference_helper)}};(a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
if __name__=='__main__':main()
