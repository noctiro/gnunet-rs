"""Pinned original macro source ranges and actual normal compiler __LINE__.
Preprocessing executes no C program. It uses the unchanged normal TU command,
strips only compile/output actions, and records every generated artifact/hash.
"""
import json,re,shlex,subprocess
from pathlib import Path
from _common import sha
LOG=re.compile(r'\b(LOG_STRERROR_FILE|LOG_STRERROR|LOG|GNUNET_log(?:_from)?(?:_strerror(?:_file)?)?|GNUNET_break)\s*\(')
def calls(text):
 result=[];ignored=set();continuation=False
 for number,line in enumerate(text.splitlines(),1):
  if continuation or line.lstrip().startswith('#'):
   ignored.add(number);continuation=line.rstrip().endswith('\\')
 for match in LOG.finditer(text):
  if text.count('\n',0,match.start())+1 in ignored:continue
  at=match.end();depth=1;quote=None
  while at<len(text)and depth:
   char=text[at]
   if quote:
    if char=='\\':at+=2;continue
    if char==quote:quote=None
   elif char in ['"',"'"]:quote=char
   elif text.startswith('/*',at):
    end=text.find('*/',at+2)
    if end<0:raise ValueError('unterminated source comment')
    at=end+2;continue
   elif text.startswith('//',at):
    at=text.find('\n',at)
    if at<0:raise ValueError('unterminated macro')
    continue
   elif char=='(':depth+=1
   elif char==')':depth-=1
   at+=1
  if depth:raise ValueError('unterminated source macro')
  result.append({'macro':match[1],'start_line':text.count('\n',0,match.start())+1,'end_line':text.count('\n',0,at)+1,'source':text[match.start():at]})
 return result

def preprocess(reference,name,output):
 db=json.loads(Path(reference['compile_commands']['path']).read_text());rows=[row for row in db if row['file'].endswith('/'+name)]
 if len(rows)!=1:raise ValueError('normal TU ambiguous: '+name)
 row=rows[0];command=row.get('arguments')or shlex.split(row['command']);flags=[];at=1
 while at<len(command):
  value=command[at]
  if value in ['-o','-MQ','-MF','-MT']:at+=2;continue
  if value in ['-c','-MD','-MMD']or value==row['file']:at+=1;continue
  flags.append(value);at+=1
 argv=[command[0],*flags,'-E','-P',row['file'],'-o',str(output)];run=subprocess.run(argv,cwd=row['directory'],capture_output=True)
 output.with_suffix('.stdout').write_bytes(run.stdout);output.with_suffix('.stderr').write_bytes(run.stderr)
 if run.returncode:raise RuntimeError('actual normal TU preprocessing failed')
 source=(Path(row['directory'])/row['file']).resolve();sites=calls(source.read_text());expanded=output.read_text();actual={int(v)for v in re.findall(r'GNUNET_get_log_call_status\s*\([^;]*?__func__, ([0-9]+)\)',expanded)}
 checked=[site for site in sites if site['macro']!='GNUNET_break']
 for site in checked:
  site['normal_profile_active']=site['end_line']in actual
 return {'source':str(source),'source_sha256':sha(source),'compile_file':row['file'],'argv':argv,'cwd':row['directory'],'exit_code':run.returncode,'output':str(output),'output_sha256':sha(output),'sites':sites,'actual_policy_lines':sorted(actual)}
