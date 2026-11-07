#!/usr/bin/env python3
"""Source-level whole-translation-unit inventory, not API completion evidence."""
import argparse,hashlib,json,re
from pathlib import Path
FILES=['src/lib/util/program.c','src/lib/util/getopt.c','src/lib/util/getopt_helpers.c','src/lib/util/common_logging.c','src/lib/util/speedup.c']
HEADERS=['src/include/gnunet_program_lib.h','src/include/gnunet_getopt_lib.h','src/include/gnunet_common.h','src/lib/util/speedup.h']
def masked(text):
    return re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',lambda m:''.join('\n'if x=='\n'else' 'for x in m[0]),text,flags=re.S)
def inventory(source):
    rows=[];hashes={}
    for name in FILES+HEADERS:
        path=source/name;raw=path.read_bytes();hashes[name]=hashlib.sha256(raw).hexdigest()
        if name in HEADERS:continue
        text=raw.decode();plain=masked(text)
        for match in re.finditer(r'(?m)^([A-Za-z_]\w*)\s*\(',plain):
            pos=match.end();balance=1
            while pos<len(plain)and balance:
                balance+=(plain[pos]=='(')-(plain[pos]==')');pos+=1
            while pos<len(plain)and plain[pos].isspace():pos+=1
            if pos==len(plain)or plain[pos]!='{':continue
            end=pos+1;balance=1
            while end<len(plain)and balance:
                balance+=(plain[end]=='{')-(plain[end]=='}');end+=1
            name_=match[1];rows.append({'file':name,'name':name_,'line':text.count('\n',0,match.start())+1,'definition_sha256':hashlib.sha256(text[match.start():end].encode()).hexdigest(),'public_name':name_.startswith('GNUNET_'),'implementation':'pending','evidence':[]})
    return {'revision':'346358e26d4dcc2dc4f51bef5d52dca29c7d8165','source_inputs':hashes,'definitions':rows,'definition_count':len(rows),'public_definition_count':sum(r['public_name']for r in rows),'owner_complete':False}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.write_text(json.dumps(inventory(a.source),indent=2)+'\n')
