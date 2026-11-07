#!/usr/bin/env python3
"""Compile-only caller ownership diagnostic controls; never execute bad C."""
import argparse,json,sys,hashlib
from pathlib import Path
sys.dont_write_bytecode=True;sys.path.insert(0,str(Path(__file__).resolve().parent))
from normal_reference import load,compile_probe
p=argparse.ArgumentParser()
for key in ['output','repo','source','reference']:p.add_argument('--'+key,type=Path,required=True)
a=p.parse_args();o=a.output.resolve()
if o.exists():raise SystemExit('fresh output required')
o.mkdir(parents=True);r,inputs=load(a.reference,a.source,a.repo)
source='''#include "platform.h"\n#include "gnunet_util_lib.h"\nvoid owned_compile_only(struct GNUNET_CONFIGURATION_Handle *cfg){%s}\nint main(void){return 0;}\n'''
cases={'const_owned_transfer_rejected':('const char term[]="owned-compile-only";char *value=GNUNET_CONFIGURATION_expand_dollar(cfg,term);GNUNET_free(value);',True),'heap_owned_transfer_compiles':('char *value=GNUNET_CONFIGURATION_expand_dollar(cfg,GNUNET_strdup("owned-compile-only"));GNUNET_free(value);',False)}
rows=[]
for name,(body,rejected)in cases.items():
 f=o/(name+'.c');f.write_text(source%body);binary=o/name
 try:result=compile_probe(f,binary,r,strict_fixture=True);failure=None
 except RuntimeError as e:result=None;failure=str(e)
 compiler=json.loads(Path(str(binary)+'.compile.json').read_text());stderr=Path(str(binary)+'.compile.stderr').read_text()
 actual_rejected=compiler['exit_code']!=0
 if actual_rejected!=rejected:raise RuntimeError('unexpected compiler outcome: '+name)
 if rejected and ('discards qualifiers'not in stderr or '-Wincompatible-pointer-types-discards-qualifiers'not in stderr):raise RuntimeError('unexpected rejection diagnostic')
 rows.append({'name':name,'expected_rejection':rejected,'compiler':compiler,'source_sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'compiler_stderr_sha256':hashlib.sha256(stderr.encode()).hexdigest(),'result':result,'error':failure,'executed':False})
(o/'result.json').write_text(json.dumps({'status':'passed','scope':'only compile-time prototype/const transfer control, zero C actor execution, no stack-owned input is ever run','rows':rows,'normal_inputs':inputs},indent=2)+'\n')
