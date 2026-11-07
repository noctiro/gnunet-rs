#!/usr/bin/env python3
"""Finite BLOCK public API differential corpus; actors are test controls, not a wire protocol."""
import argparse,hashlib,json,os,pathlib,random,subprocess,sys,time
from common import normal,disjoint,successful,require,trace_differences,require_probe,reference_inputs
PIN='346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def corpus():
 rng=random.Random(0xB10C);rows=[]
 def put(label,line):rows.append({'label':label,'line':line})
 put('nullable-lifecycle','N')
 put('negative-merge-consumes-second','L')
 for size1,k1,size2,k2,nonce2 in [(8,16,8,16,0),(8,17,8,33,0),(8,16,8,16,1),(8,16,9,16,0),(0,16,0,16,0),(8,0,8,16,0),(8,16,8,0,1)]:
  put(f'merge-{size1}-{k1}-{size2}-{k2}-{nonce2}',f'J {size1} {k1} 00000000 {size2} {k2} {nonce2.to_bytes(4,sys.byteorder).hex()} {rng.randbytes(64).hex()}')
 for count in [0,1,2,3,32767,32768,32769,2**32-1]:
  for k in [0,1,16,17,2**31,2**32-1]:put(f'size-{count}-{k}',f'S {count} {k}')
 for nonce in [0,1,0x01020304,2**32-1]:
  for n in range(3):put(f'mingle-{nonce}-{n}',f'M {nonce} {rng.randbytes(64).hex()}')
 for n in [0,1,15,16,17,63,64,65,127,128,1024,4096]:put(f'pow-{n}',f'P {rng.randbytes(16).hex()} {rng.randbytes(n).hex() if n else "-"}')
 for size in [0,1,7,8,9,64,32768]:
  for k in [0,1,16,17,33,2**31,2**32-1]:
   for mode in ['exact','mismatch','short']:
    raw=rng.randbytes(size+4) if mode=='exact' else rng.randbytes(4 if mode=='mismatch' else 3)
    put(f'bloom-{size}-{k}-{mode}',f'B {size} {k} {raw.hex()} {rng.randbytes(64).hex()}')
 types=[0,1,2,6,7,8,9,10,11,12,13,22,23,24,25,26,27,99]
 for kind in types:
  for xq in ['-','00','6162','61006200']:
   put(f'query-{kind}-{xq}',f'D Q {kind} {"00"*64} {xq} -')
  for n in [0,1,7,8,63,103,104,111,112,176,280,316,379,380]:
   b=rng.randbytes(n).hex() if n else '-'
   for operation in ['V','K']:put(f'{operation}-{kind}-{n}',f'D {operation} {kind} {"00"*64} - {b}')
 # Maximum native size headers must reject on both32-bit and64-bit targets.
 for offset,kind,size,values in [(64,9,104,[2**32-1,2**32-2,2**32-64]),(4,12,380,[2**32-1,2**32-2,2**32-8])]:
  for value in values:
   block=bytearray(size);block[offset:offset+4]=value.to_bytes(4,'big')
   if kind==12:block[280:284]=(65556).to_bytes(4,'big')
   put(f'max-size-{kind}-{value}',f'D V {kind} {"00"*64} - {block.hex()}')
 # Reply callbacks deliberately do not repeat validation. Only source-defined
 # preconditions are admitted; no C asserts, OOB destinations or short proofs.
 for kind in [0,1,2,6,7,8,9,10,12,13,24,25,99]:
  for n in [0,1,17,112]:put(f'reply-{kind}-{n}',f'D R {kind} {"00"*64} - {rng.randbytes(n).hex() if n else "-"}')
 for kind in [26,27]:put(f'reply-set-{kind}',f'D R {kind} {"00"*64} - 000102')
 # GNS unknown type returns YES without modifying key (helper result ignored).
 unknown=bytearray(112);unknown[:4]=(112).to_bytes(4,'big');unknown[4:8]=(99).to_bytes(4,'big')
 for operation in ['V','K','R']:put(f'gns-unknown-{operation}',f'D {operation} 11 {"00"*64} - {unknown.hex()}')
 return rows

def local_inputs(package):
 from workspace_bridge import inputs
 return inputs(package)

def main():
 p=argparse.ArgumentParser();p.add_argument('--package',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]);p.add_argument('--normal-receipt',type=pathlib.Path,required=True);p.add_argument('--c-probe',type=pathlib.Path,required=True);p.add_argument('--rust-probe',type=pathlib.Path,required=True);p.add_argument('--reference-helper',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();a.package=a.package.resolve();a.output=a.output.resolve();r=json.loads(a.normal_receipt.read_text());c=json.loads(a.c_probe.read_text());require((r['status'] == 'passed' and r['source_unchanged'] and (c['status'] == 'passed')), 'verification invariant failed: compare.py:63');sys.path.insert(0,str(a.reference_helper.resolve().parent));from build_reference import source_state
 normal(a.normal_receipt,a.reference_helper);require_probe(c,a.normal_receipt,a.reference_helper,pathlib.Path(__file__).resolve().parent);reference_before=reference_inputs(r,a.reference_helper);disjoint(a.output,[a.package,r['source'],r['build'],r['prefix'],a.normal_receipt.parent]);a.output.mkdir(parents=True,exist_ok=False);before_source=source_state(pathlib.Path(r['source']));require((before_source == r['upstream'] and before_source['revision'] == PIN), 'verification invariant failed: compare.py:64')
 bound=[{'path':p,'sha256':h}for p,h in c['compiler_artifacts'].items()]+[{'path':p,'sha256':h}for p,h in c['compiler_header_inputs'].items()]+[{'path':p,'sha256':h}for p,h in c['normal_reference_inputs'].items()]+r['libraries']+r['plugins']+[r['compile_commands'],r['generated_config'],c['source'],c['binary'],c['builder'],c['receipt'],c['common'],c['reference_helper'],{'path':str(a.normal_receipt),'sha256':sha(a.normal_receipt)},{'path':str(a.rust_probe),'sha256':sha(a.rust_probe)},{'path':str(a.reference_helper),'sha256':sha(a.reference_helper)}]
 for item in bound:require((sha(item['path']) == item['sha256']), item)
 before=local_inputs(a.package);rows=corpus();require((rows and len(set((x['label'] for x in rows))) == len(rows)), 'verification invariant failed: compare.py:67');text=''.join(x['line']+'\n'for x in rows);(a.output/'corpus.json').write_text(json.dumps(rows,indent=2)+'\n');env={k:v for k,v in os.environ.items() if not k.startswith('GNUNET_')};env.update(r['runtime_environment']);observed={};start=time.monotonic()
 for name,binary in [('c',pathlib.Path(c['binary']['path'])),('rust',a.rust_probe)]:
  proc=subprocess.run([str(binary),*([str(time.time_ns()//1000),r['hello_profile']] if name=='rust' else [])],input=text.encode(),capture_output=True,env=env,cwd=a.output,timeout=180);(a.output/(name+'.stdout')).write_bytes(proc.stdout);(a.output/(name+'.stderr')).write_bytes(proc.stderr);successful(proc,name);lines=proc.stdout.decode('ascii').splitlines();require((len(lines) == len(rows)), (name, len(lines), len(rows)));observed[name]=lines
 differences=trace_differences(rows,observed['c'],observed['rust'])
 after=local_inputs(a.package);require((after == before), 'verification invariant failed: compare.py:71');require((source_state(pathlib.Path(r['source'])) == before_source), 'verification invariant failed: compare.py:71')
 require(reference_inputs(r,a.reference_helper)==reference_before,'normal provider/generated-header input set changed')
 for item in bound:require((sha(item['path']) == item['sha256']), item)
 result={'status':'passed' if not differences else 'failed','scope':'Actual normal unmodified C BLOCK/group/nine installed plugins versus Rust API actor; safe defined finite corpus. Not whole-owner acceptance.','cases':len(rows),'categories':{prefix:sum(x['label'].startswith(prefix)for x in rows)for prefix in ['nullable','size','mingle','pow','bloom','query','V-','K-','reply','gns-unknown']},'differences':differences,'upstream':before_source,'source_unchanged':True,'inputs_before':before,'inputs_after':after,'bound_inputs':bound,'seconds':time.monotonic()-start};(a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'result':str(a.output/'result.json'),'cases':len(rows),'differences':len(differences)}));require((not differences), differences[:3])
if __name__=='__main__':main()
