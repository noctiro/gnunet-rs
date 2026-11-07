#!/usr/bin/env python3
"""Actual C-built and Rust-built signed plugin blocks, each checked by both implementations."""
import argparse,hashlib,json,os,pathlib,subprocess,sys,time
from compare import sha,local_inputs,PIN
from common import normal,disjoint,successful,require,trace_differences,require_probe,reference_inputs

def main():
 p=argparse.ArgumentParser();p.add_argument('--package',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]);p.add_argument('--normal-receipt',type=pathlib.Path,required=True);p.add_argument('--c-probe',type=pathlib.Path,required=True);p.add_argument('--rust-probe',type=pathlib.Path,required=True);p.add_argument('--rust-vectors',type=pathlib.Path,required=True);p.add_argument('--reference-helper',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();a.package=a.package.resolve();r=json.loads(a.normal_receipt.read_text());c=json.loads(a.c_probe.read_text());require((r['status'] == 'passed' and c['status'] == 'passed' and r['source_unchanged']), 'verification invariant failed: signed_compare.py:8');sys.path.insert(0,str(a.reference_helper.resolve().parent));from build_reference import source_state
 normal(a.normal_receipt,a.reference_helper);require_probe(c,a.normal_receipt,a.reference_helper,pathlib.Path(__file__).resolve().parent);reference_before=reference_inputs(r,a.reference_helper);disjoint(a.output,[a.package,r['source'],r['build'],r['prefix'],a.normal_receipt.parent]);a.output.mkdir(parents=True,exist_ok=False);upstream=source_state(pathlib.Path(r['source']));require((upstream == r['upstream'] and upstream['revision'] == PIN), 'verification invariant failed: signed_compare.py:9')
 bound=[{'path':p,'sha256':h}for p,h in c['compiler_artifacts'].items()]+[{'path':p,'sha256':h}for p,h in c['compiler_header_inputs'].items()]+[{'path':p,'sha256':h}for p,h in c['normal_reference_inputs'].items()]+r['libraries']+r['plugins']+[r['compile_commands'],r['generated_config'],c['source'],c['binary'],c['builder'],c['receipt'],c['common'],c['reference_helper']]+[{'path':str(x),'sha256':sha(x)}for x in [a.normal_receipt,a.c_probe,a.rust_probe,a.rust_vectors,a.reference_helper]]
 for item in bound:require((sha(item['path']) == item['sha256']), item)
 inputs=local_inputs(a.package);env={k:v for k,v in os.environ.items()if not k.startswith('GNUNET_')};env.update(r['runtime_environment']);commands=[];cbin=c['binary']['path'];utc=time.time_ns()//1000;ts=utc-1000000
 def execute(name,argv,data):
  proc=subprocess.run(list(map(str,argv)),input=data.encode(),capture_output=True,cwd=a.output,env=env,timeout=180);(a.output/(name+'.stdin')).write_text(data);(a.output/(name+'.stdout')).write_bytes(proc.stdout);(a.output/(name+'.stderr')).write_bytes(proc.stderr);commands.append({'name':name,'argv':list(map(str,argv)),'exit_code':proc.returncode});successful(proc,name);return proc.stdout.decode('ascii').splitlines()
 vectors=[]
 for line in execute('rust-build',[a.rust_vectors,str(ts),r['hello_profile']],''):
  label,kind,wire=line.split();vectors.append({'origin':'rust','label':label,'kind':int(kind),'bytes':wire})
 seq=0
 def sign(kind,region,seed='2a'*32):
  nonlocal seq
  seq+=1;out=execute(f'c-sign-{seq}',[cbin],f'E {kind} {seed} {region.hex()}\n');require((len(out) == 1), 'verification invariant failed: signed_compare.py:21');tag,pub,sig=out[0].split();require((tag == 'E'), 'verification invariant failed: signed_compare.py:21');return bytes.fromhex(pub),bytes.fromhex(sig)
 def emit(label,kind,wire):vectors.append({'origin':'c','label':label,'kind':kind,'bytes':wire.hex()})
 def u32(n):return n.to_bytes(4,'big')
 def u64(n):return n.to_bytes(8,'big')
 public,_=sign(65556,u32(8)+u32(17))
 for n in [0,1,64,4096]:
  region=u32(40+n)+u32(17)+public+bytes(i%256 for i in range(n));_,sig=sign(65556,region);emit(f'fs-{n}',9,sig+region)
 for expiry in [0,2**64-1]:
  region=u32(48)+u32(11)+u64(expiry)+public;_,sig=sign(65556,region);emit(f'dns-{expiry}',10,sig+region)
  region=u32(80)+u32(18)+u64(expiry)+bytes([93])*64;_,sig=sign(65556,region);emit(f'regex-accept-{expiry}',23,region+public+sig)
  hello_expiry=max(1,expiry) # C builder reserves zero for its default lifetime.
  lines=execute(f'c-hello-{hello_expiry}',[cbin],f'H {"2a"*32} {hello_expiry}\n');require((len(lines) == 1 and lines[0].startswith('H ')), 'verification invariant failed: signed_compare.py:32');emit(f'hello-{hello_expiry}',13,bytes.fromhex(lines[0][2:]))
 for kind in [65536,65556]:
  for n in [0,1,16,65,65535]:
   payload=bytes(i%256 for i in range(n));region=u32(16+n)+u32(15)+u64(2**64-1)+payload;public,sig=sign(kind,region,'07'*32);emit(f'gns-{kind}-{n}',11,u32(112+n)+u32(kind)+public+sig+u64(2**64-1)+payload)
  public,_=sign(kind,u32(8)+u32(3),'07'*32);pk=u32(kind)+public;region=u32(52)+u32(3)+u64(ts)+pk;_,sig=sign(kind,region,'07'*32);proof=u64(ts)+u64(123)+b''.join(u64(i)for i in range(32))+pk+sig;emit(f'revocation-{kind}',12,b'\0'*4+u32(len(proof))+proof)
 rows=[]
 def case(label,kind,wire,operation,query='00'*64,xquery='-'):
  rows.append({'label':label+'-'+operation,'line':f'D {operation} {kind} {query} {xquery} {wire.hex() if wire else "-"}'})
 for vector in vectors:
  name=vector['origin']+'-'+vector['label'];kind=vector['kind'];b=bytes.fromhex(vector['bytes'])
  for op in ['V','K','R']:case(name,kind,b,op)
  corrupt=bytearray(b);off={9:0,10:0,11:40,12:316,13:32,23:112}[kind];corrupt[off]^=1
  for op in ['V','K','R']:case(name+'-bad-signature',kind,corrupt,op)
  if kind==13:
   altered=bytearray(b);altered[-2]^=1 # Valid address body, unchanged peer/expiry/signature.
   for op in ['V','K','R']:case(name+'-address-alter',kind,altered,op)
  if kind==11:
   for op in ['V','K','R']:case(name+'-trailing',kind,b+b'X',op)
  if kind==12:
   unsorted=bytearray(b);unsorted[32:40]=unsorted[24:32]
   for op in ['V','K']:case(name+'-unsorted',kind,unsorted,op)
   extended=bytearray(b+b'extra');extended[4:8]=u32(len(extended)-8)
   for op in ['V','K']:case(name+'-extended',kind,extended,op)
   ttl=bytearray(b);ttl[16:24]=u64(2**64-1)
   case(name+'-ignored-ttl',kind,ttl,'V')
 # Real group creation/seen/reply/serialization on both C-built and Rust-built
 # signed vectors. Imported nonce makes serialization deterministic; no entropy
 # is replaced. An all-FF imported filter and explicit mark_seen exercise true
 # duplicate classification independently of a second check_reply call.
 for vector in vectors:
  if vector['kind'] in [10,13,23] and not vector['label'].endswith('18446744073709551615'):continue
  name=vector['origin']+'-'+vector['label'];kind=vector['kind'];wire=bytes.fromhex(vector['bytes']);seen=hashlib.sha512(wire[:32]if kind==13 else wire).hexdigest()
  for mode,size in [(0,1),(1,8),(2,8),(1,0)]:
   for state in ['fresh','saturated','marked','short']:
    raw=(b'\x04\x03\x02\x01'+(b'\xff'*8 if state=='saturated'else b''))if state!='short'else b'bad'
    label=f'group-{name}-{mode}-{size}-{state}';rows.append({'label':label,'line':f'G {kind} {mode} {size} {raw.hex()} {seen if state=="marked"else "-"} {"00"*64} - {wire.hex()}'})
 for kind in [0,1,2,6,7,8,10,12,24,25,26,27,99]:
  wire=b'\0test';rows.append({'label':f'group-opaque-{kind}','line':f'G {kind} 1 8 04030201 - {"00"*64} - {wire.hex()}'})
 # Structured REGEX matrices: key proof remains correct; no destination OOB or
 # assertion preconditions are invoked. accept==1 early-return malformed token
 # length is defined by the C checker and tested, rather than normalized away.
 for accepting in [0,1,2,65535]:
  for token in [b'',b'a',b'ab',b'a\0b']:
   proof=b'proof\0bytes';block=len(proof).to_bytes(2,'big')+accepting.to_bytes(2,'big')+b'\0\1\0\1'+bytes([7])*64+b'\0\0'+len(token).to_bytes(2,'big')+proof+token;query=hashlib.sha512(proof).hexdigest()
   for op in ['V','K']:case(f'regex-{accepting}-{token.hex()}',22,block,op,query)
   for x in ['-','00','6100','61626300','61006200']:case(f'regex-{accepting}-{token.hex()}-x{x}',22,block,'R',query,x)
 early=b'\0\0\0\1\0\0\0\0trailing'
 for op in ['V','K','R']:case('regex-early-accept-trailing',22,early,op,hashlib.sha512(b'').hexdigest())
 # Recreate actual plugin contexts at their real config readpoint. A missing
 # required value prevents REV plugin loading; no fallback success is invented.
 for bits,epoch in [('0','86400000000'),('1','86400000000'),('2','86400000000'),('513','86400000000'),('4294967295','86400000000'),('4294967296','86400000000'),('18446744073709551615','86400000000'),('0','0'),('0','1'),('0','18446744073709551615'),('-','1'),('0','-')]:
  prefix=f'rev-config-{bits}-{epoch}';rows.append({'label':prefix,'line':f'T {bits} {epoch}'})
  for vector in vectors:
   if vector['kind']!=12:continue
   for operation in ['V','K','Q','R']:case(prefix+'-'+vector['origin']+'-'+vector['label'],12,bytes.fromhex(vector['bytes']),operation)
 require((rows and len({x['label'] for x in rows}) == len(rows)), 'verification invariant failed: signed_compare.py:87');data=''.join(x['line']+'\n'for x in rows);(a.output/'vectors.json').write_text(json.dumps(vectors,indent=2)+'\n');(a.output/'corpus.json').write_text(json.dumps(rows,indent=2)+'\n');observed={}
 observed['c']=execute('c-check',[cbin],data);observed['rust']=execute('rust-check',[a.rust_probe,str(utc),r['hello_profile']],data)
 for name,lines in observed.items():require((len(lines) == len(rows)), (name, len(lines), len(rows)))
 differences=trace_differences(rows,observed['c'],observed['rust'])
 profile_codes=[observed['c'][i].split()[3]for i,row in enumerate(rows)if row['label'].endswith('hello-18446744073709551615-address-alter-V')]
 require((profile_codes == (['1', '1'] if r['hello_profile'] == 'normal' else ['0', '0'])), profile_codes)
 # Both normal HELLO builders with the same fixed peer/expiry must emit exactly
 # the same block; this additionally pins the normal metadata-only profile.
 hello_equal=all(next(x['bytes']for x in vectors if x['origin']=='c'and x['label']==label)==next(x['bytes']for x in vectors if x['origin']=='rust'and x['label']==label)for label in ['hello-1','hello-18446744073709551615']);require((hello_equal), 'verification invariant failed: signed_compare.py:95')
 require((local_inputs(a.package) == inputs), 'verification invariant failed: signed_compare.py:96');require((source_state(pathlib.Path(r['source'])) == upstream), 'verification invariant failed: signed_compare.py:96')
 require(reference_inputs(r,a.reference_helper)==reference_before,'normal provider/generated-header input set changed')
 for item in bound:require((sha(item['path']) == item['sha256']), item)
 result={'status':'passed'if not differences else'failed','scope':'Two-way normal C-produced and Rust-produced signed plugin blocks and defined REGEX cases; real normal C UTC, explicit sampled Rust UTC only for stable zero/never/one-day vectors. Not clock-boundary or whole-owner proof.','vectors':len(vectors),'c_built':sum(x['origin']=='c'for x in vectors),'rust_built':sum(x['origin']=='rust'for x in vectors),'cases':len(rows),'differences':differences,'hello_profile':r['hello_profile'],'normal_hello_bytes_equal':hello_equal,'altered_address_validation_codes':profile_codes,'rust_utc':utc,'proof_timestamp':ts,'commands':commands,'inputs_before':inputs,'inputs_after':local_inputs(a.package),'bound_inputs':bound,'upstream':upstream,'source_unchanged':True};(a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'result':str(a.output/'result.json'),'vectors':len(vectors),'cases':len(rows),'differences':len(differences)}));require((not differences), differences[:10])
if __name__=='__main__':main()
