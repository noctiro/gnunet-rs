#!/usr/bin/env python3
"""Fresh actual normal-C native pack boundaries; only existing count correction."""
import argparse,pathlib,subprocess,json,hashlib,time
parser=argparse.ArgumentParser(description=__doc__)
for name in ['c-probe','rust-probe','output']:parser.add_argument('--'+name,type=pathlib.Path,required=True)
args=parser.parse_args()
PACKAGE=pathlib.Path(__file__).resolve().parents[1]
output=args.output.resolve()
assert not output.is_relative_to(PACKAGE) and not PACKAGE.is_relative_to(output),'Output and source must be disjoint'
assert not output.exists(),'Output must be new'
output.parent.mkdir(parents=True,exist_ok=True)
C=args.c_probe.resolve();R=args.rust_probe.resolve()
def n(label):return bytes([len(label)])+label+b'\0'
def packet(qs=(),an=(),ns=(),ad=(),tail=b''):
 return b'\x12\x34\x01\0'+b''.join(len(s).to_bytes(2,'big')for s in [qs,an,ns,ad])+b''.join([*qs,*an,*ns,*ad])+tail
def q(name):return name+b'\0\1\0\1'
def rr(typ,data,owner=n(b'OWNER.')):return owner+typ.to_bytes(2,'big')+b'\0\1'+b'\0'*4+len(data).to_bytes(2,'big')+data
cases=[]
def add(i,p,capacities):
 for cap in capacities:cases.append((i+'-cap'+str(cap),p,cap))
for ident,name in [('uppercase',n(b'EXAMPLE')),('embedded-nul',n(b'a\0b')),('raw-invalid-utf8',n(b'\xff')),('emoji-alabel',n(b'xn--e28h')),('raw-eacute',n('é'.encode())),('canonical-alabel',n(b'xn--9ca'))]:add(ident,packet([q(name)]),[512])
add('root-query',packet([q(b'\0')]),range(12,40))
add('wire-dot-label',packet([q(n(b'a..b'))]),range(12,50))
add('wire-trailing-dot-label',packet([q(n(b'a.'))]),range(12,50))
add('prefix-pointer-root',packet([q(b'\x01x\xc0\x14')],tail=b'\0'),range(12,50))
long=n(b'a'+b'.'*62);root=b'\0';trailing=n(b'TARGET.')
# Every cap across native owner reserve10 and each target/header's largest need.
for owner_name,owner in [('root',root),('long-early-empty',long),('trailing',n(b'OWNER.'))]:
 for typ,body in [(2,trailing),(5,trailing),(12,trailing),(15,b'\0\7'+long),(33,b'\0\1\0\2\0\3'+trailing),(6,long+trailing+b'\0'*20),(6,n(b'm')+long+b'\0'*20)]:add('type'+str(typ)+'-owner-'+owner_name+'-body'+body.hex()[:6],packet(an=[rr(typ,body,owner)]),range(12,180))
# Section-stopping lookup failure; all trailing sections continue.
validq=q(n(b'EXAMPLE'));badq=q(n(b'\xff'))
validr=rr(5,n(b'TARGET'));badr=rr(5,n(b'xn--e28h'))
add('multi-section-semantic',packet([validq,badq,validq],[validr,badr,validr],[validr],[validr]),range(12,180))
# Pointer native guard failure vs a complete packet with enough trailing context.
label=b'xn--'+('\U00020000'*40).encode('punycode')
p=packet([q(b'\xc0\x12')],tail=n(label));add('compression-native-guard',p,[512]);add('compression-native-whole-packet',p+b'\0'*(200-len(p)),[512])
start=time.monotonic();rows=[];bad=[]
for ident,data,cap in cases:
 c=json.loads(subprocess.run([str(C),data.hex(),str(cap)],capture_output=True,text=True,check=True).stdout)
 r=json.loads(subprocess.run([str(R),data.hex(),str(cap)],capture_output=True,text=True,check=True).stdout)
 if c.get('parsed') is False:equal=r.get('error')=='Malformed';projected=None
 elif 'error' in r:equal=False;projected=None
 else:
  wire=bytearray.fromhex(c['wire']);declared=[int.from_bytes(data[i:i+2],'big')for i in [4,6,8,10]];actual=[]
  for i,wanted in zip([4,6,8,10],declared):
   found=int.from_bytes(wire[i:i+2],'big');count=found if found==wanted else (found+1)&65535;actual.append(count);wire[i:i+2]=count.to_bytes(2,'big')
  projected=wire.hex();equal=projected==r['wire'] and (c['rc']==0)==r['truncated'] and actual==[r[x]for x in ['queries','answers','authority','additional']]
 row={'id':ident,'input':data.hex(),'maximum':cap,'c':c,'c_actual_count_projection':projected,'rust':r,'equal_after_existing_count_correction':equal};rows.append(row)
 if not equal:bad.append(row)
j={'status':'passed' if not bad else 'failed','comparisons':len(rows),'functional_mismatches':len(bad),'mismatches':bad,'observations':rows,'counts_projection':'Only known i-1 count bug corrected: when packed count differs from source declared count, actual emitted prefix count is(count+1)mod65536. All fixture source counts <=3. No new private protocol or acceptance scope.','binaries':{str(p):hashlib.sha256(p.read_bytes()).hexdigest()for p in [C,R]},'tool_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'elapsed_seconds':time.monotonic()-start};output.write_text(json.dumps(j,indent=2)+'\n');print('comparisons',len(rows),'mismatches',len(bad),'seconds',j['elapsed_seconds']);print(json.dumps(bad[:3],indent=2))

assert len(rows)==3846 and not bad, "native pack scope changed or actual C comparison failed"
