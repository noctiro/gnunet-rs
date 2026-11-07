#!/usr/bin/env python3
import pathlib,subprocess,json,hashlib,zipfile,random,time,sys,argparse
ROOT=pathlib.Path(__file__).resolve().parents[1]
C=None;R=None;OUTPUT=None;UCD15=None;UCD18=None;LIBIDN2=None
def compare(cases,name,allow_errors=False):
 t=time.monotonic(); h=hashlib.sha256(); c_digest=hashlib.sha256();r_digest=hashlib.sha256();bad=[];n=0;accepted=0;errors={};variances=[];norm_bad=[];mismatch_count=0
 batch=[]
 def run():
  nonlocal n,accepted,mismatch_count
  data=''.join(op+'\t'+b.hex()+'\n' for op,b,*_ in batch).encode();h.update(data)
  a=subprocess.run([str(C)],input=data,capture_output=True,check=True).stdout
  p=subprocess.run([str(R)],input=data,capture_output=True)
  if p.returncode:raise RuntimeError(p.stderr.decode())
  b=p.stdout
  c_digest.update(a);r_digest.update(b)
  aa=a.decode().splitlines();bb=b.decode().splitlines();assert len(aa)==len(batch)==len(bb)
  for case,x,y in zip(batch,aa,bb):
   n+=1;accepted+=x.startswith('0\t');errors[x.split('\t')[0]]=errors.get(x.split('\t')[0],0)+1
   equal=x==y or (allow_errors and not x.startswith('0\t') and not y.startswith('0\t'))
   if x!=y:
    item={'op':case[0],'hex':case[1].hex(),'text':case[1].decode('utf8','replace'),'c':x,'rust':y}
    if equal:variances.append(item)
    else:
     mismatch_count+=1
     if len(bad)<300:bad.append(item)
   if len(case)==3:
    expected='0\t'+case[2].hex()
    if x!=expected or y!=expected:norm_bad.append({'hex':case[1].hex(),'expected':expected,'c':x,'rust':y})
  batch.clear()
 for case in cases:
  batch.append(case)
  if len(batch)==4096:run()
 if batch:run()
 result={'name':name,'cases':n,'c_success':accepted,'c_error_counts':errors,'input_sha256':h.hexdigest(),'c_output_sha256':c_digest.hexdigest(),'rust_output_sha256':r_digest.hexdigest(),'mismatches':bad,'mismatch_count':mismatch_count,'diagnostic_variances':variances,'normative_mismatches':norm_bad,'exact_native_errors':not allow_errors,'elapsed_seconds':time.monotonic()-t}
 (OUTPUT/(name+'.json')).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
 print(name,n,'accepted',accepted,'mismatches',len(bad),'seconds',round(result['elapsed_seconds'],2),flush=True)
 if bad:print(json.dumps(bad[:8],ensure_ascii=False,indent=2),flush=True)
 return result

def normal():
 with zipfile.ZipFile(UCD15) as z:text=z.read('NormalizationTest.txt').decode()
 for l in text.splitlines():
  l=l.split('#')[0].strip()
  if not l or l.startswith('@'):continue
  cells=l.split(';')[:5]
  for i,seq in enumerate(cells):
   b=''.join(chr(int(c,16)) for c in seq.split()).encode()
   expected=''.join(chr(int(c,16)) for c in cells[1 if i<3 else 3].split()).encode()
   if b'\0' not in b:yield 'N',b,expected

def normal15():
 for _,b,expected in normal():yield 'M',b,expected

def normal18():
 with zipfile.ZipFile(UCD18) as z:text=z.read('NormalizationTest.txt').decode()
 for l in text.splitlines():
  l=l.split('#')[0].strip()
  if not l or l.startswith('@'):continue
  cells=l.split(';')[:5]
  for i,seq in enumerate(cells):
   b=''.join(chr(int(c,16)) for c in seq.split()).encode()
   expected=''.join(chr(int(c,16)) for c in cells[1 if i<3 else 3].split()).encode()
   if b'\0' not in b:yield 'N',b,expected

def expanded_nfc():
 for n in [125,127,128,129,253,254]:yield 'N',('\U0001d15e'*n).encode(),('\U0001d157\U0001d165'*n).encode()

def parsed_label():
 yield 'W',b'\x0dxn--bcher-kva\0','15:bücher'.encode()

def compressed_name():
 cases=[]
 def add(data,off=0):cases.append((data,off))
 add(bytes.fromhex('0178c00400'));add(bytes.fromhex('01780179c00600'))
 add(bytes.fromhex('c00200'));add(bytes.fromhex('017800'))
 for label in [b'\0',b'x\0y',b'.',b'xn--',b'\xff',b'a',b'xn--bcher-kva']:
  add(b'\x01x\xc0\x04'+bytes([len(label)])+label+b'\0')
 for repeat in [10,20,40,48]:
  label=b'xn--'+('\U00020000'*repeat).encode('punycode');wire=bytes([len(label)])+label+b'\0'
  add(wire);add(wire+b'\xc0\0',len(wire));add(wire+b'\x01x\xc0\0',len(wire))
 for depth in [1,2,32,33,34]:
  add(b''.join(bytes([0xc0|(((i+1)*2)>>8),((i+1)*2)&255]) for i in range(depth))+b'\0')
  data=bytearray()
  for i in range(depth):
   target=(i+1)*4;data+=b'\x01x'+bytes([0xc0|(target>>8),target&255])
  data+=b'\0';add(bytes(data))
 rng=random.Random(0x10355891)
 alphabet=[b'a',b'EXAMPLE',b'\0',b'x\0y',b'.',b'xn--',b'\xff',b'xn--bcher-kva',b'xn--e28h',b'xn--'+('\U00020000'*20).encode('punycode')]
 for _ in range(1200):
  groups=[[rng.choice(alphabet) for _ in range(rng.randrange(0,4))] for _ in range(rng.randrange(2,7))]
  if 1+sum(sum(1+len(label) for label in group) for group in groups)>255:continue
  data=bytearray()
  for g,group in enumerate(groups):
   for label in group:data+=bytes([len(label)])+label
   if g+1<len(groups):
    t=len(data)+2;data+=bytes([0xc0|(t>>8),t&255])
   else:data+=b'\0'
  add(bytes(data))
 assert len(cases)==1233
 for data,off in cases:yield 'X',off.to_bytes(2,'big')+data

def compressed_record():
 label=b'xn--j50iaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
 data=bytearray([0,0,5,0,1,0,0,0,0,0,2,0xc0,13]);data+=bytes([len(label)])+label+b'\0';data+=b'\0'*(200-len(data))
 yield 'Y',bytes(data),('13:'+'\U00020000'*40).encode()

def dns_flags():
 for bits in range(65536):yield 'F',bits.to_bytes(2,'big')

def dns_constants():
 yield 'G',b''

def dns_header():
 for value in range(65536):
  data=b''.join(n.to_bytes(2,'big') for n in [value^0x1234,value^65535,value,value^0x55aa,(value+1)&65535,((value<<8)|(value>>8))&65535])
  yield 'H',data

def scalar():
 for cp in range(1,0x110000):
  if 0xd800<=cp<=0xdfff:continue
  b=chr(cp).encode()
  yield 'A',b
  yield 'A',b'a'+b+b'b'
  yield 'U',b

def selected():
 s=['','.', '..','.a','a..b','EXAMPLE','a.','ß','ẞ','é','e\u0301','ς','σ','😀','xn--e28h','xn--a','xn--_','xn--a_','xn--aa_','xn--abc-','XN--BCHER-KVA','xn--bcher-kva','a@b','a_b','_sip._tcp','-abc','ab--cd','abc-','l·l','a·b','·','\u0375α','\u0375a','א׳','a׳','カ・ナ','a・b','・','ا١۱','ا١1','ا1١','aا','اa','א_\u05b0','א_','\u200c','क्\u200c','क्\u200d','ب\u200cب','بَ\u200cَب','a\u200cb','\u0378','\u1c89','\U0001cc00','\U0002ebf0','a。b','a．b','a｡b','\u00ad','\u00adA','a\u00a0b','a\ufeffb']
 s+=['a'*n for n in [62,63,64,253,254,255]]
 s+=['a.'*n+'b' for n in [125,126,127,128]]
 s+=['é'*n for n in [56,57,58,59,60,61,62,63,64,254,255]]
 s+=['\u00ad'*n for n in [254,255,1000,32767]]
 for t in s:
  yield 'A',t.encode();yield 'U',t.encode()

def properties():
 for line in (LIBIDN2/'lib/Idna2008.txt').read_text().splitlines():
  raw=line.split('#')[0].strip()
  if not raw:continue
  area,status=raw.split(';');status=status.strip()
  if status not in ('PVALID','CONTEXTJ','CONTEXTO'):continue
  a,*b=area.strip().split('..');a=int(a,16);b=int(b[0],16) if b else a
  for cp in range(a,b+1):yield 'P',chr(cp).encode()

def idna15():
 import re
 def unescape(t):
  return re.sub(r"\\u([0-9A-Fa-f]{4})|\\x\{([0-9A-Fa-f]+)\}",lambda m:chr(int(m[1] or m[2],16)),t)
 for line in (ROOT/'data/IdnaTestV2-15.1.0.txt').read_text().splitlines():
  raw=line.split('#')[0].strip()
  if not raw:continue
  cells=[s.strip() for s in raw.split(';')]
  inherited=[cells[0],cells[1] or cells[0]]
  inherited.append(cells[3] or inherited[1]);inherited.append(cells[5] or inherited[2])
  for cell in inherited:
   assert not cell.startswith('['), 'A data column was mistaken for a status column'
   text=unescape(cell);b=text.encode('utf8','surrogatepass')
   # Explicit byte input excludes the C terminator/trailing storage. Invalid
   # UTF8 is tested, but an interiorNUL is a separate source-contract boundary.
   assert b'\0' not in b, 'Review new interior-NUL official test boundary explicitly'
   yield 'A',b;yield 'U',b

def alabels():
 for cp in range(128,0x110000):
  if 0xd800<=cp<=0xdfff:continue
  b=b'xn--'+chr(cp).encode('punycode')
  yield 'A',b;yield 'U',b

def context():
 # Every old PVALID/Context scalar as a joining/virama neighbour of each JoinControl.
 for _,b in properties():
  s=b.decode()
  for t in (s+'\u200cب','ب\u200c'+s,s+'\u200dب',s+'\u094d\u200dب','ب'+s+'\u200c'+s+'ب'):
   yield 'A',t.encode()
 # Deterministic script, digit, transparent-chain and punctuation permutations.
 alphabet=['a','1','-', '_','א','ب','ل','م','\u064e','\u0651','\u200c','\u200d','\u094d','क','١','۱','・','カ','l','·','α','͵','׳','𑜞','ᬺ','ᬼ','ᭂ']
 rng=random.Random(0x58925893)
 for _ in range(50000):
  text=''.join(rng.choices(alphabet,k=rng.randrange(1,12)))
  yield 'A',text.encode();yield 'U',text.encode()

def invalid_utf8():
 for a in range(1,256):
  for b in [b'',*[bytes([n]) for n in range(1,256)]]:
   data=bytes([a])+b
   yield 'A',data;yield 'U',data
 for b in [b'\xc0\x80',b'\xe0\x80\x80',b'\xed\xa0\x80',b'\xed\xbf\xbf',b'\xf4\x90\x80\x80',b'\xf0\x80\x80\x80',b'\xe2\x82',b'\xf0\x9f\x98',b'\xf5\x80\x80\x80']:
  yield 'A',b;yield 'U',b

def puny_fuzz():
 rng=random.Random(0x3492);alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-!@ '
 for _ in range(100000):
  b=('xn--'+''.join(rng.choices(alphabet,k=rng.randrange(0,80)))).encode()
  yield 'A',b;yield 'U',b

if __name__=='__main__':
 parser=argparse.ArgumentParser()
 parser.add_argument('modes',nargs='*',choices=['selected','normal','normal15','normal18','scalar','properties','idna15','alabels','context','puny_fuzz','expanded_nfc','invalid_utf8','parsed_label','compressed_name','compressed_record','dns_flags','dns_constants','dns_header'])
 for name in ['c-probe','rust-probe','ucd15','ucd18','libidn2-source','output']:parser.add_argument('--'+name,type=pathlib.Path,required=True)
 args=parser.parse_args();OUTPUT=args.output.resolve();assert not OUTPUT.is_relative_to(ROOT) and not ROOT.is_relative_to(OUTPUT),'Receipt output and source must be disjoint';OUTPUT.mkdir(parents=True,exist_ok=True)
 C=args.c_probe.resolve();R=args.rust_probe.resolve();UCD15=args.ucd15.resolve();UCD18=args.ucd18.resolve();LIBIDN2=args.libidn2_source.resolve()
 modes=args.modes or ['selected','normal','normal15','normal18','scalar','properties','idna15','alabels','context','puny_fuzz','expanded_nfc','invalid_utf8','parsed_label','compressed_name','compressed_record','dns_flags','dns_constants','dns_header']
 for m in modes:compare(globals()[m](),m,allow_errors=m=='puny_fuzz')
