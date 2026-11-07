"""Finite deterministic fixture selection, not an exhaustive cryptographic proof."""
import random
from collections import Counter

def generate(points):
 r=random.Random(0x2901CAFE)
 def b(n):return r.randbytes(n)
 def h(data):return data.hex() or '-'
 rows=[]
 def add(op,*parts):rows.append(' '.join([op]+[h(x) if isinstance(x,bytes) else str(x) for x in parts]))
 for _ in range(80):
  seed,eph=b(32),b(32);add('ED',seed,eph)
  scalar=bytearray(b(32));scalar[0]&=248;scalar[31]&=127;scalar[31]|=64;add('PKEY',bytes(scalar),eph)
 for value in list(range(20))+list(range((1<<255)-19,(1<<255)+1)):
  for sign in (0,1):
   data=bytearray((value% (1<<255)).to_bytes(32,'little'));data[31]|=sign<<7;add('CONV',bytes(data))
 for point in points:add('CONV',bytes.fromhex(point.split()[-1]))
 for _ in range(192):add('CONV',b(32))
 for _ in range(256):add('DH',b(32),b(32))
 low=[bytes(32),(1).to_bytes(32,'little')]+[v.to_bytes(32,'little') for v in [(1<<255)-20,(1<<255)-19,(1<<255)-18]]
 # The two remaining nontrivial low-order u-coordinates from libsodium's public
 # blocklist; exercise their high-bit aliases too, not only u=0/1.
 low += [bytes.fromhex(x) for x in ['e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800','5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157']]
 for v in low:
  for mask in (0,128):
   v=bytearray(v);v[31]^=mask;v=bytes(v)
   add('DH',b(32),v);add('KEMP',b(32),v);add('DECAP',b(32),v);add('EDDECAP',b(32),v)
 for _ in range(80):add('KEM',b(32),b(32))
 for _ in range(128):add('KEMP',b(32),b(32));add('DECAP',b(32),b(32))
 for _ in range(32):add('EDDECAP',b(32),b(32))
 for _ in range(24):add('EDKEM',b(32))
 for n in [0,1,15,16,31,32,33,63,64,65,127,128,129,255,256,1024]:add('DERIVE',b(n));add('HASH',b(n))
 for n in [0,1,31,32,63,64,65,127,128,129,255,1024,65535]:
  for key in [0,32,64,128,129,257]:add('MAC',b(key),b(n))
 for _ in range(32):add('PUBKEY',b(32))
 for salt in [0,13,32,131]:
  for n in [0,1,31,32,33,63,64,65,127,255,1024,8160,8161]:add('HKDF',b(salt),b(70),b(19),n)
 for n in [0,1,15,16,17,31,32,63,64,65,255,1024,4095,65535]:
  for ad in [0,1,15,16,17,63]:add('AEAD',b(32),b(24),b(ad),b(n));add('CHACHA12',b(32),b(12),b(ad),b(n))
 for seq in [0,1,255,256,65535,(1<<32)-1,1<<32,(1<<64)-2,(1<<64)-1]:
  for role in 'ir':add('CAKE',b(32),b(32),b(32),b(64),seq,role)
 for counter in [0,1,255,256,(1<<32)-1]:
  for sequence in [0,1,255,256,1<<32,(1<<64)-1]:add('SEQ',b(32),counter.to_bytes(4,'big')+b(12),sequence)
 for n in [0,1,15,16,17,31,32,63,64,65,257,1024,65535]:add('TCP',b(32),b(n))
 for serial in [0,1,255,256,65535,1<<31,(1<<32)-1]:add('UDP',b(32),serial)
 return rows

def openings(rows,results):
 extra=[]
 assert len(rows)==len(results)
 for line,result in zip(rows,results):
  parts=line.split();fields=result.split()
  if parts[0]!='AEAD':continue
  _,key,iv,aad,_=parts;_,ok,ct,tag=fields;assert ok=='1'
  extra.append(' '.join(['OPEN',key,iv,aad,ct,tag]))
  def flip(h):
   data=bytearray.fromhex('' if h=='-' else h)
   if data:data[0]^=1
   else:data.append(1)
   return data.hex()
  base=[key,iv,aad,ct,tag]
  for i in range(5):
   bad=base.copy();bad[i]=flip(bad[i]);extra.append(' '.join(['OPEN']+bad))
  if ct!='-':extra.append(' '.join(['OPEN',key,iv,aad,ct[:-2] or '-',tag]))
 return extra

def summary(rows):return dict(Counter(line.split()[0] for line in rows))
