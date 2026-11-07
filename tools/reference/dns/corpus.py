import argparse,hashlib,json,pathlib
parser=argparse.ArgumentParser();parser.add_argument('--reference',type=pathlib.Path,required=True);parser.add_argument('--output',type=pathlib.Path,required=True);args=parser.parse_args();crate=args.output.resolve();crate.mkdir(parents=True,exist_ok=False);(crate/'tests').mkdir();base=args.reference.resolve();r=json.loads((base/'parser-result.json').read_text());allobs={o['id']:o for o in r['observations']};rows=[];matrix=[]
def query(v):return f"{v['name']}/{v['type']}/{v['class']}"
def record(v):
 d=v['data'];t=v['type']
 if t in (2,5,12,39):data='host:'+d
 elif t==15:data=f"mx:{d['preference']}:{d['host']}"
 elif t==33:data=f"srv:{d['priority']}:{d['weight']}:{d['port']}:{d['target']}"
 elif t==6:data=f"soa:{d['mname']}:{d['rname']}:{d['serial']}:{d['refresh']}:{d['retry']}:{d['expire']}:{d['minimum']}"
 elif t==256:data=f"uri:{d['priority']}:{d['weight']}:{d['target']}"
 else:data='raw:'+d
 return f"{v['name']}/{t}/{v['class']}/{data}"
def packet(v):return f"{v['id_bytes']}/{v['flags_bytes']}/"+'|'.join([';'.join(query(x)for x in v['questions']),*[';'.join(record(x)for x in v[k])for k in ('answers','authority','additional')]])
for o in r['observations']:
 id=o['id'];mode=o['mode'];v=o['observation'];raw=(base/o['input']).read_bytes()if o['input']else b'';action='pending';expected='';arg='';status='pending_idna';why='The wire-only proof excludes native IDNA; the separate complete gnunet-idna backend/composition proof is required.'
 if mode=='profile':action='profile';status='reference_profile';why='Bind actual libidn2 flags/version/layout, not a Rust capability.'
 elif mode=='name':
  action='name';arg=o['args'][0];expected=('1:'+str(v['off'])+':'+v['name'])if v['accepted']else'0';status='native_compare';why='Compression/offset/native ASCII name result.'
  if v['accepted']and any(x>=128 for x in bytes.fromhex(v['name'])):status='pending_idna';why='Wire decode executes, but native Unicode text conversion is outside this wire-only proof.';expected='accept:'+str(v['off'])
  if id=='parse-name-label-with-nul':status='lossless_wire_variance';why='Wire retains label NUL bytes; native C string truncates. No malformed string pointer is recreated.';expected='1:'+str(v['off'])+':'+b'a\0b'.hex()
 elif mode=='query':action='query';arg=o['args'][0];expected=query(v['query'])if v['rc']==1 else'error';status='native_compare';why='Type/class/name; transactional cursor on error intentionally stronger than C.'
 elif mode=='record':
  action='record';expected=record(v['record'])if v['rc']==1 else'error';status='native_compare';why='Typed/native metadata plus explicit clock TTL math.'
  if id=='structured-record-uri':status='rfc_correction';why='Native URI parser drops four bytes and rejects valid RDATA; Rust parses complete RFC7553 target.';rawbody=bytes.fromhex(allobs['typed-uri']['observation']['wire'])[3:];expected=f"6578616d706c65/256/3/uri:7:9:{rawbody[4:].hex()}"
 elif mode=='packet':
  action='packet';expected=packet(v)if v['accepted']else'error';status='native_compare';why='All sections/ID/flags/trailing acceptance, native ASCII fields.'
  if id=='packet-uri-roundtrip':status='rfc_correction';why='Valid URI packet succeeds after the documented native length correction.';body=bytes.fromhex(allobs['typed-uri']['observation']['wire'])[3:];expected='1234/ffff/|6578616d706c65/256/3/uri:7:9:'+body[4:].hex()+'||'
 elif mode=='hex':action='hex';expected=f"{v['encoded']}/{v['decoded']}";status='native_compare';why='Native lowerHEX and partial-pair conversion.'
 elif mode=='typed':
  kind=o['args'][0];action='typed';arg=kind;baseline=bytes.fromhex(allobs['typed-'+kind]['observation']['wire'])[3:];raw=baseline;expected=baseline.hex();status='native_compare';why='Actual C-generated standalone typed success bytes and values.'
  if kind=='cert':raw=baseline[:5]+baseline[6:];expected=raw.hex();status='rfc_correction';why='Discard nonprotocol native sixth padding octet; compare semantic CERT fields with RFC4398 five-byte header.'
  if kind=='uri':status='rfc_correction';why='C builder bytes are correct; Rust parser preserves full target instead of native four-byte truncation.'
  if v['builder_rc']!=1:action='typed-cap';arg=kind+':'+o['args'][1];expected='capacity';status='atomic_error_variance';why='Both refuse capacity, Rust intentionally preserves full output/cursor rather than a partially written numeric prefix.'
 elif mode=='pack':
  raw=bytes.fromhex(v['wire']);action='packet-wire';expected=raw.hex();status='native_compare';why='Actual C packed wire parsed and fully re-encoded at explicit equivalent TTL.'
  if id=='pack-type-37':
   i=12
   def skip(i):
    while raw[i]:i+=raw[i]+1
    return i+1
   i=skip(i)+4;i=skip(i);length=int.from_bytes(raw[i+8:i+10],'big');data=i+10;raw=raw[:i+8]+(length-1).to_bytes(2,'big')+raw[i+10:data+5]+raw[data+6:];expected=raw.hex();status='rfc_correction';why='CERT semantic projection strips native padding and fixes RDLEN.'
  if id=='pack-type-39':action='dname-native-defect';status='rfc_correction';why='C emits invalid zero-length DNAME; Rust safely rejects it and separately proves correct DNAME encode/decode.'
  if id.startswith('pack-two-query-cap-'):
   action='pack-two-query';arg=o['args'][1];count=0 if v['length']==12 else 1;fixed=bytearray(raw);fixed[4:6]=count.to_bytes(2,'big');expected=fixed.hex();status='rfc_correction';why='Correct actual emitted count and TC; preserve valid uncompressed bytes.'
 elif mode=='duplicate':action='duplicate';status='ownership_equivalence';why='C deep-copy/free families correspond to actual Rust independent Arena copies/drop lifetimes.'
 elif mode=='check':
  if v['builder_rc']==1:action='wire-projection';raw=bytes.fromhex(v['wire']);expected=raw.hex()
  why='Wire projection may execute for accepted C output, but native Unicode/checker validation is handled by the separate complete backend proof, including rejected cases and frontend capacity semantics.'
 rows.append('\t'.join((id,action,raw.hex(),arg,expected,status)))
 matrix.append({'id':id,'c_mode':mode,'execution_action':action,'classification':status,'reason':why})
assert len(rows)==153
(crate/'tests/c_corpus.tsv').write_text('\n'.join(rows)+'\n')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
(crate/'c-corpus-map.json').write_text(json.dumps({'source_receipt':str(base/'parser-result.json'),'source_sha256':sha(base/'parser-result.json'),'rows':matrix,'classifications':{k:sum(x['classification']==k for x in matrix)for k in sorted(set(x['classification']for x in matrix))},'no_full_idna_claim':True},indent=2)+'\n')
print('rows',len(rows))
