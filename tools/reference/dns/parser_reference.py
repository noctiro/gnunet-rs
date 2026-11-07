import argparse,hashlib,json,pathlib,shlex,subprocess
parser=argparse.ArgumentParser(description="Run safe actual normal-C DNSPARSER observations, without network I/O.")
for key in ('source','build','library','idn2-library','output'):parser.add_argument('--'+key,type=pathlib.Path,required=True)
args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
src=args.source.resolve();build=args.build.resolve()
probe=pathlib.Path(__file__).resolve().parent/'parser_probe.c' 
commands=[];observations=[]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
source_names=['src/lib/util/dnsparser.c','src/lib/util/dnsstub.c','src/include/gnunet_dnsparser_lib.h','src/include/gnunet_dnsstub_lib.h','src/include/gnunet_tun_lib.h','src/include/gnunet_time_lib.h','src/lib/util/time.c']
source_hashes={p:sha(src/p) for p in source_names}
lib=args.library.resolve();libhash=sha(lib)
def command(argv,cwd=None):
 p=subprocess.run(list(map(str,argv)),cwd=cwd,capture_output=True,text=True,errors='backslashreplace');item={'argv':list(map(str,argv)),'cwd':str(cwd) if cwd else None,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr};commands.append(item);assert p.returncode==0,item;return p.stdout
assert command(['git','-C',src,'rev-parse','HEAD']).strip()=='346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
assert not command(['git','-C',src,'status','--porcelain','--untracked-files=no']).strip()
unit=next(e for e in json.loads((build/'compile_commands.json').read_text()) if e['file'].endswith('/dnsparser.c'))
raw=shlex.split(unit['command']);flags=[];i=0
while i<len(raw):
 if raw[i] in ('-o','-MQ','-MF'):i+=2;continue
 if raw[i] in ('-MD','-c') or raw[i]==unit['file']:i+=1;continue
 flags.append(raw[i]);i+=1
macros=command([*flags,'-E','-dM',unit['file']],cwd=build);assert '#define HAVE_LIBIDN2 1' in macros;assert '#define NDEBUG' not in macros
(out/'preprocessor.txt').write_text(macros)
assert (build/unit['file']).resolve()==src/'src/lib/util/dnsparser.c'
driver=out/'parser-probe';command([*flags,probe,'-L'+str(lib.parent),'-Wl,-rpath,'+str(lib.parent),'-lgnunetutil',str(args.idn2_library.resolve()),'-o',driver],cwd=build)
(out/'compile-flags.json').write_text(json.dumps({'build':str(build),'flags':flags,'library':str(lib)},indent=2)+'\n')
symbols=command(['nm','-gU',lib]);exports=sorted(line.split()[-1].lstrip('_') for line in symbols.splitlines() if 'GNUNET_DNSPARSER_' in line or 'GNUNET_DNSSTUB_' in line)
assert len([s for s in exports if s.startswith('GNUNET_DNSPARSER_')])==34
assert len([s for s in exports if s.startswith('GNUNET_DNSSTUB_')])==7
corpus=out/'parser-inputs';corpus.mkdir(exist_ok=True)
def observe(name,mode,data=None,*args):
 argv=[driver,mode]
 if data is not None:
  path=corpus/(name+'.bin');path.write_bytes(data);argv.append(path)
 argv.extend(map(str,args));value=json.loads(command(argv));observations.append({'id':name,'mode':mode,'input':str(path.relative_to(out)) if data is not None else None,'args':list(map(str,args)),'observation':value,'command_index':len(commands)-1});return value
observe('actual-idna-and-wire-profile','profile')
names=['','.','..','a.','.a','a..b','ExAmple.COM','faß.de','ẞ.de','bücher.example','e\u0301.example','é.example','σ.gr','ς.gr','مثال.إختبار','xn--bcher-kva.example','xn--invalid','a_b.example','-a','a-','ab--cd','@','_sip._tcp.example','a'*63,'a'*64,'.'.join(['a'*63]*3+['a'*61]),'.'.join(['a'*63]*3+['a'*62]),'a。b','Ａ.example','a\u200db','\u0378.example','😀.example']
for i,name in enumerate(names):observe('name-check-%02d'%i,'check',name.encode(),4096)
for i,name in enumerate([b'\xff',b'a\0hidden']):observe('raw-name-check-%d'%i,'check',name,4096)
for value in [b'',b'a',b'a.example']:
 for cap in [0,1,2,3,10,11,12]:observe('name-cap-'+str(len(value))+'-'+str(cap),'check',value,cap)
plain=b'\x03www\x07example\x03com\0'
for name,data,off in [('root',b'\0',0),('plain',plain,0),('pointer',plain+b'\xc0\x00',len(plain)),('prefix-pointer',plain+b'\x01x\xc0\x00',len(plain)),('forward-pointer',b'\xc0\x02'+plain,0),('pointer-root',b'\0\xc0\0',1),('cycle',b'\xc0\0',0),('out-of-range',b'\xc0\xff',0),('reserved40',b'\x40\0',0),('reserved80',b'\x80\0',0),('punycode',b'\x0dxn--bcher-kva\0',0),('invalid-alabel',b'\x04xn--\0',0),('label-with-dot',b'\x03a.b\0',0),('label-with-nul',b'\x03a\0b\0',0),('truncated-label',b'\x03ab',0)]:observe('parse-name-'+name,'name',data,off)
for depth in [32,33,34]:
 data=b''.join(bytes([0xc0|(((i+1)*2)>>8),((i+1)*2)&255]) for i in range(depth))+b'\0';observe('compression-depth-'+str(depth),'name',data,0)
for val in [b'',b'00aF',b'a',b'aZ',b'ZZ',b'1x',b' 1',b'-1',b'+1',b'0x']:
 observe('hex-'+val.hex(),'hex',val)
typed={}
for kind in ['query','mx','soa','srv','uri','cert']:
 v=observe('typed-'+kind,'typed',None,kind,4096);typed[kind]=bytes.fromhex(v['wire'])[3:]
 for cap in ([4,8,10] if kind!='uri' else []):observe('typed-'+kind+'-cap'+str(cap),'typed',None,kind,cap)
observe('all-deep-copy-and-free-families','duplicate')
for data,name in [(plain+b'\xff\xff\0\3','full'),(plain+b'\0\1','short-line')]:observe('query-'+name,'query',data,0)
def rr(typ,payload,ttl=123,owner=b'\x07example\0'):
 return owner+typ.to_bytes(2,'big')+b'\0\3'+ttl.to_bytes(4,'big')+len(payload).to_bytes(2,'big')+payload
for typ in [2,5,12,39]:observe('hostname-record-'+str(typ),'record',rr(typ,b'\xc0\0'),0)
for typ in [1,28,16,257,65000]:observe('raw-record-'+str(typ),'record',rr(typ,b'\1\2\3'),0)
for kind,typ in [('mx',15),('soa',6),('srv',33),('uri',256)]:observe('structured-record-'+kind,'record',rr(typ,typed[kind]),0)
for ttl in [0,1,0xffffffff]:observe('record-ttl-'+str(ttl),'record',rr(1,b'\1\2\3\4',ttl),0)
for typ in [0,1,2,5,6,12,15,28,33,37,39,256,257,65000]:observe('pack-type-'+str(typ),'pack',None,typ,4096)
for policy in ['future','subsecond','never']:observe('pack-ttl-'+policy,'pack',None,1,4096,policy)
for cap in [12,20,29,30,45]:observe('pack-two-query-cap-'+str(cap),'pack',None,0,cap)
header=lambda q,a,ns=0,ad=0:b'\x12\x34\xff\xff'+q.to_bytes(2,'big')+a.to_bytes(2,'big')+ns.to_bytes(2,'big')+ad.to_bytes(2,'big')
q=plain+b'\0\1\0\1';raw=rr(65000,b'xyz')
for name,packet in [('empty',header(0,0)),('one-query',header(1,0)+q),('all-sections',header(1,1,1,1)+q+raw+raw+raw),('trailing',header(0,0)+b'trailing'),('short-counted-query',header(1,0)),('short-header',b'\0'*11),('uri-roundtrip',header(0,1)+rr(256,typed['uri']))]:observe('packet-'+name,'packet',packet,0)
assert libhash==sha(lib);assert source_hashes=={p:sha(src/p) for p in source_names}
result={'status':'observed','source_revision':'346358e26d4dcc2dc4f51bef5d52dca29c7d8165','source_inputs':source_hashes,'source_and_library_unchanged':True,'library':{'path':str(lib),'sha256':libhash},'idna_library':{'path':str(args.idn2_library.resolve()),'sha256':sha(pathlib.Path(str(args.idn2_library.resolve())))},'compile_unit':unit,'preprocessor_sha256':sha(out/'preprocessor.txt'),'exports':exports,'driver_source_sha256':sha(probe),'driver_sha256':sha(driver),'observations':observations,'commands':commands,'limitations':['No network APIs invoked in this parser probe.','Positive CERT parse_record path is deliberately excluded because source falls through to raw copy after parse_cert consumed input, creating a known out-of-bounds risk. Low-level CERT parser/builder/copy/free are exercised safely.','Packet maxima below 12 and query capacities below 4 are excluded because upstream writes/asserts outside that domain.','URI boundary-overrun cases and dangling/malformed C pointers are not executed; source findings are separate from observations.']}
(out/'parser-result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':'observed','cases':len(observations),'out':str(out/'parser-result.json')}))
