#!/usr/bin/env python3
"""Actual normal C public client -> Rust foreground host -> owned loopback DNS.
No production machine files are supplied, modified, overridden by config, or read
by the fixture. All packet fixtures are emitted by this script's own UDP socket.
"""
import argparse,hashlib,ipaddress,json,os,pathlib,signal,socket,subprocess,threading,time

def sha(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def qread(packet):
    pos=12;labels=[]
    while packet[pos]:
        n=packet[pos];pos+=1;labels.append(packet[pos:pos+n]);pos+=n
    pos+=1
    return b'.'.join(labels),int.from_bytes(packet[pos:pos+2],'big')
def wire(name): return b''.join(bytes([len(x)])+x for x in name.split(b'.'))+b'\0'
def reply(q,kind,payload):
    out=bytearray(q);out[2:4]=(0x8180).to_bytes(2,'big');out[6:8]=(1).to_bytes(2,'big')
    out+=b'\xc0\x0c'+kind.to_bytes(2,'big')+b'\0\1'+(3600).to_bytes(4,'big')+len(payload).to_bytes(2,'big')+payload
    return out
class Dns:
    def __init__(self):
        self.socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.socket.bind(('127.0.0.1',0));self.socket.settimeout(.1);self.queries=[];self.errors=[];self.stop=False
        self.thread=threading.Thread(target=self.run);self.thread.start()
    def run(self):
        while not self.stop:
            try:q,peer=self.socket.recvfrom(65535)
            except socket.timeout:continue
            except OSError as e:
                if not self.stop:self.errors.append(str(e))
                return
            try:
                name,kind=qread(q);self.queries.append({'name_hex':name.hex(),'kind':kind,'id_hex':q[:2].hex()})
                if name==b'cancel.example':continue
                if name==b'empty.example':self.socket.sendto(q,peer);continue
                data=ipaddress.IPv4Address('198.51.100.4').packed if kind==1 else ipaddress.IPv6Address('2001:db8::6').packed if kind==28 else wire(b'ptr6.example' if b'ip6.arpa' in name else b'ptr4.example')
                out=reply(q,kind,data)
                if name==b'malformed.example':
                    wrong=bytearray(out);wrong[0]^=0x40;self.socket.sendto(wrong,peer);self.socket.sendto(q[:12],peer)
                if name==b'unchecked.example':
                    out[2:4]=(0x0103).to_bytes(2,'big');out[len(q)-4:len(q)-2]=(15).to_bytes(2,'big');out[len(q)-2:len(q)]=(42).to_bytes(2,'big');out[len(q)+4:len(q)+6]=(55).to_bytes(2,'big')
                self.socket.sendto(out,peer)
            except Exception as e:self.errors.append(repr(e))
    def close(self):self.stop=True;self.thread.join(1);self.socket.close()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--package',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]);ap.add_argument('--build-receipt',type=pathlib.Path,required=True);ap.add_argument('--output',type=pathlib.Path,required=True);ap.add_argument('--client',type=pathlib.Path);ap.add_argument('--service',type=pathlib.Path);args=ap.parse_args()
    args.output=args.output.resolve();args.package=args.package.resolve()
    assert not args.output.is_relative_to(args.package) and not args.package.is_relative_to(args.output),'output/source must be disjoint'
    args.output.mkdir(parents=True,exist_ok=False);out=args.output;root=args.package;normal=json.loads(args.build_receipt.read_text());runtime=normal['runtime_environment'];environment={k:v for k,v in os.environ.items() if not k.startswith('GNUNET_')};environment.update(runtime,LC_ALL='C');base=out/'empty-base';base.mkdir();environment['GNUNET_BASE_CONFIG']=str(base)
    assert args.service and args.client,'fresh explicit fixture/client artifacts are required'
    service=args.service.resolve();client=args.client.resolve();cfg=out/'service.conf';unix=out/'r.sock';hosts=out/'hosts';resolv=out/'resolv';ready=out/'ready';stop=out/'stop';hosts.write_bytes(b'192.0.2.50 own-host.example\n');resolv.write_bytes(b'')
    # Reserve and release our own ephemeral address before the binder takes it.
    with socket.socket() as reserve:reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
    cfg.write_text(f'[resolver]\nUNIXPATH = {unix}\nHOSTNAME = 127.0.0.1\nPORT = {port}\nBINDTO = 127.0.0.1\nDISABLEV6 = YES\nACCEPT_FROM = 127.0.0.1;\nUNIX_MATCH_UID = NO\nUNIX_MATCH_GID = NO\nSTART_ON_DEMAND = NO\n')
    tcp=out/'tcp-client.conf';tcp.write_text(f'[resolver]\nHOSTNAME = 127.0.0.1\nPORT = {port}\nSTART_ON_DEMAND = NO\n')
    dns=Dns();stdout=(out/'service.stdout').open('wb');stderr=(out/'service.stderr').open('wb');process=None
    production=list((root/'src').rglob('*.rs'));sources=production+[root/'examples/fixture.rs',root/'tools/public_client.c',pathlib.Path(__file__).resolve(),root/'Cargo.toml',root.parents[1]/'Cargo.toml',root.parents[1]/'Cargo.lock'];upstream=pathlib.Path(normal['source']); sources += [upstream/'src/lib/util/resolver_api.c',upstream/'src/include/gnunet_resolver_service.h',upstream/'src/lib/util/resolver.h']; library=pathlib.Path(runtime['DYLD_LIBRARY_PATH'].split(':')[0])/'libgnunetutil.23.dylib'; inputs={str(p):sha(p) for p in sources};normal_library_hash=sha(library);hostfiles={p:sha(p) for p in ('/etc/hosts','/etc/resolv.conf')};r={'status':'failed','scope':'normal C public API + Rust actual Unix/TCP reactor and own loopback UDP, fixture files only','sources':inputs,'normal_build_receipt':{'path':str(args.build_receipt),'sha256':sha(args.build_receipt)},'binaries':{str(p):sha(p) for p in (service,client)},'normal_C_library':{'path':str(library),'sha256':normal_library_hash},'cases':[],'host_machine_files':hostfiles}
    try:
        argv=[str(service),str(cfg),str(hosts),str(resolv),f'127.0.0.1:{dns.socket.getsockname()[1]}',str(ready),str(stop)];r['service_argv']=argv;process=subprocess.Popen(argv,env=environment,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr)
        until=time.monotonic()+8
        while not ready.exists():
            if process.poll() is not None:raise RuntimeError('fixture exited '+str(process.returncode))
            if time.monotonic()>until:raise TimeoutError('fixture readiness')
            time.sleep(.005)
        def call(label,operation,value,family,expected,config=cfg):
            cmd=[str(client),str(config),operation,value,str(family)];p=subprocess.run(cmd,env=environment,capture_output=True,timeout=6);(out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr);lines=p.stdout.decode().splitlines();case={'label':label,'argv':cmd,'exit_code':p.returncode,'actual':lines,'expected':expected,'passed':p.returncode==0 and lines==expected};r['cases'].append(case)
            if not case['passed']:raise ValueError(str(case)+' '+p.stderr.decode(errors='replace'))
        addr4=['HANDLE|some','ADDR|2|198.51.100.4','END|1'];addr6=['HANDLE|some',f'ADDR|{socket.AF_INET6}|2001:db8::6','END|1'];anyaddr=['HANDLE|some',f'ADDR|{socket.AF_INET6}|2001:db8::6','ADDR|2|198.51.100.4','END|2']
        call('unix-A','forward','v4.example',4,addr4)
        call('unix-AAAA','forward','v6.example',6,addr6)
        call('unix-any','forward','any.example',0,anyaddr)
        call('unix-PTR4','reverse','192.0.2.9',4,['HANDLE|some','NAME|'+b'ptr4.example'.hex(),'END|1'])
        call('unix-PTR6','reverse','2001:db8::9',6,['HANDLE|some','NAME|'+b'ptr6.example'.hex(),'END|1'])
        call('unix-unicode','forward','é.example',4,addr4)
        call('tcp-A','forward','tcp4.example',4,addr4,tcp)
        call('tcp-AAAA','forward','tcp6.example',6,addr6,tcp)
        call('wrong-id-malformed-ignored','forward','malformed.example',4,addr4)
        call('no-extra-QR-rcode-question-class-filter','forward','unchecked.example',4,addr4)
        call('empty-any-no-AAAA','forward','empty.example',0,['HANDLE|some','END|0'])
        call('normal-public-client-cancel','cancel','cancel.example',4,['HANDLE|some','CANCELED|0|0'])
        # Bad raw session closes; a distinct actual normal C client remains usable.
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as bad:
            bad.settimeout(2);bad.connect(str(unix));bad.sendall(bytes.fromhex('00040004'));assert bad.recv(1)==b''
        r['cases'].append({'label':'malformed-session-physically-closed','passed':True})
        call('survives-bad-session-hosts','forward','own-host.example',4,['HANDLE|some','ADDR|2|192.0.2.50','END|1'])
        a=[str(client),str(cfg),'forward','parallel4.example','4'];b=[str(client),str(tcp),'forward','parallel6.example','6'];pa=subprocess.Popen(a,env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE);pb=subprocess.Popen(b,env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        oa,ea=pa.communicate(timeout=6);ob,eb=pb.communicate(timeout=6);assert pa.returncode==pb.returncode==0 and oa.decode().splitlines()==addr4 and ob.decode().splitlines()==addr6,(oa,ob,ea,eb)
        r['cases'].append({'label':'concurrent-normal-C-Unix-and-TCP-clients','passed':True,'traces':[oa.decode().splitlines(),ob.decode().splitlines()]})
        stop.write_bytes(b'stop');process.wait(timeout=5);r['exit_code']=process.returncode
        if process.returncode:raise ValueError('fixture shutdown exit '+str(process.returncode))
        r['owned_unix_socket_removed']=not unix.exists();r['dns_queries']=dns.queries;r['dns_errors']=dns.errors
        assert not dns.errors
        assert any(bytes.fromhex(q['name_hex'])==b'xn--9ca.example' for q in dns.queries)
        assert [q['kind'] for q in dns.queries if bytes.fromhex(q['name_hex'])==b'empty.example']==[1]
        r['inputs_unchanged']=all(sha(p)==h for p,h in inputs.items());r['host_machine_files_unchanged']=all(sha(p)==h for p,h in hostfiles.items());r['normal_C_library_unchanged']=sha(library)==normal_library_hash
        assert r['inputs_unchanged'] and r['host_machine_files_unchanged'] and r['owned_unix_socket_removed'] and r['normal_C_library_unchanged']
        r['status']='passed'
    except Exception as e:r['failure']=type(e).__name__+': '+str(e)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait();r['cleanup_forced_kill']=True
        dns.close();stdout.close();stderr.close();(out/'result.json').write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps({'status':r['status'],'checks':len(r['cases']),'result':str(out/'result.json'),'failure':r.get('failure')}));return 0 if r['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
