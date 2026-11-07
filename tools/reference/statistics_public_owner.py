#!/usr/bin/env python3
"""Normal C/Rust public STATISTICS owners: real API callbacks and explicit differences.

No upstream function extraction, source mutation, replacement library or public DNS.
See STATISTICS_PUBLIC_OWNER.md for scope and the51case gap inventory.
"""
import argparse,collections,contextlib,hashlib,importlib.util,json,os,select,shlex,socket,struct,subprocess,sys,tempfile,time
from pathlib import Path
sys.dont_write_bytecode=True
REPO=Path(__file__).resolve().parents[2]
BUILDER=Path(__file__).with_name('build_reference.py')
builder_spec=importlib.util.spec_from_file_location('official_reference_builder',BUILDER)
builder=importlib.util.module_from_spec(builder_spec);builder_spec.loader.exec_module(builder)
ROOT=Path();CROOT=Path();SOURCE=Path();RECEIPT=Path();BUILD={};ENV={};BIN=Path();TRACES=Path()
ALL_CHECKS=[];SCENARIOS=[]
fixture=sys.modules[__name__]
def hx(v):
    if v is None: return '-'
    if isinstance(v, str): v = v.encode()
    return v.hex() or '_'

def frame(typ, payload=b''):
    return struct.pack('!HH', len(payload) + 4, typ) + payload

def value(number, sub=b'other', name=b'row', persistent=False):
    return frame(170, struct.pack('!IQ', (0x80000000 if persistent else 0) | 5, number) + sub + b'\0' + name + b'\0')

def watch_value(wid, number, flags=0, reserved=0):
    return frame(173, struct.pack('!IIIQ', flags, wid, reserved, number))

def decode_frame(raw):
    size, typ = struct.unpack('!HH', raw[:4])
    out = {'type': typ, 'size': size, 'hex': raw.hex()}
    if typ in (169, 172):
        sub, name, tail = raw[4:].split(b'\0', 2)
        assert not tail
        out.update(sub_hex=sub.hex(), name_hex=name.hex())
    elif typ == 168:
        flags, number = struct.unpack('!IQ', raw[4:16])
        sub, name, tail = raw[16:].split(b'\0', 2)
        assert not tail
        out.update(sub_hex=sub.hex(), name_hex=name.hex(), flags=flags, value=str(number))
    return out

class Probe:
    def __init__(self, name, disable='missing', transport='unix', listen=True, path=None):
        self.name = name
        # Case-insensitive native filesystems must retain YES and yes as
        # separate observed processes rather than overwrite their traces.
        self.artifact_name=name+'-'+hashlib.sha256(name.encode()).hexdigest()[:8]
        self.transport = transport
        self.temp = tempfile.TemporaryDirectory(prefix='gso-', dir='/tmp')
        self.path = Path(path) if path else Path(self.temp.name) / 's'
        self.listener = None
        self.conn = None
        self.pending = []
        self.out = bytearray()
        self.rx = bytearray()
        self.events = []
        self.wire = []
        self.checks = []
        self.accepts = 0
        self.started = time.monotonic()
        self.stderr_path = TRACES / (self.artifact_name + '.stderr')
        self.stderr = self.stderr_path.open('wb')
        if listen: self.start_listener()
        self.proc = subprocess.Popen([str(BIN), str(self.path), disable, transport], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr, env=ENV)
        os.set_blocking(self.proc.stdout.fileno(), False)
        try:self.wait(lambda e: e.get('event') == 'ready')
        except BaseException:
            self.close()
            raise

    def record(self, typ, data):
        self.events.append({'time': round(time.monotonic() - self.started, 6), 'source': typ, **data})

    def pump(self, timeout=0.02):
        ready, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if ready:
            chunk = os.read(self.proc.stdout.fileno(), 65536)
            self.out.extend(chunk)
            while b'\n' in self.out:
                line, _, tail = self.out.partition(b'\n'); self.out[:] = tail
                row = json.loads(line)
                self.pending.append(row)
                self.record('c-api', row)
            if not chunk and self.proc.poll() not in (None, 0):
                raise AssertionError(f'{self.name}: C process exit {self.proc.returncode}, stderr {self.stderr_path.read_text()}')

    def wait(self, predicate, timeout=3):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            for i, item in enumerate(self.pending):
                if predicate(item): return self.pending.pop(i)
            self.pump(min(0.02, max(0, until - time.monotonic())))
        raise AssertionError(f'{self.name}: missing C event; pending={self.pending}; stderr={self.stderr_path.read_text()}')

    def command(self, *commands):
        self.record('controller', {'commands': list(commands)})
        self.proc.stdin.write(('\n'.join(commands) + '\nCOMMIT\n').encode()); self.proc.stdin.flush()
        self.wait(lambda e: e.get('event') == 'commit')

    def start_listener(self):
        family = socket.AF_INET if self.transport=='tcp4' else socket.AF_INET6 if self.transport=='tcp6' else socket.AF_UNIX
        self.listener = socket.socket(family, socket.SOCK_STREAM)
        if family == socket.AF_UNIX:self.listener.bind(str(self.path))
        else:
            self.listener.bind(('127.0.0.1' if family==socket.AF_INET else '::1',0))
            self.path=Path(str(self.listener.getsockname()[1]))
        self.listener.listen(4); self.listener.settimeout(4)

    def accept(self, timeout=4):
        self.listener.settimeout(timeout)
        self.conn, _ = self.listener.accept(); self.conn.settimeout(3)
        self.accepts += 1; self.rx.clear()
        self.record('peer', {'event': 'accept', 'epoch': self.accepts})

    def receive(self, expected=None, timeout=3):
        until = time.monotonic() + timeout
        while True:
            if len(self.rx) >= 4:
                size = struct.unpack('!H', self.rx[:2])[0]
                assert size >= 4
                if len(self.rx) >= size:
                    raw = bytes(self.rx[:size]); del self.rx[:size]
                    result = decode_frame(raw)
                    self.wire.append(result)
                    self.record('wire-out', {'epoch': self.accepts, **result})
                    if expected is not None: assert result['type'] == expected, (self.name, result, expected)
                    return result
            self.conn.settimeout(max(0.01, until - time.monotonic()))
            data = self.conn.recv(65536)
            if not data: raise AssertionError(f'{self.name}: unexpected EOF, partial={self.rx.hex()}')
            self.rx.extend(data)

    def send(self, raw, chunks=None):
        self.record('wire-in', {'epoch': self.accepts, 'hex': raw.hex(), 'chunks': chunks})
        if chunks:
            offset = 0
            for n in chunks:
                if offset >= len(raw): break
                self.conn.sendall(raw[offset:offset+n]); offset += n
            if offset < len(raw): self.conn.sendall(raw[offset:])
        else: self.conn.sendall(raw)

    def quiet(self, seconds=0.035, wire=False, listener=False):
        before = len(self.events)
        until = time.monotonic() + seconds
        while time.monotonic() < until: self.pump(min(0.005, until-time.monotonic()))
        callbacks = [e for e in self.events[before:] if e.get('event') in ('row', 'cont')]
        if wire and self.conn:
            ready, _, _ = select.select([self.conn], [], [], 0)
            assert not ready and not self.rx, (self.name, 'unexpected wire/EOF')
        if listener:
            ready, _, _ = select.select([self.listener], [], [], 0)
            assert not ready, (self.name, 'unexpected connection')
        return callbacks

    def eof(self, timeout=2):
        self.conn.settimeout(timeout)
        assert not self.rx, (self.name, self.rx.hex())
        assert self.conn.recv(4096) == b'', self.name
        self.record('peer', {'event': 'eof', 'epoch': self.accepts})

    def disconnect(self):
        self.conn.close(); self.conn = None; self.rx.clear()
        self.record('peer', {'event': 'close', 'epoch': self.accepts})

    def check(self, label, condition, detail=None):
        item = {'id': self.name + '.' + label, 'passed': bool(condition), 'detail': detail}
        self.checks.append(item); ALL_CHECKS.append(item)
        if not condition: raise AssertionError(item)

    def rows(self, id=None):
        return [e for e in self.events if e.get('event') == 'row' and (id is None or e.get('id') == id)]

    def conts(self, id=None):
        return [e for e in self.events if e.get('event') == 'cont' and (id is None or e.get('id') == id)]

    def finish(self):
        self.command('STOP')
        self.proc.wait(timeout=2)
        while select.select([self.proc.stdout], [], [], 0)[0]:
            before = len(self.events); self.pump(0)
            if len(self.events) == before: break
        self.check('clean-exit', self.proc.returncode == 0)

    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try: self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired: self.proc.kill(); self.proc.wait(timeout=2)
        if self.conn: self.conn.close()
        if self.listener: self.listener.close()
        self.stderr.close()
        result = {'scenario': self.name, 'events': self.events, 'checks': self.checks, 'exit_code': self.proc.returncode, 'stderr': self.stderr_path.read_text(), 'all_owned_processes_reaped': self.proc.poll() is not None}
        self.temp.cleanup()
        result['temporary_resources_removed']=not Path(self.temp.name).exists()
        p = TRACES / (self.artifact_name + '.json'); p.write_text(json.dumps(result, indent=2)+'\n')
        SCENARIOS.append({'name': self.name, 'trace': str(p), 'checks': len(self.checks), 'sha256': sha(p)})

@contextlib.contextmanager
def probe(*args, **kwargs):
    p = Probe(*args, **kwargs)
    try: yield p
    finally: p.close()

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def cont(p, id, success=1):
    e = p.wait(lambda e: e.get('event') == 'cont' and e.get('id') == id)
    p.check('cont-' + str(id), e['success'] == success, e)
    return e

def create(p):
    p.command('CREATE '+hx(b'owner'))
    p.check('create', p.wait(lambda e:e.get('event') == 'create')['present'])

def disable_lazy():
    for disabled in ('missing', 'NO', 'invalid', 'YES', 'yes'):
        with probe('disable-'+disabled, disable=disabled) as p:
            p.command('CREATE '+hx(b'owner'))
            present = p.wait(lambda e:e.get('event') == 'create')['present']
            p.check('config', present == (disabled not in ('YES','yes')))
            p.quiet(listener=True)
            p.command('UPDATE '+hx(b'zero')+' 0 1')
            p.quiet(listener=True)
            p.check('lazy-zero-no-connect', True)
            if present:
                p.command('SET '+hx(b'row')+' 7 1'); p.accept(); f = p.receive(168)
                p.check('first-work-connects', f['sub_hex']==hx(b'owner') and f['name_hex']==hx(b'row') and f['flags']==2 and f['value']=='7')
            else:
                p.command('SET '+hx(b'row')+' 7 1', 'GET 0 - - 0','WATCH 10 _ _ 0','DESTROY 1')
                p.check('disabled-get', not p.wait(lambda e:e.get('event')=='get')['present'])
                p.check('disabled-watch', p.wait(lambda e:e.get('event')=='watch')['result']==-1)
                p.quiet(listener=True)
            p.finish()
    with probe('missing-transport', transport='missing') as p:
        create(p); p.command('SET '+hx(b'n')+' 1 0','UPDATE '+hx(b'n')+' 2 1')
        p.quiet(listener=True); p.command('DESTROY 1'); p.quiet(listener=True)
        p.check('invalid-transport-no-connection', True); p.finish()

def coalescing():
    with probe('coalescing') as p:
        create(p)
        p.command('SET '+hx(b'anchor')+' 1 0', 'SET '+hx(b'n')+' 20 1', 'GET 0 - '+hx(b'n')+' 0', 'UPDATE '+hx(b'n')+' -30 0', 'UPDATE '+hx(b'n')+' 10 1', 'SET '+hx(b'wrap')+' 18446744073709551615 0', 'UPDATE '+hx(b'wrap')+' 1 1', 'UPDATE '+hx(b'delta')+' -1 0', 'UPDATE '+hx(b'delta')+' 1 1', 'UPDATE '+hx(b'replace')+' -8 1','SET '+hx(b'replace')+' 4 0','SET '+hx(b'replace')+' 17 1')
        p.accept(); a=p.receive(168); n=p.receive(168); g=p.receive(169)
        p.check('immutable-anchor', a['value']=='1' and a['name_hex']==hx('anchor'))
        p.check('across-get-clamp-positive-latest-persist', n['value']=='10' and n['flags']==2 and g['name_hex']==hx('n'))
        p.send(value(10, b'owner',b'n',True)+frame(171));cont(p,0)
        rows=[p.receive(168) for _ in range(3)]
        p.check('absolute-positive-wrap', rows[0]['name_hex']==hx('wrap') and rows[0]['value']=='0' and rows[0]['flags']==2)
        p.check('relative-zero-still-queued', rows[1]['name_hex']==hx('delta') and rows[1]['value']=='0' and rows[1]['flags']==3)
        p.check('update-to-set-and-replace', rows[2]['name_hex']==hx('replace') and rows[2]['value']=='17' and rows[2]['flags']==2)
        p.command('UPDATE '+hx(b'signed')+' -9 0'); f=p.receive(168)
        p.check('signed-relative-wire', f['value']==str((1<<64)-9) and f['flags']==1)
        p.command('DESTROY 0'); p.eof(); p.finish()

def local_tcp_and_reference_crash():
    for transport in ('tcp4','tcp6'):
        with probe('local-'+transport,transport=transport) as p:
            create(p);p.command('SET '+hx('n')+' 8 1','GET 0 - - 0');p.accept();f=p.receive(168);p.receive(169)
            p.send(value(8,b'owner',b'n',True)+frame(171));cont(p,0)
            p.check('tcp-public-api-roundtrip',f['value']=='8' and len(p.rows(0))==1)
            p.command('DESTROY 0');p.eof();p.finish()
    with probe('reference-missing-hostname-crash',transport='missing-hostname') as p:
        create(p)
        commands=['SET '+hx('n')+' 1 0']
        p.record('controller',{'commands':commands})
        p.proc.stdin.write(('\n'.join(commands)+'\nCOMMIT\n').encode());p.proc.stdin.flush()
        p.proc.wait(timeout=3)
        p.check('actual-reference-sigsegv',p.proc.returncode==-11,{'exit_code':p.proc.returncode,'source':'client.c:1217 strlen(cstate->hostname), present PORT and missing HOSTNAME'})

def get_values():
    with probe('get-values') as p:
        create(p)
        p.command('WATCH 10 '+hx(b'registration')+' '+hx(b'literal')+' 1','GET 0 - - 0','GET 1 _ '+hx(b'n')+' 0','GET 2 '+hx(b's')+' _ 0','GET 3 _ _ 0')
        p.accept(); w=p.receive(172); first=p.receive(169)
        p.check('literal-watch-and-null-wildcards',w['sub_hex']==hx('registration') and first['sub_hex']=='' and first['name_hex']=='')
        raw=watch_value(0,77,2,7)+value((1<<64)-1,b'\xffs',b'\xfe',True)+value(0,b'other',b'zero',False)+frame(171)
        p.send(raw,[1,2,1,3,7]); cont(p,0)
        for i, sub, name in ((1,b'',b'n'),(2,b's',b''),(3,b'',b'')):
            f=p.receive(169);p.check('selector-'+str(i),f['sub_hex']==sub.hex() and f['name_hex']==name.hex());p.send(frame(171));cont(p,i)
        wr=p.rows(10); r=p.rows(0)
        p.check('watch-interleave-retains-registration',len(wr)==1 and wr[0]['sub_hex']==hx('registration') and wr[0]['name_hex']==hx('literal'))
        p.check('opaque-value-persistence',len(r)==2 and r[0]['sub_hex']=='ff73' and r[0]['name_hex']=='fe' and r[0]['value']==str((1<<64)-1) and r[0]['persistent']==1 and r[1]['value']=='0' and r[1]['persistent']==0)
        p.check('watch-flag2-reference-discrepancy',wr[0]['persistent']==0)
        p.check('reserved-diagnosed-and-delivered','statistics_api.c:506' in p.stderr_path.read_text() and wr[0]['value']=='77')
        p.send(watch_value(0,78,0,0));p.wait(lambda e:e.get('event')=='row' and e.get('id')==10 and e.get('value')=='78')
        p.check('watch-return-ignored',len(p.rows(10))==2)
        p.command('DESTROY 0');p.eof();p.finish()

def cancel_abort():
    with probe('cancel-buffered') as p:
        create(p);p.command('GET 0 - - 2','GET 1 - '+hx('removed')+' 0','GCANCEL 1','GET 2 - '+hx('next')+' 0')
        p.accept();p.receive(169)
        p.send(value(1)+value(2)+frame(171))
        p.wait(lambda e:e.get('event')=='callback_cancel')
        f=p.receive(169);p.check('queued-cancel-never-submitted',f['name_hex']==hx('next'))
        p.send(value(3)+frame(171));cont(p,2);p.quiet()
        p.check('buffered-cancel-suppresses',len(p.rows(0))==1 and not p.conts(0) and not p.rows(1) and not p.conts(1))
        p.command('DESTROY 0');p.eof();p.finish()
    with probe('iterator-abort-end') as p:
        create(p);p.command('GET 0 - - 1','GET 1 - '+hx('next')+' 0');p.accept();p.receive(169)
        p.send(value(1)+value(2)+frame(171));cont(p,0);p.receive(169);p.send(frame(171));cont(p,1)
        p.check('abort-drains-success',len(p.rows(0))==1 and len(p.conts(0))==1)
        p.command('DESTROY 0');p.eof();p.finish()

def failures():
    for mode in (0,1,2):
        with probe('get-loss-'+str(mode)) as p:
            create(p);p.command(f'GET 0 - - {mode}','GET 1 - '+hx('next')+' 0');p.accept();p.receive(169)
            p.send(value(1));p.wait(lambda e:e.get('event')=='row');p.disconnect()
            p.accept();f=p.receive(169);p.check('pending-get-retries',f['name_hex']==hx('next'))
            p.send(frame(171));cont(p,1);p.quiet()
            p.check('loss-cont-eligibility',len(p.conts(0))==(1 if mode==0 else 0) and (mode!=0 or p.conts(0)[0]['success']==-1))
            p.command('DESTROY 0');p.eof();p.finish()
    for kind, bad in (('bad-value',frame(170,struct.pack('!IQ',0,1)+b'one\0missing')),('trailing-end',frame(171,b'x'))):
        with probe(kind) as p:
            create(p);p.command('GET 0 - - 0','GET 1 - '+hx('next')+' 0');p.accept();p.receive(169);p.send(bad)
            cont(p,0,-1);p.eof();p.disconnect();p.accept();p.receive(169);p.send(frame(171));cont(p,1)
            p.check('malformed-retires-once',len(p.conts(0))==1);p.command('DESTROY 0');p.eof();p.finish()
    with probe('foreign-type-ignored') as p:
        create(p);p.command('GET 0 - - 0');p.accept();p.receive(169)
        p.send(frame(65000)+value(19)+frame(171));cont(p,0)
        p.check('actual-client-ignores-unhandled-type',len(p.rows(0))==1 and p.rows(0)[0]['value']=='19')
        p.command('DESTROY 0');p.eof();p.finish()
    with probe('null-continuation') as p:
        create(p);p.command('GET 0 - - 3','GET 1 - - 0');p.accept();p.receive(169);p.send(value(17)+frame(171));p.receive(169);p.send(frame(171));cont(p,1)
        p.check('null-cont-no-callback-and-next-get',len(p.rows(0))==1 and not p.conts(0));p.command('DESTROY 0');p.eof();p.finish()
    with probe('unexpected-confirm') as p:
        create(p);p.command('GET 0 - - 0','GET 1 - - 0');p.accept();p.receive(169);p.send(frame(175));cont(p,0,-1);p.eof();p.disconnect();p.accept();p.receive(169);p.send(frame(171));cont(p,1)
        p.check('unexpected-confirm-not-success',len(p.conts(0))==1);p.command('DESTROY 0');p.eof();p.finish()

def watch_hole():
    with probe('watch-reconnect-hole') as p:
        create(p);p.command('WATCH 10 '+hx('s')+' '+hx('A')+' 0','WATCH 11 '+hx('s')+' '+hx('B')+' 0');p.accept();p.receive(172);p.receive(172)
        p.command('WCANCEL 10','WATCH 12 '+hx('s')+' '+hx('C')+' 0');p.receive(172)
        p.send(watch_value(0,100)+watch_value(1,101)+watch_value(2,102));p.wait(lambda e:e.get('event')=='row' and e.get('id')==12)
        p.check('cancel-local-no-unwatch',not p.rows(10) and [r['value'] for r in p.rows(11)]==['101'])
        p.quiet(wire=True);p.disconnect();p.accept();b=p.receive(172);c=p.receive(172)
        p.check('reregister-live-order',b['name_hex']==hx('B') and c['name_hex']==hx('C'))
        p.send(watch_value(0,201)+watch_value(1,202));p.wait(lambda e:e.get('event')=='row' and e.get('value')=='202');p.quiet()
        p.check('actual-c-hole-misroutes', [r['value'] for r in p.rows(11)]==['101','202'] and [r['value'] for r in p.rows(12)]==['102'], {'observed':'new server WID0 B suppressed; new server WID1 C delivered to B context'})
        p.command('DESTROY 0');p.eof();p.finish()
    with probe('watch-queued-copy') as p:
        create(p);p.command('SET '+hx('anchor')+' 1 0','WATCH 10 _ _ 0','WCANCEL 10','WATCH 11 '+hx('s')+' '+hx('B')+' 0');p.accept();p.receive(168);a=p.receive(172);b=p.receive(172)
        p.check('cancelled-copy-transmits-literal-empty',a['sub_hex']=='' and a['name_hex']=='' and b['name_hex']==hx('B'))
        p.send(watch_value(0,1)+watch_value(1,2));p.wait(lambda e:e.get('event')=='row' and e.get('id')==11);p.quiet()
        p.check('cancelled-copy-tombstone',not p.rows(10) and [r['value'] for r in p.rows(11)]==['2'])
        p.command('DESTROY 0');p.eof();p.finish()

def reconnect_pending():
    with probe('reconnect-pending') as p:
        create(p);p.command('SET '+hx('submitted')+' 9 1','GET 0 - - 0');p.accept();p.receive(168);p.receive(169)
        p.command('SET '+hx('pending')+' 10 1','GET 1 - '+hx('next')+' 0','WATCH 10 '+hx('s')+' '+hx('w')+' 0')
        p.send(b'\x00\x20');p.disconnect();cont(p,0,-1);p.accept();s=p.receive(168);g=p.receive(169)
        p.check('nonwatch-pending-before-watch',s['name_hex']==hx('pending') and g['name_hex']==hx('next'))
        p.send(value(5)+frame(171));cont(p,1);w=p.receive(172);p.send(watch_value(0,7));p.wait(lambda e:e.get('event')=='row' and e.get('id')==10)
        p.check('no-set-replay-and-partial-rx-retired',[f['name_hex'] for f in p.wire if f['type']==168]==[hx('submitted'),hx('pending')] and len(p.rows(1))==1 and w['name_hex']==hx('w'))
        p.command('DESTROY 0');p.eof();p.finish()

def destroy_immediate():
    for mode in (0,1,2):
        with probe('destroy-current-'+str(mode)) as p:
            create(p);p.command(f'GET 0 - - {mode}','GET 1 - '+hx('queued')+' 0','SET '+hx('pending')+' 12 1','WATCH 10 '+hx('s')+' '+hx('w')+' 0');p.accept();p.receive(169)
            p.send(value(1));p.wait(lambda e:e.get('event')=='row');p.command('DESTROY 0');p.eof();p.quiet()
            p.check('current-cont-eligibility',len(p.conts(0))==(1 if mode==0 else 0) and (mode!=0 or p.conts(0)[0]['success']==-1))
            p.check('queued-retired-no-callbacks',not p.conts(1) and not p.rows(1) and not p.rows(10) and len(p.wire)==1)
            if mode==0:
                seq=[e.get('event') for e in p.events]
                p.check('failure-cont-synchronous-destroy',seq.index('destroy_begin')<seq.index('cont')<seq.index('destroy_return'))
            p.finish()
    with probe('destroy-sync-idle') as p:
        create(p);p.command('GET 0 - - 0');p.accept();p.receive(169);p.send(frame(171));cont(p,0);p.command('DESTROY 1');p.eof()
        p.check('idle-sync-no-barrier',all(f['type']!=174 for f in p.wire));p.finish()

def grow_backoff(p, rounds=6):
    for _ in range(rounds):
        p.send(frame(171));p.eof();p.disconnect();p.accept();p.receive(172)

def destroy_deferred():
    for ending in ('confirm','deadline','disconnect'):
        with probe('destroy-deferred-'+ending) as p:
            create(p);p.command('WATCH 10 '+hx('s')+' '+hx('w')+' 0');p.accept();p.receive(172);grow_backoff(p)
            p.command('GET 0 - - 0','SET '+hx('retained')+' 17 1','GET 1 - '+hx('removed')+' 0','WATCH 11 '+hx('s')+' '+hx('removed')+' 0','DESTROY 1')
            p.receive(169);p.send(watch_value(0,88)+value(1)+frame(171));cont(p,0);p.wait(lambda e:e.get('event')=='row' and e.get('id')==10)
            s=p.receive(168);p.receive(174)
            p.check('deferred-abort-drain',not p.rows(0) and not p.rows(1) and not p.conts(1) and s['name_hex']==hx('retained'))
            p.check('live-watch-until-final',len(p.rows(10))==1 and not p.rows(11))
            if ending=='confirm': p.send(frame(175));p.eof()
            elif ending=='deadline': p.eof(timeout=2)
            else: p.disconnect();p.quiet(0.15,listener=True)
            p.check('no-late-callbacks',not p.quiet(0.04))
            p.finish()

def unused_timeout():
    with probe('setter-timeout-unused', listen=False) as p:
        create(p);p.command('SET '+hx('anchor')+' 1 0','SET '+hx('still-pending')+' 22 1')
        p.quiet(2.25);p.start_listener();p.accept(timeout=3)
        a=p.receive(168);b=p.receive(168)
        p.check('pending-survives-over-two-seconds',a['name_hex']==hx('anchor') and b['name_hex']==hx('still-pending') and b['value']=='22')
        p.command('DESTROY 0');p.eof();p.finish()

def normal_daemon():
    temp = tempfile.TemporaryDirectory(prefix='gsd-',dir='/tmp')
    d=Path(temp.name);path=d/'s';config=d/'test.conf';empty=d/'defaults';empty.mkdir()
    config.write_text(f'[PATHS]\nGNUNET_HOME = {d}/home\n[statistics]\nUNIXPATH = {path}\nPORT = 0\nDISABLEV6 = YES\nDATABASE = {d}/statistics.db\n')
    env=ENV.copy();env['GNUNET_BASE_CONFIG']=str(empty)
    daemon=Path(BUILD['prefix'])/'lib/gnunet/libexec/gnunet-service-statistics'
    log=(TRACES/'normal-daemon.stderr').open('wb')
    proc=subprocess.Popen([str(daemon),'-c',str(config),'-L','ERROR'],env=env,stdout=subprocess.DEVNULL,stderr=log)
    try:
        until=time.monotonic()+5
        while not path.exists():
            if proc.poll() is not None:raise AssertionError('normal daemon failed')
            if time.monotonic()>until:raise AssertionError('normal daemon not ready')
            time.sleep(.01)
        with probe('normal-daemon-watch',listen=False,path=path) as p:
            create(p);p.command('SET '+hx('row')+' 7 1','GET 0 - '+hx('row')+' 0');cont(p,0)
            p.check('real-service-get-persistent',len(p.rows(0))==1 and p.rows(0)[0]['value']=='7' and p.rows(0)[0]['persistent']==1)
            p.command('WATCH 10 '+hx('owner')+' '+hx('row')+' 1','WATCH 11 '+hx('owner')+' '+hx('unset-zero')+' 0')
            p.wait(lambda e:e.get('event')=='row' and e.get('id')==10);p.quiet()
            p.check('nonzero-immediate-unset-zero-silent',len(p.rows(10))==1 and not p.rows(11))
            p.check('real-service-watch-persistence-discrepancy',p.rows(10)[0]['persistent']==0)
            p.command('SET '+hx('unset-zero')+' 0 0');p.wait(lambda e:e.get('event')=='row' and e.get('id')==11)
            p.command('SET '+hx('unset-zero')+' 0 0');p.quiet()
            p.check('first-zero-notifies-equal-suppressed',len(p.rows(11))==1 and p.rows(11)[0]['value']=='0')
            p.command('UPDATE '+hx('row')+' 1 1');p.wait(lambda e:e.get('event')=='row' and e.get('id')==10 and e.get('value')=='8')
            p.check('real-watch-return-ignored',len(p.rows(10))==2)
            p.command('WATCH 12 '+hx('owner')+' '+hx('row')+' 0','WATCH 12 '+hx('owner')+' '+hx('row')+' 0')
            p.wait(lambda e:e.get('event')=='row' and e.get('id')==12 and e.get('row')==2)
            p.command('WCANCEL 12','UPDATE '+hx('row')+' 1 1');p.wait(lambda e:e.get('event')=='row' and e.get('id')==12 and e.get('value')=='9');p.quiet()
            p.check('duplicate-first-match-only',len(p.rows(12))==3)
            p.command('WCANCEL 12','UPDATE '+hx('row')+' 1 1');p.wait(lambda e:e.get('event')=='row' and e.get('id')==10 and e.get('value')=='10');p.quiet()
            p.check('duplicate-second-independent',len(p.rows(12))==3)
            p.command('WCANCEL 12');r=p.wait(lambda e:e.get('event')=='watch_cancel' and e.get('result')==-1)
            p.check('missing-watch-cancel-error',r['result']==-1)
            p.command('WATCH 13 _ _ 0','SET _ 11 0','WATCH 14 '+hx('owner')+' _ 0')
            p.wait(lambda e:e.get('event')=='row' and e.get('id')==14);p.quiet()
            p.check('real-service-empty-watch-is-literal',not p.rows(13) and len(p.rows(14))==1 and p.rows(14)[0]['name_hex']=='' and p.rows(14)[0]['value']=='11')
            p.command('DESTROY 0');p.check('no-callback-after-destroy',not p.quiet(.05));p.finish()
        proc.terminate();proc.wait(timeout=3)
        ALL_CHECKS.append({'id':'normal-daemon.exit','passed':proc.returncode==0,'detail':{'exit_code':proc.returncode}})
        if proc.returncode!=0:raise AssertionError('daemon unclean exit')
    finally:
        if proc.poll() is None:proc.kill();proc.wait(timeout=2)
        log.close();temp.cleanup()

ORIGINAL=fixture.Probe
DIFFERENCES=[]
KNOWN={
 'get-values.watch-flag2-reference-discrepancy':'Rust interprets official server flag2 as persistent=true; normal C watch callback tests VALUE UID high bit.',
 'get-values.reserved-diagnosed-and-delivered':'Rust exposes raw reserved7/flags in WatchValue; C emits a C-source assertion diagnostic and still delivers.',
 'watch-reconnect-hole.actual-c-hole-misroutes':'Rust maps fresh WIDs to stable logical subscriptions; normal C canceled array hole suppresses/misroutes.',
 'destroy-current-0.failure-cont-synchronous-destroy':'Explicit Rust destroy records eligible completion and dispatches it on the next drive; C continuation runs synchronously inside destroy(false).',
 'normal-daemon-watch.real-service-watch-persistence-discrepancy':'Rust watch persistence=true for real C daemon flag2; normal C watch callback returns false.',
}
class RustProbe(ORIGINAL):
 def record(self,typ,data):
  super().record('rust-api' if typ=='c-api' else typ,data)
 def check(self,label,condition,detail=None):
  key=self.name+'.'+label
  if key in KNOWN:
   # A mismatching C assertion is recorded as a difference, never converted
   # into an equal/passed comparison. Validate the intended Rust facts below.
   item={'id':key,'c_expectation_matched':bool(condition),'reason':KNOWN[key]}
   DIFFERENCES.append(item)
   self.record('comparison-difference',item)
   if label=='watch-flag2-reference-discrepancy':
    super().check('rust-official-flag2',self.rows(10)[0]['persistent']==1)
   elif label=='reserved-diagnosed-and-delivered':
    meta=[e for e in self.events if e.get('event')=='watch_metadata']
    super().check('rust-raw-reserved-retained',any(e['reserved']==7 and e['flags']==2 for e in meta))
   elif label=='actual-c-hole-misroutes':
    super().check('rust-reconnect-hole-correct-identity',[r['value'] for r in self.rows(11)]==['101','201'] and [r['value'] for r in self.rows(12)]==['102','202'])
   elif label=='failure-cont-synchronous-destroy':
    events=[e.get('event') for e in self.events]
    super().check('rust-completion-on-drive',events.index('destroy_begin')<events.index('destroy_return')<events.index('cont'))
   elif label=='real-service-watch-persistence-discrepancy':
    super().check('rust-real-service-watch-persistent',self.rows(10)[0]['persistent']==1)
   return
  super().check(label,condition,detail)

def local_tcp_and_reference_safe_error():
 for transport in ('tcp4','tcp6'):
  with fixture.probe('local-'+transport,transport=transport) as p:
   fixture.create(p);p.command('SET '+fixture.hx('n')+' 8 1','GET 0 - - 0');p.accept();f=p.receive(168);p.receive(169)
   p.send(fixture.value(8,b'owner',b'n',True)+fixture.frame(171));fixture.cont(p,0)
   p.check('tcp-public-api-roundtrip',f['value']=='8' and len(p.rows(0))==1);p.command('DESTROY 0');p.eof();p.finish()
 with fixture.probe('reference-missing-hostname-crash',transport='missing-hostname') as p:
  fixture.create(p);p.command('SET '+fixture.hx('n')+' 1 0');p.accept();f=p.receive(168)
  p.check('rust-valid-unix-no-hostname-safe',f['value']=='1' and p.proc.poll() is None)
  DIFFERENCES.append({'id':p.name,'c_expectation_matched':False,'reason':'Normal C crashes at strlen(NULL); valid Rust Unix endpoint works safely even when unused TCP HOSTNAME is missing.'})
  p.command('DESTROY 0');p.eof();p.finish()

def rust_failures():
 # Normal CLIENT/MQ semantics now also apply to the Rust owner: an unknown
 # but validly framed type is ignored; registered malformed handlers fail.
 fixture.failures()

def normalized(trace):
 wire=[e['hex'] for e in trace['events'] if e['source']=='wire-out']
 callbacks=[{k:e[k] for k in ('event','kind','id','sub_hex','name_hex','value','persistent','success') if k in e} for e in trace['events'] if e.get('event') in ('row','cont')]
 return {'wire_out':wire,'callbacks':callbacks}

def compare():
 c=json.loads((CROOT/'result.json').read_text());c_by={s['name']:s for s in c['scenarios']};pairs=[]
 for s in fixture.SCENARIOS:
  ct=json.loads(Path(c_by[s['name']]['trace']).read_text());rt=json.loads(Path(s['trace']).read_text());a=normalized(ct);b=normalized(rt)
  row={'scenario':s['name'],'c_trace_sha256':fixture.sha(c_by[s['name']]['trace']),'rust_trace_sha256':fixture.sha(s['trace']),'equal_wire_out':a['wire_out']==b['wire_out'],'equal_callback_values':a['callbacks']==b['callbacks']}
  if s['name'] in ('reference-missing-hostname-crash','watch-reconnect-hole','get-values','normal-daemon-watch'):
   row['classification']='explicit_reference_difference';row['c_observation']=a;row['rust_observation']=b
  else:
   row['classification']='equal_observed_wire_and_callback_values'
   assert row['equal_wire_out'] and row['equal_callback_values'],row
  pairs.append(row)
 return pairs


CASE_REVIEW = [{'id': 'statistics.client.create.disabled', 'c_coverage': 'c_observed', 'actual_assertions': ['disable-missing.config', 'disable-NO.config', 'disable-invalid.config', 'disable-YES.config', 'disable-yes.config'], 'remaining': 'Rust paired trace still required.'}, {'id': 'statistics.client.create.lazy', 'c_coverage': 'c_partial', 'actual_assertions': ['disable-missing.lazy-zero-no-connect', 'disable-missing.first-work-connects'], 'remaining': 'The private initial 1ms backoff value is not inspected.'}, {'id': 'statistics.client.create.subsystem', 'c_coverage': 'c_observed', 'actual_assertions': ['disable-missing.first-work-connects', 'get-values.watch-interleave-retains-registration', 'get-values.opaque-value-persistence'], 'remaining': 'Rust event/API pairing remains pending.'}, {'id': 'statistics.client.create.config', 'c_coverage': 'c_partial', 'actual_assertions': ['missing-transport.invalid-transport-no-connection', 'local-tcp4.tcp-public-api-roundtrip', 'local-tcp6.tcp-public-api-roundtrip', 'reference-missing-hostname-crash.actual-reference-sigsegv'], 'remaining': 'No ARM activation, public/general DNS, Unix/TCP round alternation, longpath, or every config profile. Rust must safely reject/ignore invalid TCP, not copy the crash.'}, {'id': 'statistics.client.destroy.immediate', 'c_coverage': 'c_observed', 'actual_assertions': ['destroy-current-0.queued-retired-no-callbacks', 'normal-daemon-watch.no-callback-after-destroy'], 'remaining': 'No Rust callback-owner or stale future proof.'}, {'id': 'statistics.client.destroy.current-get', 'c_coverage': 'c_observed', 'actual_assertions': ['destroy-current-0.current-cont-eligibility', 'destroy-current-1.current-cont-eligibility', 'destroy-current-2.current-cont-eligibility', 'destroy-current-0.failure-cont-synchronous-destroy'], 'remaining': 'Rust completion scheduling differs and must be documented/tested.'}, {'id': 'statistics.client.destroy.defer-condition', 'c_coverage': 'c_partial', 'actual_assertions': ['missing-transport.invalid-transport-no-connection', 'destroy-sync-idle.idle-sync-no-barrier', 'destroy-deferred-confirm.deferred-abort-drain'], 'remaining': 'Private MQ in-flight-only and first-try fatal/EAGAIN/full-write boundaries are not introspected.'}, {'id': 'statistics.client.destroy.drain', 'c_coverage': 'c_observed', 'actual_assertions': ['destroy-deferred-confirm.deferred-abort-drain', 'destroy-deferred-confirm.live-watch-until-final', 'destroy-deferred-confirm.cont-0'], 'remaining': 'Processing confirmation is not a filesystem durability proof.'}, {'id': 'statistics.client.destroy.confirm', 'c_coverage': 'c_partial', 'actual_assertions': ['unexpected-confirm.unexpected-confirm-not-success', 'destroy-deferred-confirm.no-late-callbacks'], 'remaining': 'Trailing/malformed CONFIRM and early barrier-write races are not tested; no false durable result is invented for C void API.'}, {'id': 'statistics.client.destroy.deadline', 'c_coverage': 'c_partial', 'actual_assertions': ['destroy-deferred-deadline.deferred-abort-drain', 'destroy-deferred-deadline.no-late-callbacks'], 'remaining': 'Exact admission+5*backoff equality, cap/reset internals, overflow and immutable deadline require clock/MQ oracle or Rust virtual time.'}, {'id': 'statistics.client.destroy.failure', 'c_coverage': 'c_partial', 'actual_assertions': ['destroy-deferred-deadline.no-late-callbacks', 'destroy-deferred-disconnect.no-late-callbacks', 'missing-transport.invalid-transport-no-connection'], 'remaining': 'C has no DestroyReport; Rust discarded/unknown mutation counts must be independently checked.'}, {'id': 'statistics.client.destroy.callback-authority', 'c_coverage': 'c_partial', 'actual_assertions': ['destroy-deferred-confirm.no-late-callbacks', 'destroy-deferred-disconnect.no-late-callbacks', 'normal-daemon-watch.no-callback-after-destroy'], 'remaining': 'Old connect/read/write/timer completion generation checks exist only in Rust and need paired host tests.'}, {'id': 'statistics.client.get.wildcards', 'c_coverage': 'c_observed', 'actual_assertions': ['get-values.literal-watch-and-null-wildcards', 'get-values.selector-1', 'get-values.selector-2', 'get-values.selector-3'], 'remaining': 'No new Rust conformance credit.'}, {'id': 'statistics.client.get.queue', 'c_coverage': 'c_observed', 'actual_assertions': ['get-values.cont-0', 'get-values.cont-1', 'get-values.cont-2', 'get-values.cont-3', 'cancel-buffered.queued-cancel-never-submitted'], 'remaining': 'No C generation IDs exist.'}, {'id': 'statistics.client.get.values', 'c_coverage': 'c_observed', 'actual_assertions': ['get-values.opaque-value-persistence', 'normal-daemon-watch.real-service-get-persistent'], 'remaining': 'Borrowed callback contract follows the public header; no invalid retained pointer is exercised.'}, {'id': 'statistics.client.get.watch-interleave', 'c_coverage': 'c_observed', 'actual_assertions': ['get-values.watch-interleave-retains-registration', 'get-values.opaque-value-persistence'], 'remaining': 'Rust paired buffered trace remains pending.'}, {'id': 'statistics.client.get.end', 'c_coverage': 'c_partial', 'actual_assertions': ['get-values.cont-0', 'get-values.cont-1', 'get-values.cont-2', 'get-values.cont-3'], 'remaining': 'Private backoff reset to precisely 1ms is source reviewed, not normally introspected.'}, {'id': 'statistics.client.get.abort-iterator', 'c_coverage': 'c_observed', 'actual_assertions': ['iterator-abort-end.abort-drains-success', 'iterator-abort-end.cont-0'], 'remaining': 'No Rust callback-interface promotion.'}, {'id': 'statistics.client.get.failure', 'c_coverage': 'c_observed', 'actual_assertions': ['bad-value.malformed-retires-once', 'trailing-end.malformed-retires-once', 'get-loss-0.loss-cont-eligibility', 'get-loss-0.pending-get-retries', 'foreign-type-ignored.actual-client-ignores-unhandled-type'], 'remaining': 'Unregistered well-framed types are ignored by both owners; malformed registered messages still retire the GET. Full callback registry/platform scope remains separate.'}, {'id': 'statistics.client.get.callback-lifetime', 'c_coverage': 'contract_only', 'actual_assertions': [], 'remaining': 'Not an executable proof of Rust type/lifetime exclusion; add compile-fail/API contract review. Never invoke forbidden C use to obtain a passing test.'}, {'id': 'statistics.client.get.bounds', 'c_coverage': 'rust_only_pending', 'actual_assertions': [], 'remaining': 'Rust queue/name/terminal atomic admission, IDs and callback authority require actual Rust snapshots; C process success cannot certify them.'}, {'id': 'statistics.client.get_cancel.queued', 'c_coverage': 'c_observed', 'actual_assertions': ['cancel-buffered.queued-cancel-never-submitted', 'cancel-buffered.buffered-cancel-suppresses'], 'remaining': 'Rust pair still pending.'}, {'id': 'statistics.client.get_cancel.current', 'c_coverage': 'c_observed', 'actual_assertions': ['cancel-buffered.buffered-cancel-suppresses', 'get-loss-2.loss-cont-eligibility'], 'remaining': 'No C pointer can be reused after terminal completion.'}, {'id': 'statistics.client.get_cancel.late', 'c_coverage': 'rust_only_pending', 'actual_assertions': [], 'remaining': 'Passing a stale C pointer is invalid use, not a normal reference test. Rust logical generation reuse protection needs Rust-only negative tests.'}, {'id': 'statistics.client.get_cancel.buffered', 'c_coverage': 'c_observed', 'actual_assertions': ['cancel-buffered.buffered-cancel-suppresses'], 'remaining': 'Rust event/CallbackContext pairing still pending.'}, {'id': 'statistics.client.set.absolute', 'c_coverage': 'c_partial', 'actual_assertions': ['disable-missing.first-work-connects', 'coalescing.update-to-set-and-replace'], 'remaining': 'Standalone absolute zero/UINT64_MAX full-domain boundary samples are not both sent without coalescing in this batch.'}, {'id': 'statistics.client.set.replace', 'c_coverage': 'c_partial', 'actual_assertions': ['coalescing.immutable-anchor', 'coalescing.update-to-set-and-replace'], 'remaining': 'Same-name in-flight vs pending mutation and actual EAGAIN should be added to paired trace.'}, {'id': 'statistics.client.set.coalesce-order', 'c_coverage': 'c_observed', 'actual_assertions': ['coalescing.across-get-clamp-positive-latest-persist'], 'remaining': 'No queue shim used.'}, {'id': 'statistics.client.set.update-to-set', 'c_coverage': 'c_observed', 'actual_assertions': ['coalescing.update-to-set-and-replace'], 'remaining': 'No Rust paired trace yet.'}, {'id': 'statistics.client.set.queue-atomic', 'c_coverage': 'rust_only_pending', 'actual_assertions': [], 'remaining': 'Rust capacity rejection must prove old value/persistence/FIFO/completion ownership unchanged; not observable through normal C allocation success.'}, {'id': 'statistics.client.set.submission', 'c_coverage': 'c_partial', 'actual_assertions': ['coalescing.immutable-anchor', 'reconnect-pending.no-set-replay-and-partial-rx-retired'], 'remaining': 'Kernel partial/fatal-first/EAGAIN and in-flight length boundary need explicit socket or component proof; unknown Rust outcomes are independent.'}, {'id': 'statistics.client.update.signed', 'c_coverage': 'c_observed', 'actual_assertions': ['coalescing.signed-relative-wire'], 'remaining': 'INT64_MIN C undefined negation is deliberately excluded from portable behavior claims.'}, {'id': 'statistics.client.update.zero', 'c_coverage': 'c_partial', 'actual_assertions': ['disable-missing.lazy-zero-no-connect', 'disable-YES.lazy-zero-no-connect', 'coalescing.relative-zero-still-queued'], 'remaining': 'Existing-row persistence not changed by a new update(0) is not independently sampled in the normal daemon.'}, {'id': 'statistics.client.update.absolute-pending', 'c_coverage': 'c_partial', 'actual_assertions': ['coalescing.across-get-clamp-positive-latest-persist', 'coalescing.absolute-positive-wrap'], 'remaining': 'INT64_MIN negative magnitude is undefined in the C subtract expression; do not certify that C UB as a standard. Rust defined safe boundary needs its own test.'}, {'id': 'statistics.client.update.relative-pending', 'c_coverage': 'c_observed', 'actual_assertions': ['coalescing.relative-zero-still-queued'], 'remaining': 'Other unsigned-wrap boundary samples remain available in extracted C queue oracle, not recredited here.'}, {'id': 'statistics.client.update.persistence', 'c_coverage': 'c_observed', 'actual_assertions': ['coalescing.across-get-clamp-positive-latest-persist', 'coalescing.absolute-positive-wrap', 'coalescing.relative-zero-still-queued', 'coalescing.update-to-set-and-replace'], 'remaining': 'Zero-call persistence is separately partial.'}, {'id': 'statistics.client.update.timeout', 'c_coverage': 'c_observed', 'actual_assertions': ['setter-timeout-unused.pending-survives-over-two-seconds'], 'remaining': 'This is actual non-expiry past2s, not a claim on precise retry intervals.'}, {'id': 'statistics.client.watch.literal', 'c_coverage': 'c_observed', 'actual_assertions': ['watch-queued-copy.cancelled-copy-transmits-literal-empty', 'normal-daemon-watch.real-service-empty-watch-is-literal', 'normal-daemon-watch.duplicate-first-match-only'], 'remaining': 'No wildcard watch semantics invented.'}, {'id': 'statistics.client.watch.no-ack', 'c_coverage': 'c_partial', 'actual_assertions': ['normal-daemon-watch.nonzero-immediate-unset-zero-silent', 'watch-queued-copy.cancelled-copy-tombstone'], 'remaining': 'No claimed positive WATCH acknowledgment or remote cancellation acknowledgment.'}, {'id': 'statistics.client.watch.initial', 'c_coverage': 'c_observed', 'actual_assertions': ['normal-daemon-watch.nonzero-immediate-unset-zero-silent', 'normal-daemon-watch.first-zero-notifies-equal-suppressed'], 'remaining': 'Service and client are both actual unmodified C binaries.'}, {'id': 'statistics.client.watch.ordering', 'c_coverage': 'c_observed', 'actual_assertions': ['watch-queued-copy.cancelled-copy-transmits-literal-empty', 'watch-queued-copy.cancelled-copy-tombstone', 'watch-reconnect-hole.reregister-live-order'], 'remaining': 'Reconnection hole separately records C discrepancy.'}, {'id': 'statistics.client.watch.callback', 'c_coverage': 'c_observed', 'actual_assertions': ['get-values.watch-interleave-retains-registration', 'get-values.watch-return-ignored', 'normal-daemon-watch.real-watch-return-ignored'], 'remaining': 'No callback return translated into private unwatch.'}, {'id': 'statistics.client.watch.flags', 'c_coverage': 'c_discrepancy', 'actual_assertions': ['get-values.reserved-diagnosed-and-delivered', 'get-values.watch-flag2-reference-discrepancy', 'normal-daemon-watch.real-service-watch-persistence-discrepancy'], 'remaining': 'Rust correct flag2/raw flags representation must remain a documented safe protocol discrepancy, not edited C expectations.'}, {'id': 'statistics.client.watch.reconnect', 'c_coverage': 'c_observed', 'actual_assertions': ['reconnect-pending.nonwatch-pending-before-watch', 'reconnect-pending.no-set-replay-and-partial-rx-retired', 'watch-reconnect-hole.reregister-live-order'], 'remaining': 'C stale array callback mapping is separately defective.'}, {'id': 'statistics.client.watch.epochs', 'c_coverage': 'c_partial', 'actual_assertions': ['reconnect-pending.no-set-replay-and-partial-rx-retired', 'watch-reconnect-hole.actual-c-hole-misroutes'], 'remaining': 'C has no explicit epoch/generation token; canceled-hole watch mapping actually differs. Rust stale connect/read/write and reused logical slot tests remain required.'}, {'id': 'statistics.client.watch_cancel.local', 'c_coverage': 'c_observed', 'actual_assertions': ['watch-reconnect-hole.cancel-local-no-unwatch', 'normal-daemon-watch.duplicate-second-independent'], 'remaining': 'Service resource release follows real connection ownership; no invented remote unwatch ACK.'}, {'id': 'statistics.client.watch_cancel.identity', 'c_coverage': 'c_observed', 'actual_assertions': ['normal-daemon-watch.duplicate-first-match-only', 'normal-daemon-watch.duplicate-second-independent', 'normal-daemon-watch.missing-watch-cancel-error'], 'remaining': 'Rust logical tokens need equivalent selection documented.'}, {'id': 'statistics.client.watch_cancel.queued-copy', 'c_coverage': 'c_partial', 'actual_assertions': ['watch-queued-copy.cancelled-copy-transmits-literal-empty', 'watch-queued-copy.cancelled-copy-tombstone'], 'remaining': 'Rust reused-slot generational authority is not a C public feature and needs Rust trace.'}, {'id': 'statistics.client.watch_cancel.reconnect-hole', 'c_coverage': 'c_discrepancy', 'actual_assertions': ['watch-reconnect-hole.actual-c-hole-misroutes'], 'remaining': 'The safe logical-vs-wire remapping requirement intentionally fixes this C defect. Do not silently mark C behavior equivalent.'}, {'id': 'statistics.client.reconnect.backoff', 'c_coverage': 'c_partial', 'actual_assertions': ['destroy-deferred-confirm.deferred-abort-drain', 'reconnect-pending.nonwatch-pending-before-watch', 'setter-timeout-unused.pending-survives-over-two-seconds'], 'remaining': 'Exact 1ms/doubling/900s cap/END reset and initial CLIENT2ms distinction require clock/component proof, not wall-clock guess.'}, {'id': 'statistics.client.transport.partial-write', 'c_coverage': 'c_partial', 'actual_assertions': ['get-values.opaque-value-persistence', 'coalescing.immutable-anchor', 'reconnect-pending.no-set-replay-and-partial-rx-retired'], 'remaining': 'No guaranteed kernel EAGAIN, send0, fatal first send, or exact non-inflight-length proof. Existing extracted MQ/core tests remain separate evidence.'}]

EXPECTED_SCENARIOS = {
 'disable-missing','disable-NO','disable-invalid','disable-YES','disable-yes','missing-transport',
 'local-tcp4','local-tcp6','reference-missing-hostname-crash','coalescing','get-values',
 'cancel-buffered','iterator-abort-end','get-loss-0','get-loss-1','get-loss-2','bad-value',
 'trailing-end','foreign-type-ignored','null-continuation','unexpected-confirm',
 'watch-reconnect-hole','watch-queued-copy','reconnect-pending','destroy-current-0',
 'destroy-current-1','destroy-current-2','destroy-sync-idle','destroy-deferred-confirm',
 'destroy-deferred-deadline','destroy-deferred-disconnect','setter-timeout-unused','normal-daemon-watch',
}

def collect_inputs(rust, c_binary):
    paths=[Path(__file__),Path(__file__).with_suffix('.c'),Path(__file__).with_name('STATISTICS_PUBLIC_OWNER.md'),BUILDER,RECEIPT,rust,c_binary,REPO/'spec/gnunet/api/statistics.json']
    for package in ('adapters/ipc-unix','adapters/config-std','adapters/native-std','crates/gnunet-client','crates/gnunet-types','crates/gnunet-wire','crates/gnunet-statistics','crates/gnunet-crypto'):
        for p in (REPO/package).rglob('*'):
            if p.is_symlink():raise ValueError('source symlink is not supported: '+str(p))
            if p.is_file() and p.suffix in ('.rs','.toml'):paths.append(p)
    paths.extend(REPO/p for p in ('Cargo.toml','Cargo.lock','rust-toolchain.toml'))
    paths.extend(Path(v['path']) for v in BUILD['libraries'])
    paths.extend(Path(v['path']) for v in BUILD['artifacts'].values())
    paths.extend(Path(v['path']) for v in BUILD['default_configurations'])
    paths.extend((Path(BUILD['generated_config']['path']),Path(BUILD['build'])/'src/include/gnunet_config.h'))
    return {str(p.resolve()):sha(p) for p in paths}

def seal_side(side, output):
    assert ALL_CHECKS and all(c['passed'] for c in ALL_CHECKS)
    assert len({c['id'] for c in ALL_CHECKS})==len(ALL_CHECKS)
    assert {s['name'] for s in SCENARIOS}==EXPECTED_SCENARIOS
    assert len(SCENARIOS)==len(EXPECTED_SCENARIOS)
    calls=collections.Counter();callbacks=collections.Counter();wire=set()
    for s in SCENARIOS:
        p=Path(s['trace']);assert sha(p)==s['sha256'],s['name']
        trace=json.loads(p.read_text());assert trace['scenario']==s['name']
        assert trace['all_owned_processes_reaped'] and trace['temporary_resources_removed']
        expected=-11 if side=='c' and s['name']=='reference-missing-hostname-crash' else 0
        assert trace['exit_code']==expected,(side,s['name'],trace['exit_code'])
        for e in trace['events']:
            event=e.get('event')
            if event in ('create','get','watch','get_cancel','watch_cancel','destroy_begin'):calls[event]+=1
            if event=='callback_cancel':calls['get_cancel']+=1
            if event=='call':calls[e['api'].lower()]+=1
            if event in ('row','cont'):callbacks[event]+=1
            if e['source']=='wire-out':wire.add(e['type'])
            if e['source']=='wire-in':
                data=bytes.fromhex(e['hex'])
                while len(data)>=4:
                    size,typ=struct.unpack('!HH',data[:4])
                    if size<4 or size>len(data):break
                    wire.add(typ);data=data[size:]
    assert all(calls[k]>0 for k in ('create','get','watch','get_cancel','watch_cancel','destroy_begin','set','update'))
    assert set(range(168,176))<=wire
    record={'side':side,'status':'passed','scope':'Selected actual public-owner operations, not full API/service verification','actual_assertions':len(ALL_CHECKS),'checks':ALL_CHECKS,'scenarios':SCENARIOS,'public_operation_events':dict(calls),'actual_callbacks':dict(callbacks),'official_wire_ids_observed':sorted(set(range(168,176))&wire),'all_probe_processes_reaped':True,'all_probe_temporary_resources_removed':True}
    (output/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    return record

def run_side(side, output, binary):
    global ROOT,BIN,TRACES,ALL_CHECKS,SCENARIOS,Probe
    ROOT=output;BIN=binary;TRACES=output/'traces';TRACES.mkdir(parents=True)
    ALL_CHECKS=[];SCENARIOS=[];Probe=ORIGINAL if side=='c' else RustProbe
    functions=(disable_lazy,local_tcp_and_reference_crash,coalescing,get_values,cancel_abort,failures,watch_hole,reconnect_pending,destroy_immediate,destroy_deferred,unused_timeout,normal_daemon) if side=='c' else (disable_lazy,local_tcp_and_reference_safe_error,coalescing,get_values,cancel_abort,rust_failures,watch_hole,reconnect_pending,destroy_immediate,destroy_deferred,unused_timeout,normal_daemon)
    for fn in functions:
        fn();print(side,fn.__name__,'passed',flush=True)
    return seal_side(side,output)

def main():
    global SOURCE,RECEIPT,BUILD,ENV,CROOT
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference',type=Path,required=True,help='Normal unchanged C statistics build-result.json')
    parser.add_argument('--rust',type=Path,required=True,help='Built statistics_public_owner Rust example')
    parser.add_argument('--output',type=Path,required=True,help='New evidence directory')
    parser.add_argument('--cc',default=os.environ.get('CC','cc'))
    args=parser.parse_args()
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    RECEIPT=args.reference.resolve();BUILD=json.loads(RECEIPT.read_text());SOURCE=Path(BUILD['source'])
    if BUILD.get('status')!='passed':raise ValueError('passed normal reference receipt required')
    before_source=builder.source_state(SOURCE)
    if before_source!=BUILD['upstream']:raise ValueError('reference tracked sources changed since normal build')
    for entry in [*BUILD['libraries'],*BUILD['artifacts'].values(),*BUILD['default_configurations'],BUILD['generated_config']]:
        if sha(entry['path'])!=entry['sha256']:raise ValueError('normal reference artifact changed: '+entry['path'])
    ENV={k:v for k,v in os.environ.items() if not k.startswith('GNUNET_')}
    ENV.update(BUILD['runtime_environment']);ENV['LC_ALL']='C'
    # The expected crashing C diagnostic must never create a core file.
    import resource
    _,hard=resource.getrlimit(resource.RLIMIT_CORE);resource.setrlimit(resource.RLIMIT_CORE,(0,hard))
    c_binary=output/'normal-c-owner'
    compile_argv=[args.cc,'-g','-std=c11','-D_DARWIN_C_SOURCE','-D_GNU_SOURCE','-Wall','-Wextra','-Werror','-I'+str(SOURCE/'src/include'),'-I'+str(Path(BUILD['build'])/'src/include')]+shlex.split(BUILD['build_environment']['CPPFLAGS'])+[str(Path(__file__).with_suffix('.c'))]+shlex.split(BUILD['build_environment']['LDFLAGS'])+['-L'+str(Path(BUILD['prefix'])/'lib'),'-Wl,-rpath,'+str(Path(BUILD['prefix'])/'lib'),'-lgnunetstatistics','-lgnunetutil','-o',str(c_binary)]
    completed=subprocess.run(compile_argv,capture_output=True,text=True,timeout=120)
    compilation={'argv':compile_argv,'exit_code':completed.returncode,'stdout':completed.stdout,'stderr':completed.stderr}
    (output/'compile-c.json').write_text(json.dumps(compilation,indent=2)+'\n')
    if completed.returncode:raise ValueError('normal C public owner compilation failed; see compile-c.json')
    rust=args.rust.resolve();before=collect_inputs(rust,c_binary)
    CROOT=output/'c';rroot=output/'rust'
    report={'status':'failed','scope':'Actual normal C and Rust public-owner selected fixture comparisons; explicit reference differences are not equality or whole-service completion','full_client_api_verified':False,'reference':{'path':str(RECEIPT),'sha256':sha(RECEIPT),'upstream':before_source},'compile_c':compilation,'inputs_before':before,'official_source_before':before_source}
    try:
        c=run_side('c',CROOT,c_binary)
        rust_result=run_side('rust',rroot,rust)
        pairs=compare()
        expected_differences={'get-values','normal-daemon-watch','watch-reconnect-hole','reference-missing-hostname-crash'}
        assert {p['scenario'] for p in pairs if p['classification']=='explicit_reference_difference'}==expected_differences
        assert len(DIFFERENCES)==6 and all(not d['c_expectation_matched'] for d in DIFFERENCES)
        assert {p['scenario'] for p in pairs}==EXPECTED_SCENARIOS
        # Identical literal input bytes must underlie every scripted comparison.
        c_by={s['name']:s for s in c['scenarios']}
        for s in rust_result['scenarios']:
            ct=json.loads(Path(c_by[s['name']]['trace']).read_text());rt=json.loads(Path(s['trace']).read_text())
            sent=lambda t:[e['hex'] for e in t['events'] if e['source']=='wire-in']
            assert sent(ct)==sent(rt),(s['name'],'literal input changed')
        canonical=json.loads((REPO/'spec/gnunet/api/statistics.json').read_text())
        cases=[case for f in canonical['public_functions'] for case in f['cases']]+canonical['cross_operation_cases']
        assert len(cases)==51 and {v['id'] for v in cases}=={v['id'] for v in CASE_REVIEW}
        case_by={case['id']:case for case in cases};actual={check['id'] for check in c['checks']}
        for item in CASE_REVIEW:
            assert set(item['actual_assertions'])<=actual
        coverage=[dict(item,requirement=case_by[item['id']]['requirement'],rust_requirement_verified=False) for item in CASE_REVIEW]
        report.update(c=c,rust=rust_result,pairs=pairs,known_differences_observed=DIFFERENCES,case_review=coverage,status='passed')
    except Exception as error:
        report['failure']=repr(error)
        raise
    finally:
        after=collect_inputs(rust,c_binary);after_source=builder.source_state(SOURCE)
        report.update(inputs_after=after,inputs_unchanged=before==after,official_source_after=after_source,official_sources_unchanged=before_source==after_source)
        if before!=after or before_source!=after_source:report['status']='failed'
        (output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    if report['status']!='passed':raise ValueError('participant/source changed during probe')
    print(json.dumps({'status':report['status'],'c_assertions':c['actual_assertions'],'rust_assertions':rust_result['actual_assertions'],'pairs':len(pairs),'equal_selected_wire_callback_pairs':sum(p['classification']=='equal_observed_wire_and_callback_values' for p in pairs),'explicit_difference_pairs':len(expected_differences),'full_client_api_verified':False,'result':str(output/'result.json')}))

if __name__=='__main__':main()
