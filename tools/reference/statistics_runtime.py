#!/usr/bin/env python3
"""Normal C client/service versus Rust official Unix/TCP/activation runtime.

Only owned private directories and loopback sockets are used. Numeric inherited
FDs are duplicated to deliberately nonconsecutive values; no systemd protocol,
peer transport, public bootstrap or private application framing is introduced.
"""
import argparse
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sys
import tempfile

sys.dont_write_bytecode = True
from statistics_daemons import Harness, REVISION, digest, save, snapshot, source_state
from source_fingerprint import fingerprints

ROOT = Path(__file__).resolve().parents[2]
IPV6_UNAVAILABLE = {errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT,
                    errno.EADDRNOTAVAIL, errno.ENOPROTOOPT}


def ready_line(kind, memory=False):
    if kind != 'rust':
        return None
    persistence = b'memory-only' if memory else b'official-set-snapshot'
    return (b'READY statistics wire=0.29.1 persistence=' + persistence
            + b' authentication=kernel-unix\n')


def duplicate_listener(parent, minimum, foreign, errors, label):
    # A raw F_DUPFD result has no destructor. Defer already-handled signals
    # across acquisition/registration, then restore handlers before any launch.
    previous, pending = {}, {}
    fd = None
    registered = False
    original = None

    def defer(signum, frame):
        pending.setdefault(signum, frame)

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            handler = signal.getsignal(signum)
            if callable(handler):
                previous[signum] = handler
                signal.signal(signum, defer)
        fd = fcntl.fcntl(parent.fileno(), fcntl.F_DUPFD, minimum)
        foreign.append(fd)
        registered = True
    except BaseException as error:
        original = error
        if fd is not None and not registered:
            try:
                os.close(fd)
            except BaseException as cleanup:
                errors.append({'name':label, 'phase':'unregistered-fd-close',
                               'fd':fd, 'error':type(cleanup).__name__+': '+str(cleanup)})
    finally:
        for signum, handler in previous.items():
            try:
                signal.signal(signum, handler)
            except BaseException as error:
                errors.append({'name':label, 'phase':'restore-signal-'+str(signum),
                               'error':type(error).__name__+': '+str(error)})
                if original is None:
                    original = error
    if original is not None:
        raise original
    for signum, frame in pending.items():
        previous[signum](signum, frame)


def close_listeners(foreign, parents, errors, label):
    # Raw duplicated FDs have no destructor: record ownership immediately after
    # each acquisition, then attempt every independent close on every exit.
    for fd in foreign:
        try:
            os.close(fd)
        except BaseException as error:
            errors.append({'phase': 'inherited-fd-close', 'name': label,
                           'fd': fd, 'error': type(error).__name__ + ': ' + str(error)})
    for parent in parents:
        try:
            parent.close()
        except BaseException as error:
            errors.append({'phase': 'parent-listener-close', 'name': label,
                           'error': type(error).__name__ + ': ' + str(error)})

def config(path, unix=None, port=0, hostname='127.0.0.1', database=None, bind='127.0.0.1', deny=False):
    text = '[statistics]\nPORT = %s\nHOSTNAME = %s\nBINDTO = %s\nDISABLEV6 = YES\nUNIX_MATCH_UID = YES\nUNIX_MATCH_GID = NO\n' % (port, hostname, bind)
    if unix is not None:
        text += 'UNIXPATH = %s\n' % unix
    if database is not None:
        text += 'DATABASE = %s\n' % database
    if deny:
        text += 'ACCEPT_FROM = 192.0.2.1;\n'
    path.write_text(text)

def run_suite():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--reference', required=True, type=Path)
    p.add_argument('--rust-service', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    output = a.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    report = {'schema':1, 'kind':'normal-c-statistics-service-runtime', 'status':'failed',
              'full_gnunet_conformance':False, 'full_statistics_verified':False,
              'selected_profile':'normal-service-listeners', 'skipped_profiles':[], 'scope':'Real Unix/TCP listeners, numeric inherited FDs, service ACL and no-DATABASE memory lifetime. Not the complete service/util/ARM or P2P contract.'}
    h = None; runtime = None; cleanup_errors = []
    try:
        receipt = json.loads(a.reference.read_text())
        if receipt.get('status')!='passed' or receipt.get('kind')!='unmodified-official-c-reference-build' or receipt['upstream']['revision']!=REVISION:
            raise ValueError('normal pinned C build receipt required')
        source_before = source_state(Path(receipt['source']))
        if source_before != receipt['upstream']:
            raise ValueError('C source changed since normal build')
        reference_inputs=[*receipt['artifacts'].values(),*receipt['libraries'],*receipt['default_configurations']]
        for row in reference_inputs:
            if digest(row['path'])!=row['sha256']:raise ValueError('C reference file changed: '+row['path'])
        rust_before = fingerprints(ROOT)
        report['source_inputs'] = rust_before
        report['reference_receipt']={'path':str(a.reference.resolve()),'sha256':digest(a.reference)}
        report['upstream']=receipt['upstream']
        binaries=output/'binaries';binaries.mkdir()
        original={'rust':a.rust_service.resolve(),'c':Path(receipt['artifacts']['service']['path']),'client':Path(receipt['artifacts']['client']['path'])}
        actual={key:snapshot(path,binaries,key) for key,path in original.items()}
        report['participants']={key:{'original':str(original[key]),'snapshot':str(path),'sha256':digest(path)} for key,path in actual.items()}
        env={key:value for key,value in os.environ.items() if not key.startswith(('GNUNET_','LISTEN_'))}
        env.update(receipt['runtime_environment'],LC_ALL='C')
        runtime=Path(tempfile.mkdtemp(prefix='grt-'));runtime.chmod(0o700)
        report['owned_runtime']=str(runtime)
        for key,name in [('XDG_CONFIG_HOME','config'),('XDG_DATA_HOME','data'),('XDG_CACHE_HOME','cache'),('XDG_RUNTIME_DIR','runtime')]:
            directory=runtime/name;directory.mkdir(mode=0o700);env[key]=str(directory)
        h=Harness(output,env);report['commands']=h.commands;report['checks']=h.checks
        def client(name,conf,value=None,persistent=False):
            argv=[str(actual['client']),'-c',str(conf),'-L','ERROR','-q','-s','runtime-oracle','-n','value']
            if persistent:argv.append('-p')
            if value is not None:argv.append(str(value))
            return h.command(name,argv)
        for kind in ['c','rust']:
            for inherited in [False,True]:
                label=kind+('-inherited' if inherited else '-bound')
                directory=runtime/label;directory.mkdir()
                sock=directory/'s';database=directory/'stats';conf=directory/'service.conf'
                parents=[];foreign=[]
                try:
                    if inherited:
                        local=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);parents.append(local)
                        local.bind(str(sock));local.listen(5);os.chmod(sock,0o700)
                        tcp=socket.socket(socket.AF_INET,socket.SOCK_STREAM);parents.append(tcp)
                        tcp.bind(('127.0.0.1',0));tcp.listen(5);port=tcp.getsockname()[1]
                        v6=None
                        try:
                            v6=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);parents.append(v6)
                            v6.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
                            v6.bind(('::1',0));v6.listen(5)
                        except OSError as error:
                            if error.errno not in IPV6_UNAVAILABLE:
                                raise
                            report['skipped_profiles'].append({
                                'name':label+'-ipv6', 'phase':'listener-acquisition',
                                'errno':error.errno, 'reason':str(error)})
                            if v6 is not None:
                                v6.close();parents.remove(v6)
                            v6=None
                        # Official GNUNET_NETWORK launchers supply nonblocking listeners.
                        # The normal C accept loop relies on this inherited state.
                        for parent in parents:parent.setblocking(False)
                        for index,parent in enumerate(parents):
                            duplicate_listener(parent,128+index*32,foreign,cleanup_errors,label)
                        # These invalid configured bind addresses must be ignored
                        # when a valid inherited listener set is actually used.
                        config(conf,unix=directory/'unused',port=port,database=database,bind='not-a-numeric-address.invalid')
                        child_env=dict(env,LISTEN_FDS=str(len(foreign)),LISTEN_FDNAMES=':'.join(map(str,foreign)),LISTEN_PID='1')
                    else:
                        with socket.socket() as reserve:
                            reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
                        config(conf,unix=sock,port=port,database=database)
                        child_env=env
                    argv=[str(actual[kind]),'-c',str(conf),'-L','ERROR']
                    service=h.start(label,argv,pass_fds=foreign,env=child_env)
                    h.ready(service,sock,ready_line(kind))
                    mode=sock.stat().st_mode&0o777
                    h.check(label+'-unix-mode-private',mode==0o700,{'actual_mode':oct(mode),'expected_mode':'0o700','match_uid':True,'match_gid':False})
                    unix_conf=directory/'unix.conf';config(unix_conf,unix=sock,database=database)
                    client(label+'-set-unix',unix_conf,31)
                    tcp_conf=directory/'tcp.conf';config(tcp_conf,port=port,database=database)
                    h.check(label+'-get-over-tcp',client(label+'-get-tcp',tcp_conf).strip()==b'31')
                    client(label+'-set-tcp',tcp_conf,47)
                    h.check(label+'-cross-listener-core',client(label+'-get-unix',unix_conf).strip()==b'47')
                    if inherited and v6 is not None:
                        v6_conf=directory/'ipv6.conf';config(v6_conf,port=v6.getsockname()[1],hostname='::1',database=database)
                        h.check(label+'-all-inherited-listeners',client(label+'-get-ipv6',v6_conf).strip()==b'47')
                    if inherited:
                        h.check(label+'-ignores-configured-bind',not (directory/'unused').exists())
                        h.check(label+'-nonconsecutive-numeric-fds',foreign[0]>=128 and all(b-a>=32 for a,b in zip(foreign,foreign[1:])),foreign)
                    h.finish(service)
                    h.check(label+'-path-lifetime',sock.exists()==inherited)
                finally:
                    close_listeners(foreign,parents,cleanup_errors,label)
            # ACL rejection must not affect Unix admission or other connections.
            directory=runtime/(kind+'-acl');directory.mkdir();sock=directory/'s';conf=directory/'service.conf'
            with socket.socket() as reserve:
                reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
            config(conf,unix=sock,port=port,database=directory/'stats',deny=True)
            argv=[str(actual[kind]),'-c',str(conf),'-L','ERROR']
            service=h.start(kind+'-acl',argv);h.ready(service,sock,ready_line(kind))
            unix_conf=directory/'unix.conf';config(unix_conf,unix=sock)
            client(kind+'-acl-unix-set',unix_conf,61)
            with socket.create_connection(('127.0.0.1',port),timeout=3) as denied:
                denied.settimeout(3);h.check(kind+'-acl-real-denial',denied.recv(1)==b'')
            h.check(kind+'-acl-unix-unaffected',client(kind+'-acl-unix-get',unix_conf).strip()==b'61')
            h.finish(service)
            # The service entrypoint has its own XDG/user-file discovery;
            # it must load that candidate without an explicit -c option.
            directory=runtime/(kind+'-default');directory.mkdir();xdg=directory/'xdg';xdg.mkdir()
            sock=directory/'s';conf=xdg/'gnunet.conf'
            config(conf,unix=sock,database=directory/'stats')
            child_env=dict(env,XDG_CONFIG_HOME=str(xdg))
            argv=[str(actual[kind]),'-L','ERROR']
            service=h.start(kind+'-default-config',argv,env=child_env);h.ready(service,sock,ready_line(kind))
            client(kind+'-default-config-set',conf,65)
            h.check(kind+'-default-config-selected',client(kind+'-default-config-get',conf).strip()==b'65')
            h.finish(service)
            # Exercise the actual NETWORK_shorten_unixpath contract across a
            # normal C client and each service, not merely equal local codecs.
            directory=runtime/(kind+'-long');directory.mkdir()
            long_dir=directory/('a'*70)/('b'*70);long_dir.mkdir(parents=True)
            configured=long_dir/'s';conf=directory/'service.conf'
            alphabet=b'0123456789ABCDEFGHJKMNPQRSTVWXYZ'
            hashed=int.from_bytes(hashlib.sha512(os.fsencode(configured)).digest(),'big')
            suffix=bytes(alphabet[(hashed>>(512-5*(i+1)))&31] for i in range(16))
            prefix=os.fsencode(configured);limit=104 if sys.platform.startswith(('darwin','freebsd','openbsd','netbsd')) else 108
            while 16+len(prefix)>=limit:prefix=prefix.rsplit(b'/',1)[0]
            actual_path=Path(os.fsdecode(prefix+suffix))
            config(conf,unix=configured,database=directory/'stats')
            argv=[str(actual[kind]),'-c',str(conf),'-L','ERROR']
            service=h.start(kind+'-long-unix',argv);h.ready(service,actual_path,ready_line(kind))
            client(kind+'-long-unix-set',conf,67)
            h.check(kind+'-long-unix-c-client-matches',client(kind+'-long-unix-get',conf).strip()==b'67')
            mode=actual_path.stat().st_mode&0o777
            h.check(kind+'-shortened-path-exact-and-private',not configured.exists() and mode==0o700,{'actual_mode':oct(mode),'expected_mode':'0o700','match_uid':True,'match_gid':False})
            h.finish(service);h.check(kind+'-shortened-path-cleanup',not actual_path.exists())
            # No DATABASE is an official in-memory service mode, including
            # processing persistent-marked rows without promising a disk commit.
            directory=runtime/(kind+'-memory');directory.mkdir();sock=directory/'s';conf=directory/'service.conf'
            defaults=directory/'defaults';defaults.mkdir()
            config(conf,unix=sock)
            memory_env=dict(env,GNUNET_BASE_CONFIG=str(defaults))
            for generation in [0,1]:
                argv=[str(actual[kind]),'-c',str(conf),'-L','ERROR']
                service=h.start(kind+'-memory-'+str(generation),argv,env=memory_env)
                h.ready(service,sock,ready_line(kind,memory=True))
                if generation==0:
                    client(kind+'-memory-set',conf,73,persistent=True)
                    h.check(kind+'-memory-live-value',client(kind+'-memory-get',conf).strip()==b'73')
                else:
                    h.check(kind+'-memory-restart-is-empty',client(kind+'-memory-get-after-restart',conf)==b'')
                h.finish(service)
        report['rust_sources_unchanged']=rust_before==fingerprints(ROOT)
        report['reference_receipt_unchanged']=digest(a.reference)==report['reference_receipt']['sha256']
        report['reference_source_unchanged']=source_state(Path(receipt['source']))==source_before
        report['reference_files_unchanged']=all(digest(row['path'])==row['sha256'] for row in reference_inputs)
        report['participants_unchanged']=all(digest(original[key])==digest(actual[key])==row['sha256'] for key,row in report['participants'].items())
        h.check('all-inputs-and-participants-unchanged',all(report[key] for key in ['rust_sources_unchanged','reference_source_unchanged','reference_files_unchanged','reference_receipt_unchanged','participants_unchanged']))
        report['status']='passed'
    except (Exception, KeyboardInterrupt) as error:
        report['failure']=type(error).__name__+': '+str(error)
    finally:
        if h is not None:
            try:
                h.cleanup()
            except BaseException as error:
                cleanup_errors.append({'phase':'harness-cleanup',
                                       'error':type(error).__name__+': '+str(error)})
            cleanup_errors.extend(h.cleanup_errors)
            report['all_children_reaped']=True
            for owned in h.services:
                try:
                    if owned['process'] is not None and owned['process'].poll() is None:
                        report['all_children_reaped']=False
                        cleanup_errors.append({'name':owned['row']['name'],
                                               'phase':'final-reap-observation',
                                               'error':'owned child remains live'})
                except BaseException as error:
                    report['all_children_reaped']=False
                    cleanup_errors.append({'name':owned['row']['name'],
                                           'phase':'final-reap-observation',
                                           'error':type(error).__name__+': '+str(error)})
        if runtime is not None:
            try:
                shutil.rmtree(runtime);report['runtime_removed']=not runtime.exists()
            except BaseException as error:
                report['runtime_removed']=False
                cleanup_errors.append({'phase':'runtime-directory',
                                       'error':type(error).__name__+': '+str(error)})
        report['cleanup_errors']=cleanup_errors
        if cleanup_errors:
            report['status']='failed'
        report['executed_checks']=len(report.get('checks',[]))
        try:
            save(output/'result.json',report)
        except BaseException as error:
            report['status']='failed'
            report['report_failure']=type(error).__name__+': '+str(error)
    print(json.dumps({'status':report['status'],'checks':report['executed_checks'],
                      'report':str(output/'result.json'),'failure':report.get('failure'),
                      'cleanup_errors':report['cleanup_errors'],
                      'report_failure':report.get('report_failure')}))
    return 0 if report['status']=='passed' else 1

def main():
    def interrupted(signum, _frame):
        raise InterruptedError('harness interrupted by signal '+str(signum))
    signal.signal(signal.SIGTERM,interrupted)
    return run_suite()


if __name__=='__main__':raise SystemExit(main())
