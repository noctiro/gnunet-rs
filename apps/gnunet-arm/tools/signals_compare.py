#!/usr/bin/env python3
"""Compare actual scheduler signal behavior, only against owned child PIDs."""
import argparse, json, os, selectors, signal, socket, struct, subprocess, tempfile, time
from pathlib import Path
from paired import sha, save, status
PROMPT = b'Now only monitoring, press CTRL-C to stop.\n'
def actor(binary, number, environment, destination):
    destination.mkdir(); proc = None; peers = []; selection = selectors.DefaultSelector(); wire = []; pre_error = bytearray()
    with tempfile.TemporaryDirectory(prefix='gasig-', dir='/private/tmp') as owned:
        owned = Path(owned); endpoint = owned/'s'; home = owned/'home'; home.mkdir(); config = destination/'arm.conf'
        config.write_bytes(b'[PATHS]\nGNUNET_HOME = '+os.fsencode(home)+b'\n[arm]\nUNIXPATH = '+os.fsencode(endpoint)+b'\n[TESTING]\nWEAKRANDOM = YES\n')
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); listener.bind(str(endpoint)); listener.listen(); listener.setblocking(False); selection.register(listener, selectors.EVENT_READ, 'listen')
        env = environment.copy(); env.update(HOME=str(owned/'user'), XDG_CONFIG_HOME=str(owned/'xdg'), GNUNET_ARGS='')
        try:
            proc = subprocess.Popen([b'gnunet-arm',b'-c',os.fsencode(config),b'-L',b'ERROR',b'-m',b'-T',b'250ms'], executable=os.fsencode(binary), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            os.set_blocking(proc.stderr.fileno(), False); selection.register(proc.stderr, selectors.EVENT_READ, 'stderr')
            sent = False; registered = False; deadline = time.monotonic()+3
            while proc.poll() is None:
                if time.monotonic()>deadline: raise RuntimeError('owned signal watchdog')
                for key,_ in selection.select(.005):
                    if key.data == 'listen':
                        conn,_ = listener.accept(); conn.setblocking(False); peer = {'socket':conn,'rx':bytearray()}; peers.append(peer); selection.register(conn,selectors.EVENT_READ,peer)
                    elif key.data == 'stderr':
                        part = os.read(proc.stderr.fileno(),65535)
                        if part: pre_error.extend(part)
                        else: selection.unregister(proc.stderr)
                    else:
                        peer = key.data; conn = peer['socket']
                        try: part = conn.recv(65535)
                        except BlockingIOError: continue
                        if not part: selection.unregister(conn); conn.close(); continue
                        peer['rx'].extend(part)
                        while len(peer['rx'])>=4:
                            size,kind = struct.unpack('>HH',peer['rx'][:4])
                            if size<4: raise RuntimeError('bad actor frame')
                            if len(peer['rx'])<size: break
                            frame = bytes(peer['rx'][:size]); del peer['rx'][:size]; wire.append(frame.hex())
                            if kind==15: conn.sendall(frame)
                            elif kind==14: conn.sendall(status(0,b'arm')); registered=True
                            else: raise RuntimeError('unexpected signal actor frame')
                if not sent and registered and PROMPT in pre_error:
                    proc.send_signal(number); sent=True
            if not sent: raise RuntimeError('signal not sent after real monitor admission')
            os.set_blocking(proc.stderr.fileno(),True); stdout,stderr=proc.communicate(timeout=1); stderr=bytes(pre_error)+stderr
            expected=2 if number==signal.SIGPIPE else 0
            if proc.returncode!=expected or stdout or stderr!=PROMPT: raise RuntimeError(('signal behavior',number,proc.returncode,stdout,stderr))
            observation={'exit':proc.returncode,'stdout_hex':stdout.hex(),'stderr_hex':stderr.hex(),'signal_sent_after_monitor_and_prompt':sent}
            (destination/'stdout').write_bytes(stdout);(destination/'stderr').write_bytes(stderr);save(destination/'wire.json',wire);save(destination/'observation.json',observation)
            return observation
        finally:
            if proc is not None and proc.poll() is None: proc.kill();proc.communicate(timeout=2)
            for peer in peers: peer['socket'].close()
            listener.close();selection.close()
def main():
    ap=argparse.ArgumentParser()
    for name in ['reference','rust','output']:ap.add_argument('--'+name,type=Path,required=True)
    args=ap.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False);receipt=json.loads(args.reference.read_text());normal=Path(receipt['artifacts']['client']['path']);assert sha(normal)==receipt['artifacts']['client']['sha256']
    env={k:v for k,v in os.environ.items() if not k.startswith(('GNUNET_','LISTEN_'))};env.update(receipt['runtime_environment']);env['LC_ALL']='C';base=out/'base';base.mkdir();env['GNUNET_BASE_CONFIG']=str(base);rows=[]
    try:
        for name in ['SIGINT','SIGTERM','SIGQUIT','SIGHUP','SIGPIPE']:
            directory=out/name;directory.mkdir();number=getattr(signal,name);c=actor(normal,number,env,directory/'c');rust=actor(args.rust,number,env,directory/'rust');rows.append({'name':name,'matched':c==rust,'c':c,'rust':rust});save(out/'progress.json',rows)
            if c!=rust:raise RuntimeError('signal mismatch '+name)
        result={'status':'passed','scope':'actual CLI entrypoints, real signal delivered only after owned literal monitor admission and observed prompt; SIGPIPE must remain live until official timeout','rows':rows,'processes':2*len(rows),'normal_cli_sha256':sha(normal),'rust_cli_sha256':sha(args.rust)}
    except Exception as error:result={'status':'failed','error':str(error),'rows':rows};raise
    finally:save(out/'result.json',result)
    print(json.dumps({'status':result['status'],'cases':len(rows)}))
if __name__=='__main__':main()
