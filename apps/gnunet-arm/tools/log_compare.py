#!/usr/bin/env python3
"""Log destination/append/body checks. Generic prefixes remain explicit pending."""
import argparse,json,os,re,subprocess,tempfile
from pathlib import Path
from paired import sha,save
MESSAGE=b'GNUnet not running, cannot stop the peer\n'
def actor(binary,profile,environment,destination):
    destination.mkdir()
    with tempfile.TemporaryDirectory(prefix='galog-',dir='/private/tmp')as owned:
        owned=Path(owned);home=owned/'home';home.mkdir();config=destination/'arm.conf';config.write_bytes(b'[PATHS]\nGNUNET_HOME = '+os.fsencode(home)+b'\n[arm]\nUNIXPATH = '+os.fsencode(owned/'s')+b'\n[TESTING]\nWEAKRANDOM = YES\n')
        logfile=os.fsencode(owned)+b'/log/sub/raw-bytes.log';os.makedirs(os.path.dirname(logfile));initial=b'owned-preexisting\n'
        with open(logfile,'wb')as f:f.write(initial)
        env=environment.copy();env.update(HOME=str(owned/'user'),XDG_CONFIG_HOME=str(owned/'xdg'),GNUNET_ARGS='')
        args=[b'gnunet-arm',b'-c',os.fsencode(config),b'-e',b'-l',logfile]+([b'-L',b'ERROR']if profile=='suppressed'else[])
        child=subprocess.run(args,executable=os.fsencode(binary),env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3)
        with open(logfile,'rb')as f:raw=f.read()
        if child.returncode or child.stdout or child.stderr or not raw.startswith(initial):raise RuntimeError('log routing/append failure')
        tail=raw[len(initial):];body=b''
        if profile=='warning':
            if not tail.endswith(MESSAGE):raise RuntimeError('actual warning missing')
            prefix=tail[:-len(MESSAGE)]
            if prefix and not re.fullmatch(rb'[0-9-]+T[0-9:.]+[+-][0-9]{4} gnunet-arm-[0-9]+ WARNING ',prefix):raise RuntimeError(('unrecognized normal prefix',prefix))
            body=MESSAGE
        elif tail:raise RuntimeError('ERROR threshold did not suppress WARNING')
        (destination/'log').write_bytes(raw);(destination/'stdout').write_bytes(child.stdout);(destination/'stderr').write_bytes(child.stderr)
        value={'exit':child.returncode,'stdout_hex':child.stdout.hex(),'stderr_hex':child.stderr.hex(),'original_bytes_preserved':True,'warning_body_hex':body.hex(),'native_byte_path_used':True}
        save(destination/'observation.json',value);return value

def main():
    p=argparse.ArgumentParser()
    for name in ['reference','rust','output']:p.add_argument('--'+name,type=Path,required=True)
    args=p.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False);receipt=json.loads(args.reference.read_text());normal=Path(receipt['artifacts']['client']['path']);assert sha(normal)==receipt['artifacts']['client']['sha256'];env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_'))};env.update(receipt['runtime_environment']);env.update(LC_ALL='C',GNUNET_ARGS='');base=out/'base';base.mkdir();env['GNUNET_BASE_CONFIG']=str(base);rows=[]
    try:
        for profile in ['suppressed','warning']:
            directory=out/profile;directory.mkdir();c=actor(normal,profile,env,directory/'c');rust=actor(args.rust,profile,env,directory/'rust');rows.append({'profile':profile,'matched_body_routing_append':c==rust,'c':c,'rust':rust})
            if c!=rust:raise RuntimeError('log body/destination differs')
        result={'status':'passed','scope':'actual -l native byte path, append, WARNING body and -L ERROR suppression; raw normal GNUnet timestamp/component/PID/severity prefix explicitly normalized, not equivalent or fully implemented','rows':rows,'full_generic_logging_complete':False,'normal_cli_sha256':sha(normal),'rust_cli_sha256':sha(args.rust)}
    except Exception as error:result={'status':'failed','error':str(error),'rows':rows};raise
    finally:save(out/'result.json',result)
    print(json.dumps({'status':result['status'],'profiles':len(rows),'full_generic_logging_complete':False}))
if __name__=='__main__':main()
