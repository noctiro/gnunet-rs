#!/usr/bin/env python3
"""Compile only the small caller against an existing unchanged normal C build."""
import argparse,hashlib,json,os,pathlib,shlex,subprocess

def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--build-receipt',type=pathlib.Path,required=True);ap.add_argument('--package',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]);ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args();a.output=a.output.resolve();a.package=a.package.resolve()
    assert not a.output.is_relative_to(a.package) and not a.package.is_relative_to(a.output),'output/source must be disjoint'
    a.output.mkdir(parents=True,exist_ok=False)
    receipt=json.loads(a.build_receipt.read_text());assert receipt['status']=='passed' and receipt['source_unchanged'] and receipt['upstream']['revision']=='346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
    for item in [*receipt['artifacts'].values(),*receipt['libraries'],*receipt['default_configurations']]:assert sha(item['path'])==item['sha256'],item['path']
    build=pathlib.Path(receipt['build']);entries=json.loads((build/'compile_commands.json').read_text());entry=next(e for e in entries if e['file'].endswith('/resolver_api.c'));args=entry.get('arguments') or shlex.split(entry['command']);directory=pathlib.Path(entry['directory']);flags=[];i=1
    while i<len(args):
        x=args[i]
        if x in ('-o','-MF','-MQ','-MT'):i+=2;continue
        if x in ('-c','-MD','-MMD'):i+=1;continue
        if not x.startswith('-') and x.endswith('.c'):i+=1;continue
        if x.startswith('-I') and len(x)>2:
            p=pathlib.Path(x[2:]);x='-I'+str(p if p.is_absolute() else directory/p)
        flags.append(x);i+=1
    library=pathlib.Path(receipt['runtime_environment']['DYLD_LIBRARY_PATH'].split(':')[0])/'libgnunetutil.23.dylib';expected=next(row for row in receipt['libraries'] if pathlib.Path(row['path']).resolve()==library.resolve());assert sha(library)==expected['sha256']
    source=a.package/'tools/public_client.c';binary=a.output/'public-client';argv=[args[0],*flags,str(source),str(library),'-Wl,-rpath,'+str(library.parent),'-o',str(binary)]
    before={str(p):sha(p) for p in [source,library,a.build_receipt,build/'src/include/gnunet_config.h',pathlib.Path(__file__).resolve(),build/'compile_commands.json',build/'gnunet_private_config.h']};p=subprocess.run(argv,capture_output=True,cwd=directory);(a.output/'stdout').write_bytes(p.stdout);(a.output/'stderr').write_bytes(p.stderr);r={'argv':argv,'cwd':str(directory),'exit_code':p.returncode,'inputs':before,'inputs_unchanged':all(sha(p)==h for p,h in before.items()),'binary':{'path':str(binary),'sha256':sha(binary)} if p.returncode==0 else None,'normal_C_library_not_rebuilt':True};(a.output/'result.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'exit_code':p.returncode,'result':str(a.output/'result.json')}));return p.returncode
if __name__=='__main__':raise SystemExit(main())
