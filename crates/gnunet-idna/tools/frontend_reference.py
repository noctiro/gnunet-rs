#!/usr/bin/env python3
"""Fresh actual normal-C public GNUnet observations from the bundled55 fixtures."""
import argparse,pathlib,subprocess,json,hashlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--probe',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();out=a.output.resolve();assert not out.is_relative_to(ROOT) and not ROOT.is_relative_to(out),'Frontend output and source must be disjoint';out.mkdir(parents=True,exist_ok=True);actual=[]
 for row in (ROOT/'tests/frontend.tsv').read_text().splitlines():
  f=row.split('\t');assert len(f)==7;ident,raw,label,name,built,cap,wire=f;cmd=[str(a.probe.resolve()),raw,cap]
  r=subprocess.run(cmd,capture_output=True,text=True,check=True);v=json.loads(r.stdout)
  assert (v['label_rc'],v['name_rc'],v['builder_rc'],v['wire'])==(int(label),int(name),int(built),wire),ident
  assert v['off']==len(bytes.fromhex(wire)),ident
  actual.append({'id':ident,'argv':cmd,'input_sha256':hashlib.sha256(bytes.fromhex(raw)).hexdigest(),'observation':v,'stdout_sha256':hashlib.sha256(r.stdout.encode()).hexdigest()})
 assert len(actual)==55
 receipt={'status':'passed','count':55,'direct_correspondence':53,'explicit_boundaries':{'interior_nul_cstring_storage':1,'exact_root_wire_capacity':1},'reference_probe':{'path':str(a.probe.resolve()),'sha256':hashlib.sha256(a.probe.read_bytes()).hexdigest()},'fixture_sha256':hashlib.sha256((ROOT/'tests/frontend.tsv').read_bytes()).hexdigest(),'observations':actual}
 (out/'frontend-reference.json').write_text(json.dumps(receipt,indent=2)+'\n');print('55 actual C frontend observations reproduced;53 direct and2 explicit safe boundaries.')
if __name__=='__main__':main()
