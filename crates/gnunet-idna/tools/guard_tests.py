#!/usr/bin/env python3
"""Tools must reject source/ancestor destinations before reading or writing inputs."""
import pathlib,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
def main():
 tests=[]
 for destination in [ROOT,ROOT.parent]:
  tests.extend([
   ('generate.py',['--libidn2-source',ROOT/'nonexistent','--ucd15',ROOT/'nonexistent','--ucd18',ROOT/'nonexistent','--output',destination]),
   ('tools/build_probe.py',[q for name in ['gnunet-source','reference-build','reference-library','idn2-library','unistring-library'] for q in ['--'+name,ROOT/'nonexistent']]+['--output',destination]),
   ('tools/frontend_reference.py',['--probe',ROOT/'nonexistent','--output',destination]),
   ('tools/compare.py',[q for name in ['c-probe','rust-probe','ucd15','ucd18','libidn2-source'] for q in ['--'+name,ROOT/'nonexistent']]+['--output',destination,'selected']),
   ('tools/native_pack_compare.py',['--c-probe',ROOT/'nonexistent','--rust-probe',ROOT/'nonexistent','--output',destination]),
   ('verify.py',[q for name in ['gnunet-source','reference-build','reference-library','idn2-library','unistring-library','libidn2-source','libidn2-archive','libunistring-archive','ucd15','ucd18'] for q in ['--'+name,ROOT/'nonexistent']]+['--output',destination])
  ])
 for tool,args in tests:
  p=subprocess.run([sys.executable,'-B',str(ROOT/tool),*[str(x) for x in args]],capture_output=True,text=True)
  assert p.returncode!=0 and 'disjoint' in p.stderr,(tool,p.stdout,p.stderr)
 print('12 source/ancestor output-boundary guards rejected before nonexistent inputs were accessed.')
if __name__=='__main__':main()
