#!/usr/bin/env python3
"""Read-only compiler/Meson inventory. Generated captures are external test artifacts, never implementation or compatibility credit."""
import argparse,concurrent.futures,gzip,hashlib,json,os,re,shlex,subprocess,sys,time
from pathlib import Path
PARSER=argparse.ArgumentParser(description=__doc__)
PARSER.add_argument('--source',type=Path,required=True)
PARSER.add_argument('--build',type=Path,required=True)
PARSER.add_argument('--output',type=Path,required=True,help='new capture directory; raw captures remain external test artifacts')
PARSER.add_argument('--compiler',default='clang',help='Clang frontend used for typed AST parsing with actual Meson target flags')
PARSER.add_argument('--define',action='append',default=[],help='explicit supplemental discovery macro, e.g. ENABLE_MALICIOUS=1; does not claim a built production feature')
OPTIONS=PARSER.parse_args()
SOURCE=OPTIONS.source.resolve()
BUILD=OPTIONS.build.resolve()
OUT=OPTIONS.output.resolve()
if OUT.exists():raise SystemExit('capture output must be a new directory')
OUT.mkdir(parents=True)
ROW=next(r for r in json.loads((BUILD/'compile_commands.json').read_text()) if r['file'].endswith('statistics_api.c'))
ARGS=shlex.split(ROW['command']);ARGS[0]=OPTIONS.compiler;FLAGS=[];i=1
while i<len(ARGS):
 a=ARGS[i]
 if a in ('-o','-MQ','-MF'):i+=2;continue
 if a in ('-MD','-c') or a==ROW['file'] or a.startswith('-fdiagnostics-color'):i+=1;continue
 FLAGS.append(a);i+=1
# Include paths come from the actual configured build graph; retain the native
# statistics/public-client macros, not private per-module compile definitions.
for row in json.loads((BUILD/'compile_commands.json').read_text()):
 for arg in shlex.split(row['command']):
  if arg.startswith('-I') and arg not in FLAGS:FLAGS.append(arg)
FLAGS.extend('-D'+value for value in OPTIONS.define)
PLAN=json.loads((BUILD/'meson-info/intro-install_plan.json').read_text())
HEADERS=sorted(Path(p) for p in PLAN['headers'] if Path(p).name.startswith(('gnunet_','gnu_name_system_')))
HEADERS += [BUILD/'src/include/gnunet_config.h']
TARGETS=json.loads((BUILD/'meson-info/intro-targets.json').read_text())
DECODER=json.JSONDecoder()
KINDS={'FunctionDecl','TypedefDecl','RecordDecl','EnumDecl','EnumConstantDecl','VarDecl'}
OUT.mkdir(exist_ok=True);(OUT/'headers').mkdir(exist_ok=True)
def digest(b):return hashlib.sha256(b).hexdigest()
def decode(s):
 off=0
 while off<len(s):
  while off<len(s) and s[off].isspace():off+=1
  if off==len(s):return
  node,off=DECODER.raw_decode(s,off);yield node

def location(loc):
 if 'expansionLoc' in loc:return location(loc['expansionLoc'])
 if 'spellingLoc' in loc:return location(loc['spellingLoc'])
 return loc

def filepath(loc):
 value=location(loc).get('file')
 if not value:return None
 path=Path(value)
 return (path if path.is_absolute() else BUILD/path).resolve()

def allnodes(node):
 yield node
 for child in node.get('inner',[]):yield from allnodes(child)

def conditions(data):
 stack=[];table={};directives=[];guard=None
 for line,text in enumerate(data.splitlines(),1):
  match=re.match(r'\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)',text)
  if match:
   kind,condition=match[1],match[2].strip()
   directives.append({'line':line,'directive':kind,'condition':condition})
   if kind in ('if','ifdef','ifndef'):
    if guard is None and kind=='ifndef' and condition.endswith('_H'):guard=condition
    stack.append({'line':line,'branch':kind,'condition':condition,'include_guard':kind=='ifndef' and condition==guard})
   elif kind in ('elif','else') and stack:
    prior=stack[-1];stack[-1]={'line':line,'branch':kind,'condition':condition,'preceding_condition':prior['condition'],'include_guard':False}
   elif kind=='endif' and stack:stack.pop()
  table[line]=[dict(item) for item in stack if not item['include_guard']]
 return table,directives,guard

def brief(node):
 text=[];tags=[]
 for c in node.get('inner',[]):
  if c.get('kind')!='FullComment':continue
  for n in allnodes(c):
   if n.get('kind')=='TextComment' and n.get('text','').strip():text.append(n['text'].strip())
   if n.get('kind') in ('BlockCommandComment','ParamCommandComment','TParamCommandComment'):
    tags.append({k:n[k] for k in ('kind','name','param','direction','explicit') if k in n})
 return (' '.join(text)[:300],tags)

def extract_node(node,header,raw,conditional):
 loc=location(node.get('loc',{}));line=loc.get('line')
 if line is None and 'offset' in loc:line=raw[:loc['offset']].count(b'\n')+1
 item={'kind':node['kind'],'name':node['name'],'line':line,'offset':loc.get('offset'),
       'type':node.get('type',{}).get('qualType'), 'canonical_type':node.get('type',{}).get('desugaredQualType'),
       'storage_class':node.get('storageClass'),'inline':node.get('inline',False),
       'attributes':[n['kind'] for n in node.get('inner',[]) if n.get('kind','').endswith('Attr')],
       'conditions':conditional.get(line,[])}
 text,tags=brief(node);item['documentation_brief']=text;item['documentation_tags']=tags
 if node['kind']=='FunctionDecl':
  item['parameters']=[{'name':n.get('name'),'type':n.get('type',{}).get('qualType'),'canonical_type':n.get('type',{}).get('desugaredQualType')} for n in node.get('inner',[]) if n.get('kind')=='ParmVarDecl']
  item['body_present']=any(n.get('kind')=='CompoundStmt' for n in node.get('inner',[]))
  item['linkage_role']='header-inline-helper' if item['storage_class']=='static' or item['inline'] else 'public-external-function'
  item['variadic']=node.get('variadic',False)
 elif node['kind']=='TypedefDecl':
  item['callback']=any(n.get('kind')=='FunctionProtoType' for n in allnodes(node))
 elif node['kind']=='RecordDecl':
  item['complete_definition']=node.get('completeDefinition',False)
  item['record_tag']=node.get('tagUsed')
  item['fields']=[{'name':n.get('name'),'type':n.get('type',{}).get('qualType'),'bitfield':n.get('isBitfield',False)} for n in node.get('inner',[]) if n.get('kind')=='FieldDecl']
 elif node['kind']=='EnumDecl':
  item['constants']=[{'name':n.get('name'),'value':next((v.get('value') for v in allnodes(n) if 'value' in v),None)} for n in node.get('inner',[]) if n.get('kind')=='EnumConstantDecl']
 # Source spans keep exact original declaration/schema available without relying
 # on a regex to identify signatures or accidentally count macro invocations.
 for side in ('begin','end'):
  point=location(node.get('range',{}).get(side,{}));item['source_'+side]={k:point[k] for k in ('offset','line','col','tokLen') if k in point}
 return item

def macros(data,header):
 active=None;line=0;out=[]
 for value in data.splitlines():
  marker=re.match(r'#\s+(\d+)\s+"([^"]+)"',value)
  if marker:
   line=int(marker[1]);path=Path(marker[2]);active=(path if path.is_absolute() else BUILD/path).resolve();continue
  match=re.match(r'#define\s+(GNUNET_[A-Za-z0-9_]+)(.*)',value)
  if match and active==header.resolve():
   remainder=match[2];out.append({'name':match[1],'line':line,'function_like':remainder.startswith('('),'definition':remainder.strip()})
  line+=1
 return out

def work(header):
 name=header.name;folder=OUT/'headers'/name;folder.mkdir(exist_ok=True)
 tu=folder/'inventory.c';tu.write_text('#include "platform.h"\n#include "gnunet_util_lib.h"\n' + ('#include "gnunet_testing_lib.h"\n' if header.name.startswith('gnunet_testing_') else '') + '#define __GNUNET_UTIL_LIB_H_INSIDE__\n#include "'+str(header)+'"\n#undef __GNUNET_UTIL_LIB_H_INSIDE__\n')
 command=[ARGS[0],*FLAGS,'-fparse-all-comments','-fsyntax-only','-Xclang','-ast-dump=json','-Xclang','-ast-dump-filter=GNUNET_',str(tu)]
 started=time.monotonic();process=subprocess.run(command,cwd=BUILD,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
 (folder/'ast.stderr.txt').write_bytes(process.stderr)
 with gzip.open(folder/'ast.jsons.gz','wb') as out:out.write(process.stdout)
 raw=header.read_bytes();conditional,directives,guard=conditions(raw.decode())
 declarations=[];originless=[];duplicate=set()
 for node in decode(process.stdout.decode()):
  if node.get('kind') not in KINDS or not node.get('name','').startswith('GNUNET_'):continue
  origin=filepath(node.get('loc',{}))
  if origin is None:originless.append({'kind':node['kind'],'name':node['name'],'loc':node.get('loc')});continue
  if origin!=header.resolve():continue
  key=(node['kind'],node['name'],location(node.get('loc',{})).get('offset'))
  if key in duplicate:continue
  duplicate.add(key);declarations.append(extract_node(node,header,raw,conditional))
 preprocess=[ARGS[0],*FLAGS,'-E','-dD',str(tu)]
 pp=subprocess.run(preprocess,cwd=BUILD,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
 (folder/'preprocess.stderr.txt').write_bytes(pp.stderr)
 with gzip.open(folder/'preprocessed.c.gz','wb') as out:out.write(pp.stdout)
 result={'path':str(header.relative_to(SOURCE)) if header.is_relative_to(SOURCE) else str(header),
         'source_sha256':digest(raw),'configured_install_destination':PLAN['headers'].get(str(header),{}).get('destination','include/gnunet/gnunet_config.h'),
         'clang_exit_code':process.returncode,'preprocess_exit_code':pp.returncode,'elapsed_seconds':round(time.monotonic()-started,4),
         'ast_command':command,'preprocess_command':preprocess,'compiler_directory':str(BUILD),'translation_unit':tu.read_text(),'translation_unit_sha256':digest(tu.read_bytes()),
         'ast_sha256':digest(process.stdout),'preprocessed_sha256':digest(pp.stdout),'declarations':declarations,
         'macros':macros(pp.stdout.decode(),header),'conditional_directives':directives,'include_guard':guard,
         'unresolved_origin_declarations':originless,'diagnostics':process.stderr.decode(),
         'extraction_status':'complete-for-configured-profile' if process.returncode==pp.returncode==0 and not originless else 'requires-review'}
 (folder/'declarations.json').write_text(json.dumps(result,indent=2)+'\n')
 return result

def main():
 print('headers',len(HEADERS),flush=True);results=[]
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
  for index,result in enumerate(pool.map(work,HEADERS),1):
   results.append(result)
   if index%10==0 or result['clang_exit_code']:print(index,Path(result['path']).name,result['clang_exit_code'],len(result['declarations']),flush=True)
 inventory={'schema':1,'kind':'compiler-derived-official-public-api-inventory','scope':'Header declarations and macros under the actual configured native Darwin reference build, not proof of feature completeness.',
            'source':str(SOURCE),'build':str(BUILD),'baseline_revision':subprocess.check_output(['git','-C',str(SOURCE),'rev-parse','HEAD'],text=True).strip(),
            'compiler_version':subprocess.check_output([ARGS[0],'--version'],text=True),'compile_command_template':ROW,
            'source_install_manifest_sha256':digest((BUILD/'meson-info/intro-install_plan.json').read_bytes()),
            'configured_header_count':len(results),'headers':results,
            'meson_targets':[{'name':x['name'],'type':x['type'],'defined_in':x['defined_in'],'filenames':x['filename'],'installed':x['installed'],
                             'sources':[str(Path(v).relative_to(SOURCE)) if Path(v).is_relative_to(SOURCE) else v for s in x['target_sources'] for v in s.get('sources',[])]} for x in TARGETS]}
 funcs=[d for h in results for d in h['declarations'] if d['kind']=='FunctionDecl']
 inventory['summary']={'headers_successful':sum(h['clang_exit_code']==h['preprocess_exit_code']==0 for h in results),
                       'headers_failed':sum(h['clang_exit_code']!=0 or h['preprocess_exit_code']!=0 for h in results),
                       'function_declarations':len(funcs),'unique_function_names':len({f['name'] for f in funcs}),
                       'callbacks':sum(d['kind']=='TypedefDecl' and d.get('callback',False) for h in results for d in h['declarations']),
                       'macros':sum(len(h['macros']) for h in results),'deprecated_functions':sum('DeprecatedAttr' in f['attributes'] or any(t.get('name')=='deprecated' for t in f['documentation_tags']) for f in funcs)}
 (OUT/'configured-api-inventory.json').write_text(json.dumps(inventory,indent=2)+'\n');print(json.dumps(inventory['summary']),flush=True)
if __name__=='__main__':main()
