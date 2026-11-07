#!/usr/bin/env python3
"""Correlate compiler-derived public API and configured native source operations."""
import argparse,concurrent.futures,gzip,hashlib,json,re,shlex,subprocess,time,platform
from pathlib import Path
PARSER=argparse.ArgumentParser(description=__doc__)
PARSER.add_argument('--capture',type=Path,required=True)
PARSER.add_argument('--source',type=Path,required=True)
PARSER.add_argument('--build',type=Path,required=True)
PARSER.add_argument('--prefix',type=Path,help='optional actual built reference library prefix for exported-symbol correlation')
OPTIONS=PARSER.parse_args()
ROOT=Path(__file__).resolve().parents[2]
SOURCE=OPTIONS.source.resolve()
BUILD=OPTIONS.build.resolve()
OUT=OPTIONS.capture.resolve()
PREFIX=OPTIONS.prefix.resolve() if OPTIONS.prefix else None
CAT=json.loads((OUT/'configured-api-inventory.json').read_text())
LEDGER=json.loads((ROOT/'spec/gnunet/conformance.json').read_text())
TARGETS=json.loads((BUILD/'meson-info/intro-targets.json').read_text())
COMMANDS=json.loads((BUILD/'compile_commands.json').read_text())
MAPPING={
'statistics':['gnunet_statistics_service.h'],
'arm':['gnunet_arm_service.h','gnunet_testing_arm_lib.h'],
'peerstore':['gnunet_peerstore_service.h','gnunet_peerstore_plugin.h'],
'nat':['gnunet_nat_service.h','gnunet_nat_lib.h'],
'nat-auto':['gnunet_nat_auto_service.h'],
'pils':['gnunet_pils_service.h'],
'transport':['gnunet_transport_application_service.h','gnunet_transport_communication_service.h','gnunet_transport_core_service.h','gnunet_transport_monitor_service.h','gnunet_testing_transport_lib.h'],
'core':['gnunet_core_service.h','gnunet_testing_core_lib.h'],
'nse':['gnunet_nse_service.h'],
'dns':['gnunet_dns_service.h','gnunet_dnsparser_lib.h','gnunet_dnsstub_lib.h'],
'identity':['gnunet_identity_service.h'],
'namecache':['gnunet_namecache_service.h','gnunet_namecache_plugin.h'],
'namestore':['gnunet_namestore_service.h','gnunet_namestore_plugin.h'],
'datacache':['gnunet_datacache_lib.h','gnunet_datacache_plugin.h'],
'datastore':['gnunet_datastore_service.h','gnunet_datastore_plugin.h'],
'dht':['gnunet_dht_service.h','gnunet_dhtu_plugin.h','gnunet_dht_block_types.h'],
'cadet':['gnunet_cadet_service.h'],
'seti':['gnunet_seti_service.h'],
'setu':['gnunet_setu_service.h'],
'regex':['gnunet_regex_service.h'],
'revocation':['gnunet_revocation_service.h'],
'vpn':['gnunet_vpn_service.h'],
'gns':['gnunet_gns_service.h','gnunet_gnsrecord_lib.h','gnunet_gnsrecord_json_lib.h','gnunet_gnsrecord_plugin.h','gnu_name_system_protocols.h','gnu_name_system_record_types.h','gnu_name_system_service_ports.h'],
'fs':['gnunet_fs_service.h'],
'reclaim':['gnunet_reclaim_service.h','gnunet_reclaim_lib.h','gnunet_reclaim_plugin.h'],
'messenger':['gnunet_messenger_service.h'],
'rest':['gnunet_rest_lib.h','gnunet_rest_plugin.h'],
}
MAPPING['testbed']=[Path(h['path']).name for h in CAT['headers'] if Path(h['path']).name.startswith('gnunet_testing_')]
NO_API={
'hostlist':'HTTP hostlist discovery/publication and HELLO handling are daemon/configuration/network operations; no dedicated installed client header is declared.',
' topology':'Topology/friend/connectivity policy is a daemon operation, not a dedicated public client handle.',
'zonemaster':'Zone publication maintenance uses NAMESTORE/DHT and configuration; no dedicated installed client header.',
'exit':'IP exit forwarding and DNS/helpers use CADET/TUN and configured network behavior; no dedicated public client header.',
'pt':'Protocol translation/helper/daemon behavior uses VPN/DNS/TUN; no dedicated installed client header.',
}
NO_API['topology']=NO_API.pop(' topology')
SHARED={
'gnunet_crypto_lib.h':['crypto'],'gnunet_hello_uri_lib.h':['hello'],
'gnunet_gnsrecord_lib.h':['gnsrecord'],'gnunet_gnsrecord_json_lib.h':['gnsrecord'],'gnunet_gnsrecord_plugin.h':['gnsrecord'],
'gnunet_block_lib.h':['block'],'gnunet_block_group_lib.h':['block'],'gnunet_block_plugin.h':['block'],
'gnunet_common.h':['wire'],'gnunet_protocols.h':['wire'],'gnunet_signatures.h':['crypto','wire'],
'gnunet_time_lib.h':['wire'],'gnunet_configuration_lib.h':['service-runtime'],
'gnunet_client_lib.h':['service-runtime'],'gnunet_service_lib.h':['service-runtime'],'gnunet_mq_lib.h':['service-runtime'],
'gnunet_mst_lib.h':['service-runtime'],'gnunet_scheduler_lib.h':['service-runtime'],'gnunet_disk_lib.h':['storage-contracts'],
'gnunet_bio_lib.h':['storage-contracts'],
}
HISTORICAL=['gnunet_abd_service.h','gnunet_consensus_service.h','gnunet_conversation_service.h','gnunet_rps_service.h','gnunet_scalarproduct_service.h','gnunet_secretsharing_service.h','gnunet_set_service.h']
known={n for names in MAPPING.values() for n in names}
MAPPING['util']=[Path(h['path']).name for h in CAT['headers'] if Path(h['path']).name not in known and Path(h['path']).name not in HISTORICAL]
if 'gnunet_resolver_service.h' not in MAPPING['util']:MAPPING['util'].append('gnunet_resolver_service.h')
registry={}
for header in CAT['headers']:
 if Path(header['path']).name=='gnunet_protocols.h':
  for macro in header['macros']:
   if macro['name'].startswith('GNUNET_MESSAGE_TYPE_'):registry[macro['name']]=int(macro['definition'],0)
def sha(data):return hashlib.sha256(data).hexdigest()
def owner(path):
 try:p=Path(path).resolve().relative_to(SOURCE).parts
 except ValueError:return None
 if len(p)>3 and p[0]=='src' and p[1] in ('service','cli') and p[2] in {e['id'] for e in LEDGER['required_subsystems']}:return p[2]
 if len(p)>3 and p[:3]==('src','lib','util'):return 'util'
 return None
files={}
for target in TARGETS:
 if not target['installed']:continue
 for entry in target['target_sources']:
  for value in entry.get('sources',[]):
   own=owner(value)
   if own and Path(value).suffix=='.c':files.setdefault(str(Path(value).resolve()),{'owner':own,'targets':[]})['targets'].append(target['name'])
byfile={str((BUILD/r['file']).resolve()):r for r in COMMANDS}
(OUT/'translation-units').mkdir(exist_ok=True)
def preprocess(item):
 path,meta=item;row=byfile.get(path)
 if row is None:return {'path':str(Path(path).relative_to(SOURCE)),**meta,'status':'no-configured-compile-command','references':[]}
 args=shlex.split(row['command']);flags=[];i=1
 while i<len(args):
  if args[i] in ('-o','-MQ','-MF'):i+=2;continue
  if args[i] in ('-MD','-c') or args[i]==row['file'] or args[i].startswith('-fdiagnostics-color'):i+=1;continue
  flags.append(args[i]);i+=1
 command=[args[0],*flags,'-E','-fdirectives-only',row['file']]
 result=subprocess.run(command,cwd=BUILD,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
 name=str(Path(path).relative_to(SOURCE)).replace('/','__');folder=OUT/'translation-units'
 with gzip.open(folder/(name+'.c.gz'),'wb') as output:output.write(result.stdout)
 (folder/(name+'.stderr.txt')).write_bytes(result.stderr)
 active=None;line=0;references=[]
 for text in result.stdout.decode().splitlines():
  marker=re.match(r'#\s+(\d+)\s+"([^"]+)"',text)
  if marker:
   active=Path(marker[2]);active=(active if active.is_absolute() else BUILD/active).resolve();line=int(marker[1]);continue
  if active==Path(path):
   for number in re.findall(r'\bGNUNET_MESSAGE_TYPE_[A-Z0-9_]+\b',text):
    references.append({'name':number,'value':registry.get(number),'line':line,'context':'macro-definition' if text.lstrip().startswith('#') else 'active-source-token'})
  line+=1
 return {'path':str(Path(path).relative_to(SOURCE)),**meta,'status':'preprocessed' if result.returncode==0 else 'failed',
         'command':command,'directory':str(BUILD),'exit_code':result.returncode,'source_sha256':sha(Path(path).read_bytes()),
         'preprocessed_sha256':sha(result.stdout),'retained_output':'translation-units/'+name+'.c.gz',
         'diagnostics':result.stderr.decode(),'references':references}
def main():
 print('production translation units',len(files),flush=True)
 processed=[]
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
  for i,record in enumerate(pool.map(preprocess,sorted(files.items())),1):
   processed.append(record)
   if i%25==0 or record['status']!='preprocessed':print(i,record['path'],record['status'],len(record['references']),flush=True)
 surfaces=[]
 for header in CAT['headers']:
  name=Path(header['path']).name;owners=[key for key,value in MAPPING.items() if name in value]
  roles=['current-subsystem-public-surface'] if owners else []
  if name in HISTORICAL:roles.append('installed-historical-service-header-needs-reviewed-exclusion')
  if name in SHARED:roles.append('shared-foundation-surface')
  if not roles:roles.append('unmapped-needs-review')
  surfaces.append({'path':header['path'],'sha256':header['source_sha256'],'owners':owners,'foundation_owners':SHARED.get(name,[]),'roles':roles,
                   'native_ast_valid':header['clang_exit_code']==header['preprocess_exit_code']==0,
                   'functions':[d['name'] for d in header['declarations'] if d['kind']=='FunctionDecl'],
                   'callbacks':[d['name'] for d in header['declarations'] if d['kind']=='TypedefDecl' and d.get('callback')],
                   'declaration_kinds':sorted({d['kind'] for d in header['declarations']}),
                   'condition_branches':header['conditional_directives'],'declarations_file':'headers/'+name+'/declarations.json',
                   'review_status':'unreviewed','rust_equivalence':[],'behavior_cases':[]})
 entries=[]
 for subsystem in LEDGER['required_subsystems']:
  ident=subsystem['id'];headers=[h for h in surfaces if ident in h['owners']];units=[p for p in processed if p['owner']==ident]
  messages={}
  for unit in units:
   for reference in unit['references']:
    messages.setdefault(reference['name'],{'name':reference['name'],'number':reference['value'],'references':[]})['references'].append({'path':unit['path'],'line':reference['line'],'context':reference['context']})
  related=[]
  for target in TARGETS:
   if owner(target['defined_in'])!=ident:continue
   related.append({'name':target['name'],'kind':target['type'],'installed':target['installed'],'defined_in':str(Path(target['defined_in']).relative_to(SOURCE)),
                   'artifacts':[{'path':p,'built':Path(p).is_file(),'sha256':sha(Path(p).read_bytes()) if Path(p).is_file() else None} for p in target['filename']]})
  entries.append({'id':ident,'required':True,'scope_from_current_ledger':subsystem['scope'],'public_headers':[h['path'] for h in headers],
                  'function_names':sorted({n for h in headers for n in h['functions']}),'callback_names':sorted({n for h in headers for n in h['callbacks']}),
                  'direct_public_api_reason':NO_API.get(ident,'Mapped installed headers; symbols/callbacks still need per-operation Rust equivalence and behavioral review.'),
                  'meson_targets':related,'production_translation_units':[p['path'] for p in units],
                  'wire_message_candidates':sorted(messages.values(),key=lambda m:(m['number'] is None,m['number'] or 0,m['name'])),
                  'inventory_status':'needs-operation-and-profile-review','behavior_cases':[],'verified':False})
 exports=[]
 paths=sorted([path for pattern in ('libgnunet*.dylib','libgnunet*.so*') for path in (PREFIX/'lib').glob(pattern)]) if PREFIX else []
 for path in paths:
  if path.is_symlink():continue
  nm_command=['nm','-gU',str(path)] if platform.system()=='Darwin' else ['nm','-g','--defined-only',str(path)]
  output=subprocess.check_output(nm_command,text=True)
  (OUT/(path.name+'.nm.txt')).write_text(output)
  symbols=[]
  for text in output.splitlines():
   words=text.split()
   if words and words[-1].startswith(('_GNUNET_','GNUNET_')):symbols.append({'name':words[-1][1:] if words[-1].startswith('_') else words[-1],'nm_kind':words[-2]})
  exports.append({'path':str(path),'sha256':sha(path.read_bytes()),'command':nm_command,'symbols':symbols,
                  'header_declared':[s['name'] for s in symbols if any(s['name'] in h['functions'] or any(d['name']==s['name'] for d in raw['declarations']) for h,raw in zip(surfaces,CAT['headers']))],
                  'scope':'Actual built-library exports only; unavailable other libraries have no implied export evidence.'})
 report={'schema':1,'kind':'official-api-operation-inventory-design','baseline_revision':CAT['baseline_revision'],'configured_profile':'native Darwin; exact actual Meson compile definitions and installed header manifest',
         'compiler_inventory':'configured-api-inventory.json','all_34_subsystems_catalogued':len(entries)==34,'headers':surfaces,'subsystems':entries,
         'active_preprocessed_translation_units':processed,'actual_exported_libraries':exports,
         'limitations':['Only one native configured profile. Conditional branches/deprecated APIs need explicit review; inactive branches are not proven absent.',
                       'gnunet_pq_lib.h requires missing libpq-fe.h; recovered AST declarations there are candidates, not validated signatures.',
                       'Util-only headers use the documented umbrella types plus its __GNUNET_UTIL_LIB_H_INSIDE__ include marker for isolated compiler extraction; this does not prove standalone client inclusion is supported.',
                       'Message constants come from compiler-preprocessed active source tokens. They are operation candidates, not proof that send/handler/state transitions are complete.',
                       'Installed historical service headers remain explicit unresolved exclusions instead of silently joining or disappearing from current requirements.',
                       'No function count, symbol export or successful extraction awards a verified feature. Rust mapping and behavioral/interop evidence are separate required records.'],
         'summary':{'subsystems':len(entries),'headers':len(surfaces),'native_ast_valid_headers':sum(h['native_ast_valid'] for h in surfaces),'production_translation_units':len(processed),
                    'translation_units_preprocessed':sum(p['status']=='preprocessed' for p in processed),'translation_unit_failures':sum(p['status']!='preprocessed' for p in processed),
                    'required_services_without_dedicated_public_headers':[x['id'] for x in entries if not x['public_headers']],
                    'historical_headers':HISTORICAL,'actual_exported_libraries':len(exports),'all_functionality_verified':False}}
 (OUT/'api-operation-catalog.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report['summary']),flush=True)
if __name__=='__main__':main()
