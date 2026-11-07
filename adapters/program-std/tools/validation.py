"""Source-derived inventory and actual artifact checks; no status grants proof."""
import json,re
from pathlib import Path
from inventory import inventory
from _common import sha
REQUIRED_SCOPE=[
 'whole PROGRAM + DAEMON/monolith operations',
 'whole GETOPT parser + every helper factory/macro',
 'whole common_logging implementation incl bulk/custom/scope/hash/address/hex',
 'locale/domain/catalog integration',
 'logical clock + actual scheduler/driver speedup bridge',
 'explicit early process-global installation/stdio authority',
]
REQUIRED_IDS=['PROGRAM','GETOPT','LOGGING','NLS','CLOCK','NATIVE']
def validate_inventory(document,source,package):
 actual=inventory(Path(source));rows=document.get('definitions',[])
 fields=['file','name','line','definition_sha256','public_name']
 canonical=lambda records:[{key:row[key]for key in fields}for row in records]
 if canonical(rows)!=canonical(actual['definitions']):raise ValueError('fixed source definitions changed/missing/reordered')
 if document.get('revision')!=actual['revision']or document.get('definition_count')!=actual['definition_count']or document.get('public_definition_count')!=actual['public_definition_count']:raise ValueError('source inventory counts/profile differ')
 if document.get('full_required_scope')!=REQUIRED_SCOPE or document.get('requirements')!=[{'id':key,'required':True,'scope':scope}for key,scope in zip(REQUIRED_IDS,REQUIRED_SCOPE)]:raise ValueError('required ordinary PROGRAM scope weakened')
 if document.get('owner_complete')is not False:raise ValueError('component inventory cannot claim complete owner')
 for name,digest in actual['source_inputs'].items():
  if document.get('source_inputs',{}).get(name)!=digest:raise ValueError('source/header identity differs '+name)
 for name,digest in document.get('source_inputs',{}).items():
  if sha(Path(source)/name)!=digest:raise ValueError('source closure hash differs '+name)
 for row in rows:
  if row.get('implementation')not in ['in_progress','implemented']:raise ValueError('unmapped source operation '+row['name'])
  mappings=row.get('rust_equivalence')
  if not mappings or not row.get('evidence'):raise ValueError('source operation lacks actual Rust/evidence mapping '+row['name'])
  for mapping in mappings:
   path=Path(package)/mapping['path'];symbol=mapping['symbol'].rsplit('::',1)[-1]
   if not path.is_file()or not re.search(r'\bfn\s+'+re.escape(symbol)+r'\b',path.read_text())or not mapping.get('ownership_and_errors'):raise ValueError('mapped Rust source symbol absent '+row['name'])
 return {'definition_count':len(rows),'public_name_count':sum(v['public_name']for v in rows),'required_scope_ids':REQUIRED_IDS,'status_does_not_grant_owner_completion':True}
def cargo_artifacts(data,package,kind):
 result={}
 for raw in data.splitlines():
  try:row=json.loads(raw)
  except ValueError:continue
  if row.get('reason')!='compiler-artifact'or row.get('package_id')!=package or row.get('target',{}).get('kind')!=[kind]:continue
  name=row['target']['name'];paths=[Path(row['executable'])]if kind in ['bin','example']and row.get('executable')else[Path(v)for v in row.get('filenames',[])if v.endswith('.rlib')]
  if len(paths)!=1 or name in result and result[name]!=paths[0]:raise ValueError('actual Cargo artifact missing/ambiguous '+name)
  result[name]=paths[0]
 return result


LOCALE_PROFILES = ['C', 'en_US.UTF-8', 'en_US.ISO8859-1', 'tr_TR.ISO8859-9',
                   'tr_TR.UTF-8', 'de_DE.ISO8859-1']

def configuration_locale_cases():
 """Exact required finite case identities, independent of reported totals/status."""
 cases = [(mode, locale, ()) for locale in LOCALE_PROFILES
          for mode in ['switch', 'choice-paths']]
 numeric = ['C', 'en_US.ISO8859-1', 'de_DE.ISO8859-1']
 values = ['0', '-0', '1.25', '\v1.25', '0x1.8p+1', 'INF', 'NaN',
           'nan(payload)', '1e', '0x', '+', '.', ' ', '12x', '1.25 e', '1,25']
 cases += [('float', locale, (value,)) for locale in numeric for value in values]
 cases += [('float-reset', locale, (value,)) for locale in numeric
           for value in ['1.25', '1,25', '+', 'nan(payload)']]
 cases += [(mode, locale, ()) for locale in LOCALE_PROFILES
           for mode in ['byte-table', 'parse-number', 'thread-numeric']]
 cases += [('set-float', locale, (str(index),))
           for locale in ['C', 'de_DE.ISO8859-1'] for index in range(10)]
 cases += [(mode, locale, ('owned-include*.conf' if mode == 'include-matching'
                           else 'owned-include.conf',))
           for locale in LOCALE_PROFILES
           for mode in ['include', 'include-secret', 'include-matching']]
 cases += [('dollar', locale, ()) for locale in LOCALE_PROFILES]
 return cases

def validate_configuration_locale(document):
 """Check every actual C/R observation, not just successful labels or 134 rows."""
 expected = configuration_locale_cases()
 rows = document.get('rows')
 if (document.get('status') != 'passed' or document.get('inputs_unchanged') is not True
     or document.get('C_undefined_input_executed') is not False
     or document.get('profiles') != len(expected) or not isinstance(rows, list)
     or len(rows) != len(expected)):
  raise ValueError('finite locale acceptance/observations missing')
 for index, (row, identity) in enumerate(zip(rows, expected)):
  values = row.get('input')
  if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
   raise ValueError('finite locale inputs are malformed')
  if str(row.get('mode', '')).startswith('include'):
   values = [Path(value).name for value in values]
  if (row.get('index') != index
      or (row.get('mode'), row.get('locale'), tuple(values)) != identity
      or row.get('equal') is not True):
   raise ValueError('required finite locale case omitted/replaced/reordered')
  actors = row.get('actors')
  if not isinstance(actors, list) or [v.get('actor') for v in actors] != ['c', 'rust']:
   raise ValueError('actual independent C/R observations absent')
  output = []
  for actor in actors:
   value = actor.get('stdout_hex')
   if (actor.get('returncode') != 0 or actor.get('stderr_hex') != ''
       or not isinstance(value, str) or not value
       or re.fullmatch(r'(?:[0-9a-f]{2})+', value) is None):
    raise ValueError('actual locale participant did not produce valid finite output')
   output.append(bytes.fromhex(value))
  if output[0] != output[1]:
   raise ValueError('locale output differs despite equal/status label')
 return {'required_case_count': len(expected), 'actual_observations': 2 * len(rows)}
