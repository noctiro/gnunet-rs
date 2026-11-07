#!/usr/bin/env python3
"""Finite source-discovery negative controls; no compiler/C/native operation."""
import tempfile,unittest
from pathlib import Path
from _common import source_files,sha,validated_build,require_disjoint_output
from validation import validate_inventory,cargo_artifacts,configuration_locale_cases,validate_configuration_locale
import copy,json
from inventory import FILES,HEADERS,inventory
class Controls(unittest.TestCase):
 def test_directory_symlink_is_not_silently_dropped(self):
  with tempfile.TemporaryDirectory(prefix='program-walk-')as temp:
   root=Path(temp);(root/'real').mkdir();(root/'real/data').write_bytes(b'input');(root/'alias').symlink_to(root/'real',target_is_directory=True)
   with self.assertRaisesRegex(ValueError,'symbolic input'):source_files(root)
 def test_file_and_dangling_symlinks_are_rejected(self):
  for dangling in [False,True]:
   with tempfile.TemporaryDirectory(prefix='program-walk-')as temp:
    root=Path(temp)
    if not dangling:(root/'real').write_bytes(b'input')
    (root/'alias').symlink_to(root/'real')
    with self.assertRaisesRegex(ValueError,'symbolic input'):source_files(root)
 def test_new_file_and_existing_byte_changes_are_observed(self):
  with tempfile.TemporaryDirectory(prefix='program-walk-')as temp:
   root=Path(temp);file=root/'original';file.write_bytes(b'one');before={p.relative_to(root).as_posix():sha(p)for p in source_files(root)};file.write_bytes(b'two');after={p.relative_to(root).as_posix():sha(p)for p in source_files(root)};self.assertNotEqual(before,after);(root/'new').write_bytes(b'new');self.assertEqual(len(source_files(root)),2)
 def test_output_exclusion_does_not_hide_nested_source_target_directory(self):
  with tempfile.TemporaryDirectory(prefix='program-walk-')as temp:
   root=Path(temp);(root/'target').mkdir();(root/'target/output').write_bytes(b'generated');(root/'src/target').mkdir(parents=True);(root/'src/target/input').write_bytes(b'input');self.assertEqual([p.relative_to(root).as_posix()for p in source_files(root,{'target'})],['src/target/input'])
class ProofControls(unittest.TestCase):
 def test_overlap_rejected_in_both_directions(self):
  with tempfile.TemporaryDirectory(prefix='program-proof-')as temp:
   root=Path(temp);(root/'input').mkdir()
   for output,protected in [(root/'input/out',[root/'input']),(root,[root/'input'])]:
    with self.assertRaisesRegex(ValueError,'overlaps protected'):require_disjoint_output(output,protected)
 def test_failure_empty_input_and_changed_binary_or_source_cannot_validate(self):
  with tempfile.TemporaryDirectory(prefix='program-proof-')as temp:
   root=Path(temp);source=root/'input';binary=root/'actor';source.write_bytes(b'one');binary.write_bytes(b'actor');receipt=root/'receipt.json'
   baseline={'exit_code':0,'inputs_unchanged':True,'inputs':{str(source):sha(source)},'binary':{'path':str(binary),'sha256':sha(binary)}}
   receipt.write_text(json.dumps(baseline));self.assertEqual(validated_build(receipt),baseline)
   for mutation in ['source','binary','empty','exit','flag']:
    source.write_bytes(b'one');binary.write_bytes(b'actor');value=copy.deepcopy(baseline)
    if mutation=='source':source.write_bytes(b'two')
    elif mutation=='binary':binary.write_bytes(b'changed')
    elif mutation=='empty':value['inputs']={}
    elif mutation=='exit':value['exit_code']=1
    else:value['inputs_unchanged']=False
    receipt.write_text(json.dumps(value))
    with self.assertRaises(ValueError):validated_build(receipt)
 def test_cargo_selection_uses_actual_package_kind_and_unique_artifact(self):
  base={'reason':'compiler-artifact','package_id':'wanted','target':{'name':'owned','kind':['bin']},'executable':'/owned/actor'}
  self.assertEqual(cargo_artifacts(json.dumps(base).encode(),'wanted','bin'),{'owned':Path('/owned/actor')})
  for key,value in [('package_id','other'),('reason','build-script-executed'),('target',{'name':'owned','kind':['example']})]:
   other=copy.deepcopy(base);other[key]=value;self.assertEqual(cargo_artifacts(json.dumps(other).encode(),'wanted','bin'),{})
  wrong=copy.deepcopy(base);wrong['executable']='/owned/other'
  with self.assertRaisesRegex(ValueError,'ambiguous'):cargo_artifacts((json.dumps(base)+'\n'+json.dumps(wrong)).encode(),'wanted','bin')
 def test_required_inventory_cannot_be_reduced_or_only_status_approved(self):
  package=Path(__file__).resolve().parents[1]
  sample=json.loads((package/'inventory.json').read_text())['definitions'][0]
  # Synthetic inputs exercise validation without requiring a developer's C
  # checkout. Real source identity remains the reference runner's obligation.
  with tempfile.TemporaryDirectory(prefix='program-inventory-')as temp:
   source=Path(temp)
   for index,name in enumerate(FILES+HEADERS):
    path=source/name;path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(f'int\nGNUNET_fixture_{index} (void)\n{{ return {index}; }}\n')
   document=inventory(source)
   from validation import REQUIRED_SCOPE,REQUIRED_IDS
   document['full_required_scope']=list(REQUIRED_SCOPE)
   document['requirements']=[{'id':key,'required':True,'scope':scope}for key,scope in zip(REQUIRED_IDS,REQUIRED_SCOPE)]
   for row in document['definitions']:
    row.update(implementation='in_progress',rust_equivalence=copy.deepcopy(sample['rust_equivalence']),evidence=['synthetic validator control'])
   self.assertEqual(validate_inventory(document,source,package)['definition_count'],len(FILES))
   for mode in ['drop-definition','replace-definition','required','scope','mapping','status-only']:
    broken=copy.deepcopy(document)
    if mode=='drop-definition':broken['definitions'].pop()
    elif mode=='replace-definition':broken['definitions'][0]['name']='not-official'
    elif mode=='required':broken['requirements'][0]['required']=False
    elif mode=='scope':broken['full_required_scope'].pop()
    elif mode=='mapping':broken['definitions'][0]['rust_equivalence'][0]['symbol']='not_implemented'
    else:broken['definitions'][0]['implementation']='implemented';broken['definitions'][0]['rust_equivalence']=[]
    with self.assertRaises(ValueError):validate_inventory(broken,source,package)

class LocaleControls(unittest.TestCase):
 def fixture(self):
  rows = [{'index': index, 'mode': mode, 'locale': locale, 'input': list(values),
           'equal': True, 'actors': [{'actor': actor, 'returncode': 0,
           'stdout_hex': '6f6b0a', 'stderr_hex': ''} for actor in ['c', 'rust']]}
          for index, (mode, locale, values) in enumerate(configuration_locale_cases())]
  return {'status': 'passed', 'inputs_unchanged': True,
          'C_undefined_input_executed': False, 'profiles': len(rows), 'rows': rows}
 def test_locale_required_identities_cannot_be_deleted_duplicated_or_replaced(self):
  document = self.fixture()
  self.assertEqual(validate_configuration_locale(document)['required_case_count'], 134)
  for mode in ['drop', 'duplicate', 'locale', 'input', 'index', 'status-only']:
   value = copy.deepcopy(document)
   if mode == 'drop': value['rows'].pop()
   elif mode == 'duplicate': value['rows'][1] = copy.deepcopy(value['rows'][0])
   elif mode == 'locale': value['rows'][0]['locale'] = 'other'
   elif mode == 'input': value['rows'][12]['input'] = ['not-the-required-input']
   elif mode == 'index': value['rows'][0]['index'] = 99
   else: value['rows'] = []
   with self.assertRaises(ValueError): validate_configuration_locale(value)
 def test_locale_actual_output_and_success_are_not_inferred_from_equal_flags(self):
  document = self.fixture()
  for mode in ['output', 'error', 'exit', 'missing', 'empty', 'invalidhex', 'unchanged']:
   value = copy.deepcopy(document); actor = value['rows'][0]['actors'][1]
   if mode == 'output': actor['stdout_hex'] = '6e6f0a'
   elif mode == 'error': actor['stderr_hex'] = '78'
   elif mode == 'exit': actor['returncode'] = 1
   elif mode == 'missing': value['rows'][0]['actors'].pop()
   elif mode == 'empty': actor['stdout_hex'] = ''
   elif mode == 'invalidhex': actor['stdout_hex'] = 'xyz'
   else: value['inputs_unchanged'] = False
   with self.assertRaises(ValueError): validate_configuration_locale(value)
if __name__=='__main__':unittest.main()
