#!/usr/bin/env python3
"""Pure guard negative controls; never stands in for runtime C/R actors."""
import json,pathlib,tempfile,unittest,subprocess,sys
from common import disjoint,observed_tests,check_actor_result,sha,compile_source,rust_library,workspace_files,workspace_contract,normalized_metadata
class Controls(unittest.TestCase):
 def test_empty_expected_rejected(self):
  with self.assertRaises(ValueError):observed_tests('',set(),1)
 def test_empty_actual_rejected(self):
  with self.assertRaises(ValueError):observed_tests('',{'real'},1)
 def test_duplicate_actual_rejected(self):
  with self.assertRaises(ValueError):observed_tests('test real ... ok\ntest real ... ok',{'real'},1)
 def test_ignored_actual_rejected(self):
  with self.assertRaises(ValueError):observed_tests('test real ... ignored',{'real'},1)
 def test_wrong_name_rejected(self):
  with self.assertRaises(ValueError):observed_tests('test other ... ok',{'real'},1)
 def test_empty_actor_rejected(self):
  with self.assertRaises(ValueError):check_actor_result({'status':'passed','inputs_unchanged':True,'paired_profiles':1,'cases':[]},1,2)
 def test_valid_json_nonzero_actor_rejected(self):
  row={'status':'passed','inputs_unchanged':True,'paired_profiles':1,'cases':[{'trace':['END'],'exit_code':0},{'trace':['END'],'exit_code':7}]}
  with self.assertRaises(ValueError):check_actor_result(row,1,2)
 def test_source_overlap_rejected(self):
  with self.assertRaises(ValueError):disjoint('/private/tmp/source/out','/private/tmp/source')
 def test_source_bytes_mutation_changes_digest(self):
  with tempfile.TemporaryDirectory(prefix='broker-guard-')as d:
   p=pathlib.Path(d)/'a';p.write_bytes(b'a');before=sha(p);p.write_bytes(b'b');self.assertNotEqual(before,sha(p))
 def test_compile_source_in_different_clone_rejected(self):
  with self.assertRaises(ValueError):compile_source({'file':'/private/tmp/old/src/lib/util/resolver_api.c'},'/private/tmp/build','/private/tmp/clean-clone')
 def test_compile_source_relative_cwd_is_bound(self):
  self.assertEqual(compile_source({'file':'../source/src/lib/util/resolver_api.c'},'/private/tmp/build','/private/tmp/source'),pathlib.Path('/private/tmp/source/src/lib/util/resolver_api.c'))
 def test_missing_library_artifact_rejected(self):
  with self.assertRaises(ValueError):rust_library('', 'gnunet_resolver_broker')
 def test_duplicate_library_artifact_rejected(self):
  row=json.dumps({'reason':'compiler-artifact','target':{'name':'gnunet_resolver_broker','kind':['lib']},'filenames':['/private/tmp/one.rlib']})
  with self.assertRaises(ValueError):rust_library(row+'\n'+row,'gnunet_resolver_broker')
 def test_actual_library_artifact_selected_without_glob(self):
  row=json.dumps({'reason':'compiler-artifact','target':{'name':'gnunet_resolver_broker','kind':['lib']},'filenames':['/private/tmp/one.rlib','/private/tmp/one.rmeta']})
  self.assertEqual(rust_library(row,'gnunet_resolver_broker'),pathlib.Path('/private/tmp/one.rlib'))
 def test_named_nonempty_positive(self):
  self.assertEqual(observed_tests('test a::real ... ok\n',{'real'},1),['real'])
 def test_optimized_actual_decoder_rejects_malformed_header(self):
  code="import struct;from paired import decode;decode(struct.pack('!HHII',16,999,0,2)+b'abcd')"
  child=subprocess.run([sys.executable,'-O','-B','-c',code],cwd=pathlib.Path(__file__).resolve().parent,capture_output=True,timeout=5)
  self.assertNotEqual(child.returncode,0,'actual optimized decoder accepted the malformed official header')
  self.assertIn(b'ValueError',child.stderr)
 def test_foreign_local_cargo_identity_rejected(self):
  value={'workspace_root':'/private/tmp/owned-workspace','packages':[{'id':'x','name':'x','version':'1','source':None,'manifest_path':'/private/tmp/foreign/Cargo.toml'}]}
  with self.assertRaisesRegex(ValueError,'foreign local Cargo'):normalized_metadata(value,'/private/tmp/owned-workspace')
 def test_duplicate_local_cargo_identity_rejected(self):
  root=pathlib.Path('/private/tmp/owned-workspace')
  value={'workspace_root':str(root),'packages':[{'id':name,'name':'duplicate','version':'1','source':None,'manifest_path':str(root/name/'Cargo.toml')}for name in ['a','b']]}
  with self.assertRaisesRegex(ValueError,'duplicate local Cargo'):normalized_metadata(value,root)
 def test_workspace_addition_and_deletion_change_file_set(self):
  with tempfile.TemporaryDirectory(prefix='broker-workspace-')as d:
   root=pathlib.Path(d);(root/'a.rs').write_text('a');before=workspace_files(root);(root/'b.rs').write_text('a');self.assertNotEqual(before,workspace_files(root));(root/'a.rs').unlink();self.assertNotEqual(before,workspace_files(root))
   (root/'empty').mkdir();(root/'linked').symlink_to(root/'empty',target_is_directory=True)
   with self.assertRaisesRegex(ValueError,'directory symlink'):workspace_files(root)
 def test_actual_second_lock_is_required(self):
  with tempfile.TemporaryDirectory(prefix='broker-locks-')as d:
   root=pathlib.Path(d)
   for name in ['Cargo.toml','Cargo.lock','rust-toolchain.toml','rustfmt.toml','.cargo/config.toml','tests/embedded/noalloc/Cargo.toml']:
    p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('present')
   with self.assertRaisesRegex(ValueError,'two-lock'):workspace_contract(root)
 def test_foreign_actual_library_manifest_rejected(self):
  row=json.dumps({'reason':'compiler-artifact','target':{'name':'gnunet_resolver_broker','kind':['lib']},'filenames':['/private/tmp/one.rlib'],'manifest_path':'/private/tmp/foreign/Cargo.toml','package_id':'wanted'})
  with self.assertRaisesRegex(ValueError,'foreign actual library manifest'):rust_library(row,'gnunet_resolver_broker','/private/tmp/wanted/Cargo.toml','wanted')
 def test_foreign_actual_library_package_id_rejected(self):
  row=json.dumps({'reason':'compiler-artifact','target':{'name':'gnunet_resolver_broker','kind':['lib']},'filenames':['/private/tmp/one.rlib'],'manifest_path':'/private/tmp/wanted/Cargo.toml','package_id':'foreign'})
  with self.assertRaisesRegex(ValueError,'foreign actual library package id'):rust_library(row,'gnunet_resolver_broker','/private/tmp/wanted/Cargo.toml','wanted')
if __name__=='__main__':unittest.main(verbosity=2)
