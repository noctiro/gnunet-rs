"""Exact finite negative controls for the maintenance-tool boundaries."""
import ast,json,os,pathlib,subprocess,sys,tempfile,unittest
from common import checked_rows,disjoint,sha,successful,PLUGINS
class Boundaries(unittest.TestCase):
 def test_output_same_as_input_rejected(self):
  with self.assertRaises(ValueError):disjoint('/tmp/block', ['/tmp/block'])
 def test_output_descendant_of_input_rejected(self):
  with self.assertRaises(ValueError):disjoint('/tmp/block/result', ['/tmp/block'])
 def test_output_ancestor_of_input_rejected(self):
  with self.assertRaises(ValueError):disjoint('/tmp', ['/tmp/block'])
 def test_sibling_output_accepted(self):disjoint('/tmp/actual-block-output',['/tmp/block-source'])
 def test_empty_binding_rejected(self):
  with self.assertRaises(ValueError):checked_rows([])
 def test_duplicate_binding_rejected(self):
  with tempfile.TemporaryDirectory()as d:
   p=pathlib.Path(d)/'x';p.write_bytes(b'real');row={'path':str(p),'sha256':sha(p)}
   with self.assertRaises(ValueError):checked_rows([row,row])
 def test_changed_bytes_rejected(self):
  with tempfile.TemporaryDirectory()as d:
   p=pathlib.Path(d)/'x';p.write_bytes(b'real');row={'path':str(p),'sha256':sha(p)};p.write_bytes(b'changed')
   with self.assertRaises(ValueError):checked_rows([row])
 def test_deleted_file_rejected(self):
  with tempfile.TemporaryDirectory()as d:
   p=pathlib.Path(d)/'x';p.write_bytes(b'real');row={'path':str(p),'sha256':sha(p)};p.unlink()
   with self.assertRaises(FileNotFoundError):checked_rows([row])
 def test_real_file_bound_accepted(self):
  with tempfile.TemporaryDirectory()as d:
   p=pathlib.Path(d)/'x';p.write_bytes(b'real');checked_rows([{'path':str(p),'sha256':sha(p)}])
 def test_legal_output_then_exit7_rejected(self):
  process=subprocess.run([sys.executable,'-B','-c','import sys; print("valid trace");sys.exit(7)'],capture_output=True);self.assertEqual(process.stdout,b'valid trace\n')
  with self.assertRaises(ValueError):successful(process,'negative child')
 def test_actual_normal_exit_required(self):successful(subprocess.run([sys.executable,'-B','-c','pass'],capture_output=True),'positive child')
 def test_complete_core_corpus_cannot_be_empty_or_filtered(self):
  from compare import corpus
  rows=corpus();self.assertEqual(len(rows),867);self.assertEqual(len({x['label']for x in rows}),867);self.assertEqual(len(PLUGINS),9);self.assertIn('negative-merge-consumes-second',{x['label']for x in rows});self.assertEqual(sum(x['label'].startswith('pow-')for x in rows),12)
 def test_optimized_missing_trace_child_rejected(self):
  env=os.environ.copy();env['PYTHONOPTIMIZE']='1'
  code='from common import trace_differences; trace_differences([{"label":"real-case","line":"N"}],[],["actual trace"]); print("FALSE PASS")'
  child=subprocess.run([sys.executable,'-B','-c',code],cwd=pathlib.Path(__file__).resolve().parent,env=env,capture_output=True)
  self.assertNotEqual(child.returncode,0);self.assertEqual(child.stdout,b'');self.assertIn(b'actual trace count differs',child.stderr)
 def test_no_verification_asserts_can_be_disabled(self):
  paths=sorted(pathlib.Path(__file__).resolve().parent.glob('*.py'));self.assertEqual({p.name for p in paths},{'build_normal.py','build_probe.py','common.py','compare.py','signed_compare.py','test_tools.py','verify.py','workspace_bridge.py'})
  for path in paths:self.assertEqual([node.lineno for node in ast.walk(ast.parse(path.read_text()))if isinstance(node,ast.Assert)],[],str(path))
 def test_virtual_workspace_member_identity_is_required(self):
  from workspace_bridge import member
  with tempfile.TemporaryDirectory()as directory:
   package=pathlib.Path(directory)/'crates/gnunet-block';path=package/'Cargo.toml'
   actual={'id':'block-identity','name':'gnunet-block','source':None,'manifest_path':str(path)}
   meta={'packages':[actual],'workspace_members':['block-identity'],'resolve':{'root':None}}
   self.assertEqual(member(meta,package),actual)
   for changed in ({**meta,'workspace_members':[]},{**meta,'packages':[dict(actual,source='registry+https://example.invalid')]},{**meta,'packages':[dict(actual,manifest_path=str(package/'wrong.toml'))]}):
    with self.assertRaises(ValueError):member(changed,package)
 def test_actual_fixture_graph_rejects_member_union(self):
  from workspace_bridge import fixture_root
  actual={'id':'fixture','name':'gnunet-noalloc-check','manifest_path':'/private/tmp/repo/tests/embedded/noalloc/Cargo.toml'}
  meta={'packages':[actual],'resolve':{'root':'fixture'}};self.assertEqual(fixture_root(meta),'fixture')
  for changed in ({**meta,'resolve':{'root':None}},{**meta,'packages':[dict(actual,name='gnunet-block')]},{**meta,'packages':[dict(actual,manifest_path='/private/tmp/crates/gnunet-block/Cargo.toml')]}):
   with self.assertRaises(ValueError):fixture_root(changed)
 def test_workspace_file_addition_and_deletion_rejected(self):
  from workspace_bridge import helper
  shared=helper()
  with tempfile.TemporaryDirectory()as directory:
   root=pathlib.Path(directory);(root/'Cargo.toml').write_text('[workspace]');original=shared.tree(root)
   (root/'new.rs').write_text('pub fn added() {}')
   with self.assertRaises(ValueError):shared.same(shared.tree(root),original,'new file')
   (root/'new.rs').unlink();shared.same(shared.tree(root),original,'positive restore')
   (root/'Cargo.toml').unlink();(root/'other.rs').write_text('// keep nonempty tree')
   with self.assertRaises(ValueError):shared.same(shared.tree(root),original,'deleted file')
 def builder_fixture(self,directory):
  from common import BUILDER_ROLES
  base=pathlib.Path(directory);actual=base/'actual';reviewed=base/'reviewed';actual.mkdir();reviewed.mkdir();rows=[];current={}
  for role in sorted(BUILDER_ROLES):
   source=actual/(role+'.py');target=reviewed/(role+'.py');source.write_text('# exact '+role+' source\n');target.write_bytes(source.read_bytes());rows.append({'role':role,'path':str(source.resolve()),'sha256':sha(source)});current[role]=target
  return rows,current
 def test_builder_input_roles_are_complete_and_unique(self):
  from common import checked_builder_inputs
  with tempfile.TemporaryDirectory()as directory:
   rows,current=self.builder_fixture(directory);bindings=checked_builder_inputs(rows,current)
   self.assertEqual(set(bindings),{'builder','common','reference-helper'})
   self.assertTrue(all(row['actual_path']!=row['reviewed_path']and row['actual_path_preserved']for row in bindings.values()))
   for invalid in(None,[],rows[:-1],[*rows,rows[0]],[rows[0],rows[0],rows[2]],[dict(rows[0],path=rows[1]['path']),*rows[1:]]):
    with self.assertRaises(ValueError):checked_builder_inputs(invalid,current)
 def test_changed_actual_builder_helper_is_rejected_even_optimized(self):
  from common import checked_builder_inputs
  with tempfile.TemporaryDirectory()as directory:
   rows,current=self.builder_fixture(directory);checked_builder_inputs(rows,current)
   target=next(row for row in rows if row['role']=='reference-helper');pathlib.Path(target['path']).write_text('# changed actual helper\n')
   with self.assertRaises(ValueError):checked_builder_inputs(rows,current)
   env=os.environ.copy();env['PYTHONOPTIMIZE']='1'
   code='from common import checked_builder_inputs; import json; checked_builder_inputs(json.loads('+repr(json.dumps(rows))+'),json.loads('+repr(json.dumps({k:str(v)for k,v in current.items()}))+')); print("FALSE PASS")'
   child=subprocess.run([sys.executable,'-B','-c',code],cwd=pathlib.Path(__file__).resolve().parent,env=env,capture_output=True)
   self.assertNotEqual(child.returncode,0);self.assertEqual(child.stdout,b'');self.assertIn(b'actual builder input source changed',child.stderr)
if __name__=='__main__':unittest.main(verbosity=2)


