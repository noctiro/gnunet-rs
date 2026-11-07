#!/usr/bin/env python3
"""Reject vacuous proof sets and accidental output/source overlap."""
import copy,json,tempfile,unittest
from pathlib import Path
from _common import require_disjoint_output
from checks import require_inventory,require_receipt,require_rust
BASE=Path(__file__).resolve().parents[1]
class Boundaries(unittest.TestCase):
 def test_actual_inventory(self):require_inventory(json.loads((BASE/'inventory.json').read_text()))
 def test_definition_removed(self):
  value=json.loads((BASE/'inventory.json').read_text());value['CLI_definitions'].pop()
  with self.assertRaises(ValueError):require_inventory(value)
 def test_flag_removed_even_if_count_claim_unchanged(self):
  value=json.loads((BASE/'inventory.json').read_text());value['CLI_specific_options'].pop()
  with self.assertRaises(ValueError):require_inventory(value)
 def test_difference_erasure(self):
  value=json.loads((BASE/'inventory.json').read_text());value['explicit_safe_differences']=[]
  with self.assertRaises(ValueError):require_inventory(value)
 def test_vacuous_status_is_not_evidence(self):
  for group in ['literal','argv','signals','stdio','normal-daemon','local-daemon','logs']:
   with self.subTest(group=group),self.assertRaises(ValueError):require_receipt(group,{'status':'passed'})
 def test_one_real_profile_cannot_be_claimed_as_full_set(self):
  with self.assertRaises(ValueError):require_receipt('signals',{'status':'passed','rows':[{'name':'SIGINT','matched':True,'c':{},'rust':{}}]})
 def test_empty_rust_count_cannot_pass(self):
  with self.assertRaises(ValueError):require_rust('test result: ok. 12 passed; 0 failed; 0 ignored')
 def test_output_under_input(self):
  with tempfile.TemporaryDirectory()as path:
   with self.assertRaises(ValueError):require_disjoint_output(Path(path)/'generated',[Path(path)])
 def test_output_parent_of_input(self):
  with tempfile.TemporaryDirectory()as path:
   with self.assertRaises(ValueError):require_disjoint_output(Path(path),[Path(path)/'source'])
if __name__=='__main__':unittest.main()
