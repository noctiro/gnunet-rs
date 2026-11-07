#!/usr/bin/env python3
"""Fail-closed local closure and exact actual-test guards; no runtime substitute."""
import hashlib, json, pathlib, re

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def disjoint(output, *roots):
    output = pathlib.Path(output).resolve()
    for root in roots:
        root = pathlib.Path(root).resolve()
        if output.is_relative_to(root) or root.is_relative_to(output):
            raise ValueError('output overlaps input ' + str(root))

def expected_tests(files):
 names=[]
 for path in files:
  text=pathlib.Path(path).read_text()
  names.extend(re.findall(r'(?m)^\s*#\[test\]\s*(?:#\[[\s\S]*?\]\s*)*(?:async\s+)?fn\s+(\w+)',text))
 if len(set(names))!=len(names):raise ValueError('ambiguous duplicate test identity')
 return set(names)

def observed_tests(stdout, expected, count):
    if len(expected) != count:
        raise ValueError('wrong nonempty expected inventory')
    rows = re.findall('^test ([^\\n ]+) \\.\\.\\. (ok|FAILED|ignored)', stdout, re.M)
    if any((status != 'ok' for (_, status) in rows)):
        raise ValueError('nonpassing actual test')
    actual = [name.split('::')[-1] for (name, _) in rows]
    if len(actual) != count or set(actual) != expected:
        raise ValueError('actual named tests differ from expected')
    return sorted(actual)

def check_actor_result(value, pairs, actors):
    if value.get('status') != 'passed' or value.get('inputs_unchanged') is not True:
        raise ValueError('unsealed actor run')
    if value.get('paired_profiles') != pairs:
        raise ValueError('pair inventory missing')
    rows = value.get('cases')
    if not isinstance(rows, list) or len(rows) != actors:
        raise ValueError('empty/wrong actor inventory')
    if any((row.get('exit_code') != 0 for row in rows)):
        raise ValueError('actor nonzero exit')
    if any((not row.get('trace') for row in rows)):
        raise ValueError('empty callback trace')
    return True

def compile_source(entry, cwd, source):
    path = pathlib.Path(entry['file'])
    actual = (path if path.is_absolute() else pathlib.Path(cwd) / path).resolve()
    expected = (pathlib.Path(source) / 'src/lib/util/resolver_api.c').resolve()
    if actual != expected:
        raise ValueError('compiler source path is not the validated upstream tree')
    return actual

def rust_library(stdout, name, manifest=None, package_id=None):
    rows = []
    for line in stdout.splitlines():
        event = json.loads(line)
        if event.get('reason') == 'compiler-artifact' and event.get('target', {}).get('name') == name and (event['target'].get('kind') == ['lib']):
            if manifest is not None and pathlib.Path(event.get('manifest_path','')).resolve()!=pathlib.Path(manifest).resolve():raise ValueError('foreign actual library manifest')
            if package_id is not None and event.get('package_id')!=package_id:raise ValueError('foreign actual library package id')
            files = [path for path in event.get('filenames', []) if path.endswith('.rlib')]
            if len(files) != 1:
                raise ValueError('library artifact has missing/ambiguous rlib')
            rows.append(pathlib.Path(files[0]))
    if len(rows) != 1:
        raise ValueError('missing/duplicate actual Cargo library artifact')
    return rows[0]

# Whole-workspace snapshot contract. These helpers never synthesize Cargo input.
def workspace_files(repo):
 import os
 repo=pathlib.Path(repo).resolve();result={}
 for directory,subdirs,files in os.walk(repo):
  subdirs[:]=[name for name in subdirs if name not in {'.git','target','__pycache__'}]
  for name in subdirs:
   if (pathlib.Path(directory)/name).is_symlink():raise ValueError('source directory symlink is not an isolated input '+str(pathlib.Path(directory)/name))
  for name in files:
   path=pathlib.Path(directory)/name
   if path.is_symlink():raise ValueError('source symlink is not an isolated input '+str(path))
   result[str(path.relative_to(repo))]=sha(path)
 if not result:raise ValueError('empty workspace')
 return dict(sorted(result.items()))

def workspace_contract(repo):
 repo=pathlib.Path(repo).resolve()
 required=['Cargo.toml','Cargo.lock','rust-toolchain.toml','rustfmt.toml','.cargo/config.toml','tests/embedded/noalloc/Cargo.toml','tests/embedded/noalloc/Cargo.lock']
 if any(not(repo/name).is_file() for name in required):raise ValueError('complete workspace/settings/two-lock contract missing')
 text=(repo/'Cargo.toml').read_text()
 for anchor in [r'(?m)^\[workspace\]$',r'(?m)^members\s*=\s*\[',r'(?m)^\[workspace\.lints\.rust\]$',r'(?m)^\[workspace\.lints\.clippy\]$']:
  if re.search(anchor,text)is None:raise ValueError('whole inherited workspace/lint contract missing')
 # Cargo metadata parses the actual complete manifests below. This is only
 # an early preservation guard, never a generated/subset TOML parser.
 return {name:sha(repo/name)for name in required}

def copy_workspace(repo,destination):
 import shutil
 repo=pathlib.Path(repo).resolve();destination=pathlib.Path(destination).resolve();disjoint(destination,repo)
 workspace_contract(repo);before=workspace_files(repo)
 shutil.copytree(repo,destination,ignore=shutil.ignore_patterns('.git','target','__pycache__'))
 after=workspace_files(repo);copied=workspace_files(destination)
 if before!=after or before!=copied:raise ValueError('workspace file set/bytes changed during actual copy')
 workspace_contract(destination)
 return before

def normalized_metadata(metadata,repo,workspace_root=None,require_broker=True):
 repo=pathlib.Path(repo).resolve()
 if pathlib.Path(metadata['workspace_root']).resolve()!=(pathlib.Path(workspace_root).resolve()if workspace_root else repo):raise ValueError('Cargo selected another workspace')
 packages={};roles={};names=set()
 for row in metadata['packages']:
  if row['source']is not None:continue
  path=pathlib.Path(row['manifest_path']).resolve()
  if not path.is_relative_to(repo):raise ValueError('foreign local Cargo package identity '+str(path))
  if row['name']in names:raise ValueError('duplicate local Cargo package identity '+row['name'])
  names.add(row['name']);role=str(path.relative_to(repo));roles[row['id']]=role
  packages[role]={'name':row['name'],'version':row['version'],'features':row.get('features',{})}
 if packages.get('crates/gnunet/Cargo.toml',{}).get('name')!='gnunet' or (require_broker and 'adapters/resolver-broker-std/Cargo.toml'not in packages):raise ValueError('missing SDK or broker package identity')
 nodes=[]
 for node in metadata.get('resolve',{}).get('nodes',[]):
  if node['id']not in roles:continue
  deps=[{'name':d['name'],'pkg':roles.get(d['pkg'],d['pkg']),'dep_kinds':d.get('dep_kinds',[])}for d in node.get('deps',[])]
  nodes.append({'role':roles[node['id']],'features':sorted(node['features']),'dependencies':sorted(deps,key=lambda d:(d['name'],d['pkg']))})
 return {'packages':dict(sorted(packages.items())),'workspace_members':sorted(roles[x]for x in metadata['workspace_members']),'resolve':sorted(nodes,key=lambda n:n['role'])}

def apply_overlay(repo,manifest):
 import shutil
 repo=pathlib.Path(repo).resolve();manifest=pathlib.Path(manifest).resolve();value=json.loads(manifest.read_text());rows=value['source_files'];seen=set()
 allowed={'adapters/ipc-unix/src/client_transport.rs','adapters/ipc-unix/src/clock.rs','adapters/ipc-unix/src/handle.rs','adapters/resolver-broker-std/src/driver.rs','adapters/resolver-broker-std/src/lookup.rs','adapters/resolver-broker-std/tests/retry_clock.rs'}
 if len(rows)!=6 or {row['path']for row in rows}!=allowed:raise ValueError('overlay is not the exact reviewed six-source native-retry delta; settings/manifests may never be overlaid')
 for row in rows:
  rel=pathlib.Path(row['path']);target=(repo/rel).resolve();source=pathlib.Path(row['source']).resolve()
  if rel.is_absolute()or not target.is_relative_to(repo)or str(rel)in seen:raise ValueError('unsafe/duplicate overlay path')
  seen.add(str(rel));old=sha(target)if target.is_file()else None
  if old!=row['baseline_sha256']or sha(source)!=row['candidate_sha256']:raise ValueError('overlay baseline/candidate drift '+str(rel))
 for row in rows:
  target=repo/row['path'];target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(row['source'],target)
 return {'manifest':str(manifest),'sha256':sha(manifest),'files':rows}

# This replaces the old dependency-only closure while retaining its public
# helper signature for all original guard callers.
def local_files(metadata,package,repo):
 repo=pathlib.Path(repo).resolve();package=pathlib.Path(package).resolve()
 if package!=repo/'adapters/resolver-broker-std':raise ValueError('package is not canonical workspace broker role')
 normalized_metadata(metadata,repo);workspace_contract(repo)
 return {str(repo/path):digest for path,digest in workspace_files(repo).items()}

def witness_inventory(repo,profile):
 repo=pathlib.Path(repo).resolve();catalog_path=repo/'adapters/resolver-broker-std/tools/witnesses.json';catalog=json.loads(catalog_path.read_text())
 if profile not in catalog['profiles']:raise ValueError('unknown declared witness profile')
 groups=catalog['profiles'][profile];result={}
 for role,declared in catalog['all_test_targets'].items():
  actual={str(p.relative_to(repo)):sorted(expected_tests([p]))for p in sorted((repo/role/'tests').glob('*.rs'))}
  expected=dict(declared)
  if role=='adapters/resolver-broker-std'and profile=='clock-source':expected.pop('adapters/resolver-broker-std/tests/retry_clock.rs',None)
  if actual!=expected:raise ValueError('unreviewed test target/method file set '+role)
 expected_broker={str(p.relative_to(repo))for p in(repo/'adapters/resolver-broker-std/tests').glob('*.rs')}
 if expected_broker!=set(groups['broker']['files']):raise ValueError('broker test target inventory differs from declared profile')
 for name,group in groups.items():
  names=set()
  for rel,expected in group['files'].items():
   path=repo/rel
   if not path.is_file()or expected_tests([path])!=set(expected):raise ValueError('source witness names changed '+rel)
   if names.intersection(expected):raise ValueError('ambiguous source test name')
   names.update(expected)
  if not names or names!=set(group['required_names'])or len(names)!=group['reviewed_count']:raise ValueError('wrong reviewed nonempty witness group '+name)
  result[name]=names
 return result

def normal_receipt_inputs(path,source_state_value):
 path=pathlib.Path(path).resolve();value=json.loads(path.read_text())
 if value.get('status')!='passed'or value.get('source_unchanged')is not True or value.get('upstream')!=source_state_value:raise ValueError('unverified normal build '+str(path))
 if source_state_value.get('revision')!='346358e26d4dcc2dc4f51bef5d52dca29c7d8165'or source_state_value.get('tracked_sources_clean')is not True:raise ValueError('wrong/dirty normal source')
 rows=list(value.get('artifacts',{}).values())+value.get('libraries',[])+value.get('default_configurations',[])
 for key in ['generated_config','compile_commands']:
  if key in value:rows.append(value[key])
 inputs={str(path):sha(path)}
 for row in rows:
  if sha(row['path'])!=row['sha256']:raise ValueError('normal declared file changed '+row['path'])
  inputs[str(pathlib.Path(row['path']).resolve())]=row['sha256']
  if row.get('built_path'):
   if sha(row['built_path'])!=row['sha256']:raise ValueError('normal original build artifact changed')
   inputs[str(pathlib.Path(row['built_path']).resolve())]=row['sha256']
 return value,inputs
