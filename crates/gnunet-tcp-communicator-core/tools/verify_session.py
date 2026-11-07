#!/usr/bin/env python3
"""Maintain current integrated TCP proof using an exact complete workspace copy."""
import argparse
import json
import re
import sys
from pathlib import Path
from session_inputs import (CORE, HOST, PACKAGES, NOALLOC, TOOLS, Commands, Inputs, copy_workspace,
                            disjoint_output, require, same, sha, tree, workspace_contract)
from test_session_inputs import LABELS

sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser()
    for key in ('repository', 'source', 'reference', 'component-reference', 'output'):
        parser.add_argument('--' + key, type=Path, required=True)
    parser.add_argument('--prepare-only',action='store_true',help='Check/copy contracts only; no acceptance result is written')
    parser.add_argument('--development-snapshot',action='store_true',help='Label a full run against an independent development copy, not the current original Root')
    args = parser.parse_args()
    origin, out = args.repository.resolve(), args.output.resolve()
    disjoint_output(out, (origin, args.source, args.reference.parent, args.component_reference.parent, TOOLS),workspace=origin)
    out.mkdir(mode=0o700, exist_ok=False)
    origin_cmd = Commands(out, origin)
    cmd = None
    before, tools_before = tree(origin), tree(TOOLS)
    (out / 'original-workspace-before.json').write_text(json.dumps(before, indent=2) + '\n')
    try:
        controls = origin_cmd.run('guard-controls', [sys.executable, '-B', TOOLS / 'test_session_inputs.py'])
        control_log = (out / 'guard-controls.stderr').read_text()
        names = re.findall(r'^test_\w+', control_log, re.M)
        same(sorted(names), sorted(LABELS), 'exact17 nonempty named controls including original4')
        require(control_log.rstrip().endswith('OK'), 'tool controls did not finish successfully')
        profiles = {'default': (), 'all-features': ('--all-features',),
                    'no-default-features': ('--no-default-features',)}
        original_metadata = {name: origin_cmd.metadata('original-metadata-' + name, flags)
                             for name, flags in profiles.items()}
        baseline = workspace_contract(origin, original_metadata)
        (out / 'original-contract.json').write_text(json.dumps(baseline, indent=2) + '\n')
        same(tree(origin), before, 'original workspace before copy')
        workspace = out / 'workspace'
        same(copy_workspace(origin, workspace), before, 'original complete snapshot lease')
        cmd = Commands(out, workspace)
        copied_metadata = {name: cmd.metadata('copied-metadata-' + name, flags)
                           for name, flags in profiles.items()}
        copied_contract = workspace_contract(workspace, copied_metadata)
        same(copied_contract, baseline, 'all workspace dependency/feature/role/registry contracts')
        (out / 'copied-contract.json').write_text(json.dumps(copied_contract, indent=2) + '\n')
        if args.prepare_only:
            same(tree(origin),before,'original workspace during development preparation')
            same(tree(TOOLS),tools_before,'development tool input set')
            (out/'preparation.json').write_text(json.dumps({'status':'prepared-workspace-contracts-only',
                'whole_profile_executed':False,'original_workspace_files':len(before),
                'complete_metadata_profiles':list(profiles),'two_locks_and_settings':True,
                'registry_note':baseline['registry_note'],'commands':[*origin_cmd.rows,*cmd.rows]},indent=2)+'\n')
            print(json.dumps({'status':'prepared-workspace-contracts-only','path':str(out/'preparation.json')}))
            return
        xtask = cmd.xtask()
        architecture = []
        for check in ('check-deps', 'check-features', 'check-noalloc', 'check-lints'):
            result = cmd.run(check, [xtask, check])
            require(result.decode().rstrip().endswith(check + ': passed'), 'actual complete architecture check absent')
            architecture.append(check)
        common = ['--repository', workspace, '--source', args.source]
        cmd.run('components', [sys.executable, '-B', TOOLS / 'compare_components.py', *common,
                              '--reference', args.component_reference, '--output', out / 'components'])
        cmd.run('elligator', [sys.executable, '-B', TOOLS / 'compare_elligator.py', *common,
                             '--reference', args.component_reference, '--output', out / 'elligator'])
        cmd.run('services', [sys.executable, '-B', TOOLS / 'compare_services.py', *common,
                            '--reference', args.reference, '--output', out / 'services'])
        selected = [piece for package in PACKAGES for piece in ('-p', package)]
        cmd.run('rustdoc', ['cargo', '+1.99.1', 'doc', '--manifest-path', workspace / 'Cargo.toml',
                            '--locked', '--offline', *selected, '--no-deps', '-j', '1'])
        for target in ('thumbv6m-none-eabi', 'thumbv7em-none-eabi'):
            cmd.run(target, ['cargo', '+1.99.1', 'check', '--manifest-path', workspace / NOALLOC / 'Cargo.toml',
                             '--locked', '--offline', '--target', target, '-j', '1'])
        binary = cmd.example(HOST, 'normal_peer')
        fresh = sha(binary)
        cmd.run('actual-peer', [sys.executable, '-B', TOOLS / 'normal_peer_trial.py', *common,
                               '--reference', args.reference, '--output', out / 'actual-peer',
                               '--rust', binary], timeout=180)
        peer = json.loads((out / 'actual-peer/observation.json').read_text())
        require(peer['status'] == 'passed-normal-transport-peer-profile' and len(peer['processes']) == 14,
                'actual successful14-process normal profile required')
        rust = [p for p in peer['processes'] if p['label'] == 'rust-peer']
        require(len(rust) == 1 and rust[0]['binary_sha256'] == fresh and fresh == sha(binary),
                'Cargo-built Rust→actual original process binary identity changed')
        for folder, status in (('components', 'passed-components-only'), ('elligator', 'passed-finite-normal-primitives'),
                               ('services', 'passed-source-bound-service-components')):
            receipt = json.loads((out / folder / 'result.json').read_text())
            require(receipt['status'] == status and receipt['inputs_unchanged'] is True,
                    'fresh nonempty child receipt failed')
        component = json.loads((out / 'components/result.json').read_text())
        require(component['runtime_count'] == 79 and component['doc_count'] == 9, 'exact79/9 tests required')
        same(tree(workspace), before, 'complete copied workspace after every build/process')
        same(tree(origin), before, 'original workspace source/file set after every build/process')
        same(tree(TOOLS), tools_before, 'all maintained tools/support before/after')
        current_metadata = {name: cmd.metadata('final-metadata-' + name, flags) for name, flags in profiles.items()}
        same(workspace_contract(workspace, current_metadata), baseline, 'final full architecture/registry contract')
        cmd.check_artifacts()
        (out / 'original-workspace-after.json').write_text(json.dumps(tree(origin), indent=2) + '\n')
        result = {'status': 'passed-development-copied-workspace-profile'if args.development_snapshot else'passed-current-integrated-tcp-profile', 'inputs_unchanged': True,
                  'repository': str(origin), 'exact_workspace_copy': str(workspace), 'source_files': len(before),
                  'settings_and_two_locks_preserved': True, 'subset_manifests_generated': False,
                  'complete_contract_profiles': list(profiles), 'actual_architecture_checks': architecture,
                  'unique_session_crypto_type_identity': True,
                  'current_original_root_proof':not args.development_snapshot,
                  'registry_note': baseline['registry_note'], 'runtime_tests': 79, 'compile_fail_docs': 9,
                  'ignored_inherited_oracles': 3, 'tool_controls': sorted(LABELS), 'original_controls_preserved': 4,
                  'commands': [*origin_cmd.rows, *cmd.rows], 'cargo_json_artifacts': cmd.artifacts,
                  'child_receipts': [{'path': str(out / p), 'sha256': sha(out / p)} for p in
                                     ('components/result.json', 'elligator/result.json', 'services/result.json',
                                      'actual-peer/observation.json')],
                  'normal_peer': peer['actual_public_transport_roundtrip'], 'normal_rekeys': peer['actual_normal_rekeys'],
                  'whole_tcp_functions_promoted': 0, 'full_subsystems_promoted': 0,
                  'scope': 'Actual integrated packages and complete workspace/roles/two-lock contracts; '
                           'finite normal C crypto/layout components plus actual normal C communicator→Rust inbound '
                           'raw TRANSPORT40/40 and rekey. Historical CORE neighbour and failed CORE application '
                           'profiles remain separate. Full communicator, NAT reversal, CORE application encryption '
                           'and upstream Peerstore concurrent shutdown/recovery remain pending.'}
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'status': result['status'], 'receipt': str(out / 'result.json')}))
    except BaseException as error:
        (out / 'failure.json').write_text(json.dumps({'error': str(error),
                         'commands': [*origin_cmd.rows, *(cmd.rows if cmd else [])]}, indent=2) + '\n')
        raise


if __name__ == '__main__':
    main()
