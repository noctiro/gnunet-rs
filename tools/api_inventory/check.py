#!/usr/bin/env python3
"""Validate official API inventory shape/provenance and report pending coverage.

This verifier never executes commands from catalog data. It does not replace
GNUnet's source/binary/log-bound evidence validator or award whole-feature credit.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest
import copy
import tempfile
from statistics_inventory import document as statistics_document

ROOT = Path(__file__).resolve().parents[2]
REQUIRED = ('util statistics testbed arm peerstore nat nat-auto pils transport core nse hostlist topology dns identity namecache namestore datacache datastore dht cadet seti setu regex revocation vpn gns zonemaster fs exit pt reclaim messenger rest').split()
STATISTICS = {'GNUNET_STATISTICS_' + name for name in ('create', 'destroy', 'get', 'get_cancel', 'set', 'update', 'watch', 'watch_cancel')}
COMMIT = '346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
FOUNDATIONS = ['wire','crypto','hello','block','gnsrecord','service-runtime','storage-contracts','reference-harness']
AVAILABILITY = {'validated', 'recovered', 'unsupported_profile'}
SCOPES = {'required', 'inactive_installed', 'unresolved_installed', 'platform_equivalence_review'}
STATES = {'missing', 'planned', 'in_progress', 'implemented', 'verified'}
MAX_BYTES = 24 * 1024 * 1024


class Invalid(ValueError):
    """An inconsistent, unsafe or falsely promoted inventory claim."""


def require(condition, reason):
    if not condition:
        raise Invalid(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hash_value(value):
    require(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None, 'invalid SHA256')


def strings(value, label, nonempty=False):
    require(isinstance(value, list) and all(isinstance(item, str) and item for item in value), label + ' must be a string list')
    require(len(value) == len(set(value)), label + ' contains duplicates')
    require(not nonempty or bool(value), label + ' cannot be empty')
    return set(value)


def safe_file(root, value):
    require(isinstance(value, str) and bool(value), 'missing local path')
    path = Path(value)
    require(not path.is_absolute() and '..' not in path.parts, 'nonlocal path')
    result = (root / path).resolve()
    require(result.is_relative_to(root.resolve()) and result.is_file(), 'missing/escaping local file: ' + value)
    require(result.stat().st_size <= MAX_BYTES, 'inventory input exceeds bound')
    return result


def argv(value):
    require(isinstance(value, list) and value and all(isinstance(item, str) and item and '\0' not in item for item in value), 'empty/invalid test argv')


def read_bundle(root, catalog_path):
    require(catalog_path.resolve().is_relative_to(root.resolve()), 'catalog outside repository')
    require(catalog_path.stat().st_size <= MAX_BYTES, 'catalog too large')
    catalog = json.loads(catalog_path.read_text())
    files = catalog.get('files')
    require(isinstance(files, list), 'missing catalog files')
    data = {}
    for item in files:
        require(isinstance(item, dict) and item.get('role') in {'declarations', 'operations', 'statistics'}, 'unsupported catalog file role')
        role = item['role']
        require(role not in data, 'duplicate catalog role')
        path = safe_file(root, item.get('path'))
        hash_value(item.get('sha256'))
        raw = path.read_bytes()
        require(digest(raw) == item['sha256'], 'catalog input hash changed: ' + item['path'])
        data[role] = json.loads(raw)
    require(set(data) == {'declarations', 'operations', 'statistics'}, 'required catalog input missing')
    return catalog, data['declarations'], data['operations'], data['statistics']


def validate(catalog, declarations, operations, statistics, source=None, build=None, root=ROOT):
    def no_embedded_report(value):
        if isinstance(value,dict):
            require(value.get('verification') is None, 'normative API files cannot embed report references: hash cycle')
            for member in value.values():no_embedded_report(member)
        elif isinstance(value,list):
            for member in value:no_embedded_report(member)
    for item in (catalog,declarations,operations,statistics):no_embedded_report(item)
    require(all(item.get('schema') == 1 for item in (catalog, declarations, operations, statistics)), 'unsupported API catalog schema')
    require(catalog.get('baseline', {}).get('commit') == COMMIT, 'wrong official baseline')
    require(catalog.get('required_subsystems') == REQUIRED, 'all 34 subsystems are required in fixed order')
    policy = catalog.get('policy', {})
    for key in ('function_counts_are_feature_coverage', 'recovered_declarations_can_be_verified', 'deprecated_means_automatically_excluded', 'installed_means_automatically_active', 'no_public_header_means_no_required_behavior'):
        require(policy.get(key) is False, 'unsafe API coverage policy: ' + key)
    require(catalog.get('full_gnunet_conformance_claim') is False, 'API inventory cannot assert whole GNUnet conformance')
    headers = declarations.get('headers', [])
    require(headers and isinstance(headers, list), 'empty header capture')
    header_by_path, header_ids = {}, set()
    fixed_scopes={name:'inactive_installed' for name in ('gnunet_abd_service.h','gnunet_consensus_service.h','gnunet_conversation_service.h','gnunet_rps_service.h','gnunet_scalarproduct_service.h','gnunet_secretsharing_service.h','gnunet_set_service.h')}
    fixed_scopes.update({'gnunet_op_lib.h':'unresolved_installed','compat.h':'platform_equivalence_review','gettext.h':'platform_equivalence_review'})
    binding_rows=catalog.get('header_bindings',[])
    require(isinstance(binding_rows,list) and len({item.get('id') for item in binding_rows})==len(binding_rows), 'missing/duplicate independent header binding')
    bindings={item['id']:item for item in binding_rows}
    scope_pending, conditional_pending = 0, 0
    for header in headers:
        require(header.get('id') not in header_ids, 'duplicate header')
        header_ids.add(header['id'])
        binding=bindings.get(header['id'])
        require(binding is not None and all(header.get(key)==binding.get(key) for key in ('scope','owners','foundation_owners','origin')), 'compiler header scope/owner binding changed')
        require(header.get('scope')==fixed_scopes.get(header['id'],'required'), 'required header cannot be demoted by scope metadata')
        origin = header.get('origin', {})
        require(origin.get('kind') in {'tracked', 'generated'}, 'unknown header provenance')
        path = origin.get('path')
        require(isinstance(path, str) and path and path not in header_by_path, 'missing/duplicate header path')
        hash_value(origin.get('sha256'))
        require(header.get('availability') in AVAILABILITY and header.get('scope') in SCOPES, 'invalid header category')
        require(header.get('owners') is not None and strings(header['owners'], 'header owners') <= set(REQUIRED), 'unknown header owner')
        strings(header.get('declaration_ids'), 'header declarations')
        if header['availability'] == 'validated':
            compiler = header.get('compiler')
            require(isinstance(compiler, dict) and compiler.get('ast_exit_code') == compiler.get('preprocessor_exit_code') == 0, 'validated header lacks successful actual compiler capture')
            for key in ('ast_sha256', 'preprocessed_sha256', 'translation_unit_sha256'):
                hash_value(compiler.get(key))
        if header['scope_review'].get('status') != 'reviewed':
            scope_pending += 1
        else:
            require(bool(header['scope_review'].get('reason')), 'scope review requires rationale')
        if header['conditional_review'].get('status') != 'reviewed':
            conditional_pending += 1
        else:
            require(bool(header['conditional_review'].get('reason')), 'conditional review requires rationale')
        header_by_path[path] = header
    require(header_ids==set(bindings), 'independent installed header binding missing')
    require(header_ids==strings(catalog.get('expected_header_ids',[]),'expected installed headers',True), 'installed header inventory was dropped or changed')
    sites = declarations.get('declarations', [])
    require(isinstance(sites, list) and sites, 'empty compiler declarations')
    site_by_id = {}
    for site in sites:
        ident = site.get('id')
        require(isinstance(ident, str) and ident not in site_by_id, 'missing/duplicate declaration ID')
        header = header_by_path.get(site.get('header'))
        require(header is not None and ident in header['declaration_ids'], 'declaration has no exact source-header binding')
        require(site.get('owners')==header['owners'] and site.get('foundation_owners')==header['foundation_owners'], 'declaration lost its source-header owner binding')
        require(site.get('availability') == header['availability'] and site.get('scope') == header['scope'], 'declaration category differs from its compiler capture')
        require(site.get('kind') in {'FunctionDecl', 'TypedefDecl', 'RecordDecl', 'EnumDecl', 'EnumConstantDecl', 'VarDecl'}, 'macro or unknown node promoted to declaration')
        require(isinstance(site.get('name'), str) and site['name'].startswith('GNUNET_'), 'foreign symbol in GNUnet declaration capture')
        site_by_id[ident] = site
    require(set(site_by_id) == {ident for header in headers for ident in header['declaration_ids']}, 'header declaration was dropped')
    functions = declarations.get('functions', [])
    require(isinstance(functions, list) and functions, 'empty function inventory')
    function_by_id, function_sites = {}, set()
    requirements = {ident: set() for ident in REQUIRED+FOUNDATIONS}
    unverified, availability_counts = 0, Counter()
    for function in functions:
        name = function.get('id')
        require(isinstance(name, str) and re.fullmatch(r'GNUNET_[A-Za-z0-9_]+', name) and name not in function_by_id, 'missing/duplicate public function')
        require(function.get('kind') == 'function', 'nonfunction counted as function')
        refs = strings(function.get('declaration_ids'), 'function declaration references', True)
        require(not (refs & function_sites), 'declaration counted in multiple functions')
        members = [site_by_id.get(ident) for ident in refs]
        require(all(site is not None and site['kind'] == 'FunctionDecl' and site['name'] == name for site in members), 'callback/macro/nonmatching symbol counted as function')
        expected = 'validated' if any(site['availability'] == 'validated' for site in members) else ('recovered' if any(site['availability'] == 'recovered' for site in members) else 'unsupported_profile')
        require(function.get('availability') == expected, 'function was promoted beyond its compiler availability')
        require(function.get('scope')==('required' if any(site['scope']=='required' for site in members) else members[0]['scope']), 'required function scope was demoted or changed')
        require(set(function.get('signatures', [])) == {site['type'] for site in members}, 'compiler signature changed or omitted')
        require(function.get('status') in STATES, 'unknown API implementation state')
        owners = strings(function.get('owners'), 'function owners')
        require(owners == {owner for site in members for owner in site['owners']} and owners <= set(REQUIRED), 'function owner binding differs from compiler source catalog')
        foundations=strings(function.get('foundation_owners'), 'function foundations')
        require(foundations=={owner for site in members for owner in site['foundation_owners']} and foundations<=set(FOUNDATIONS), 'function foundation binding differs')
        criterion_ids = strings(function.get('required_criterion_ids'), 'API criterion IDs')
        if function.get('scope') == 'required':
            require(bool(owners|foundations), 'required API has no evidence owner')
            require('api.' + name in criterion_ids, 'required function has no stable criterion ID')
            for ident in owners|foundations:
                requirements[ident].update(criterion_ids)
            unverified += int(function['status'] not in {'implemented','verified'})
        if function['status'] in {'implemented', 'verified'}:
            require(function.get('rust_equivalence') and function.get('test_commands'), 'implemented API lacks Rust equivalence/tests')
            for command in function['test_commands']:
                argv(command)
            for mapping in function['rust_equivalence']:
                strings(mapping.get('items'), 'Rust public items', True)
                for path in strings(mapping.get('source_files'), 'Rust implementation sources', True):
                    require(path.startswith(('crates/', 'adapters/', 'apps/')) and path.endswith('.rs'), 'API implementation must be production Rust')
                    safe_file(root, path)
                require(bool(mapping.get('reason')), 'Rust equivalence needs observable semantic rationale')
        if function['status'] == 'verified':
            require(function.get('signature_review')=='reviewed', 'verified API signature was not reviewed')
            require(expected == 'validated' and function['scope'] == 'required', 'recovered/unsupported/unreviewed API cannot earn verified credit')
        function_sites.update(refs)
        availability_counts[function['availability']] += 1
        function_by_id[name] = function
    require(function_sites == {ident for ident, site in site_by_id.items() if site['kind'] == 'FunctionDecl'}, 'compiler function declaration missing from logical function inventory')
    surface_ids=set();covered_nonfunctions=set();covered_macros=set();pending_surfaces=0
    surfaces=declarations.get('surfaces',[])
    require(surfaces, 'public type/callback/macro surface inventory missing')
    for surface in surfaces:
        ident=surface.get('id')
        require(isinstance(ident,str) and ident.startswith('api-surface.') and ident not in surface_ids, 'invalid/duplicate public surface')
        surface_ids.add(ident)
        require(surface.get('status') in STATES and surface.get('availability') in AVAILABILITY and surface.get('scope') in SCOPES, 'invalid public surface category')
        if surface['kind']=='declaration':
            refs=strings(surface.get('declaration_ids'),'public surface declaration references',True)
            require(not(refs&covered_nonfunctions), 'public declaration covered by multiple surfaces')
            members=[site_by_id.get(value) for value in refs]
            require(all(member is not None and member['kind']!='FunctionDecl' for member in members), 'function counted as public nonfunction surface')
            expected='validated' if any(member['availability']=='validated' for member in members) else ('recovered' if any(member['availability']=='recovered' for member in members) else 'unsupported_profile')
            require(surface['availability']==expected, 'public type promoted beyond compiler availability')
            require(surface['scope']==('required' if any(member['scope']=='required' for member in members) else members[0]['scope']), 'required public type scope was demoted')
            require(set(surface['foundation_owners'])=={owner for member in members for owner in member['foundation_owners']},'public surface foundation binding differs')
            require(set(surface['owners'])=={owner for member in members for owner in member['owners']},'public surface owner binding differs')
            covered_nonfunctions.update(refs)
        elif surface['kind']=='macro':
            header=header_by_path.get(surface.get('header'))
            require(header is not None and surface['availability']==header['availability'] and surface['scope']==header['scope'] and surface['owners']==header['owners'] and surface['foundation_owners']==header['foundation_owners'], 'macro has no exact compiler header/owner binding')
            require(any(macro['name']==surface.get('name') and macro['definition']==surface.get('definition') and macro['definition_sha256']==surface.get('definition_sha256') for macro in header['macros']), 'macro definition changed')
            require(surface['name']!=header['include_guard'], 'include guard counted as API functionality')
            require((header['id'],surface['name']) not in covered_macros,'duplicate macro surface')
            covered_macros.add((header['id'],surface['name']))
        else:raise Invalid('unsupported public surface kind')
        if surface['scope']=='required':
            require(bool(set(surface['owners'])|set(surface['foundation_owners'])), 'required public surface has no evidence owner')
            for owner in set(surface['owners'])|set(surface['foundation_owners']):requirements[owner].add(ident)
            pending_surfaces+=int(surface['status'] not in {'implemented','verified'})
        if surface['status'] in {'implemented','verified'}:
            require(surface.get('rust_equivalence') and surface.get('test_commands'),'implemented public surface lacks Rust mapping/tests')
            for command in surface['test_commands']:argv(command)
        if surface['status']=='verified':
            require(surface['availability']=='validated' and surface['scope']=='required','recovered/unsupported public surface cannot verify')
    require(covered_nonfunctions=={ident for ident,site in site_by_id.items() if site['kind']!='FunctionDecl'}, 'public callback/type declaration was dropped')
    require(covered_macros=={(header['id'],macro['name']) for header in headers for macro in header['macros'] if macro['name']!=header['include_guard']}, 'public macro surface was dropped')
    summary = declarations.get('summary', {})
    require(summary.get('nonfunction_surface_entries')==len(surfaces), 'nonfunction surface count mismatch')
    require(summary.get('logical_functions') == len(functions) and summary.get('function_declaration_sites') == len(function_sites), 'function count does not match actual typed declarations')
    require(summary.get('function_availability') == dict(availability_counts), 'validated/recovered/unsupported tiers were mixed')
    callback_count = sum(site['kind'] == 'TypedefDecl' and site.get('callback', False) for site in sites)
    require(summary.get('callback_declaration_sites') == callback_count, 'callback count is not independent')
    require(summary.get('active_GNUNET_macro_definitions') == sum(len(header['macros']) for header in headers), 'macro count is not independent')
    registry_header = next((header for header in headers if header['id'] == 'gnunet_protocols.h'), None)
    require(registry_header is not None, 'missing source-bound message registry')
    registry = {}
    for macro in registry_header['macros']:
        if macro['name'].startswith('GNUNET_MESSAGE_TYPE_'):
            try:
                value = int(macro['definition'], 0)
            except (TypeError, ValueError) as error:
                raise Invalid('message registry needs explicit compiler-evaluated integer') from error
            require(0 <= value <= 65535 and macro['name'] not in registry, 'invalid/duplicate message number')
            registry[macro['name']] = value
    subsystem_rows = operations.get('subsystems', [])
    require([entry.get('id') for entry in subsystem_rows] == REQUIRED, 'operation inventory omitted/reordered a required subsystem')
    expected_message_owners=catalog.get('expected_owner_messages',{})
    require(set(expected_message_owners)==set(REQUIRED), 'independent message owner inventory missing')
    unit_messages={owner:set() for owner in REQUIRED}
    unit_reference_sets={owner:{} for owner in REQUIRED}
    expected_units={item['path']:item for item in catalog.get('production_unit_bindings',[])}
    require(expected_units and set(expected_units)=={item['path'] for item in operations.get('translation_units',[])}, 'configured production translation-unit inventory was dropped or changed')
    for unit in operations.get('translation_units',[]):
        binding=expected_units[unit['path']]
        require(all(unit.get(key)==binding.get(key) for key in ('owner','source_sha256','preprocessed_sha256')), 'compiler translation-unit owner/hash binding changed')
        for reference in unit.get('references',[]):
            key=(unit['path'],reference['line'],reference['context'])
            unit_reference_sets[unit['owner']].setdefault(reference['name'],set()).add(key)
            require(reference.get('name') in registry and reference.get('value')==registry[reference['name']], 'compiler message reference lost actual number binding')
        require(unit.get('owner') in unit_messages, 'unknown compiler translation-unit owner')
        unit_messages[unit['owner']].update(reference['name'] for reference in unit.get('references',[]))
    operation_pending = 0
    generic_case_ids=set()
    for entry in subsystem_rows:
        ident = entry['id']
        require(entry.get('required') is True and entry.get('verified') is False, 'source operation catalog cannot self-award verification')
        expected_functions = {name for name, function in function_by_id.items() if ident in function['owners']}
        require(strings(entry.get('function_ids'), 'subsystem function inventory') == expected_functions, 'subsystem function inventory omits a public declaration')
        require(strings(entry.get('surface_ids'),'subsystem public surface inventory')=={surface['id'] for surface in surfaces if ident in surface['owners']}, 'subsystem public type/callback/macro inventory omitted')
        if not entry['public_headers']:
            require(bool(entry.get('no_dedicated_public_api_reason')), 'headerless subsystem cannot silently become not applicable')
        incomplete_operation=entry.get('operation_review')!='reviewed'
        if not incomplete_operation:require(bool(entry.get('behavior_cases')), 'reviewed subsystem has zero behavior cases')
        for case in entry.get('behavior_cases',[]):
            case_id=case.get('id')
            require(isinstance(case_id,str) and case_id.startswith(ident+'.') and case_id not in generic_case_ids, 'invalid/duplicate subsystem behavior criterion')
            generic_case_ids.add(case_id)
            require(case.get('required') is True and case.get('requirement') and case.get('status') in STATES, 'required behavior cannot disappear through metadata')
            requirements[ident].add(case_id)
            incomplete_operation=incomplete_operation or case['status'] not in {'implemented','verified'}
            if case['status'] in {'implemented','verified'}:
                require(case.get('test_commands'),'verified behavior has zero test commands')
                for command in case['test_commands']:argv(command)
        operation_pending+=int(incomplete_operation)
        candidate_names={message.get('name') for message in entry.get('message_candidates',[])}
        require(candidate_names==strings(expected_message_owners[ident],'independent expected wire messages')==unit_messages[ident], 'active compiler message variant was dropped or changed')
        seen_messages = set()
        for message in entry.get('message_candidates', []):
            require(message.get('name') not in seen_messages and message.get('name') in registry and message.get('number') == registry.get(message.get('name')), 'message candidate lacks exact active C registry binding')
            require(bool(message.get('references')), 'wire candidate has no active compiler source reference')
            require({(reference['path'],reference['line'],reference['context']) for reference in message['references']}==unit_reference_sets[ident].get(message['name'],set()), 'wire candidate references differ from compiler source capture')
            criterion='wire-message.'+ident+'.'+message['name'].removeprefix('GNUNET_MESSAGE_TYPE_')
            require(message.get('criterion_id')==criterion, 'wire variant has no stable required evidence criterion')
            requirements[ident].add(criterion)
            seen_messages.add(message['name'])
    units = operations.get('translation_units', [])
    require(units and all(row.get('status') == 'preprocessed' and row.get('exit_code') == 0 for row in units), 'missing/failed compiler operation source capture')
    for row in units:
        hash_value(row.get('source_sha256'))
        hash_value(row.get('preprocessed_sha256'))
    stat_functions = statistics.get('public_functions', [])
    require(statistics.get('subsystem') == 'statistics' and {entry.get('symbol') for entry in stat_functions} == STATISTICS and len(stat_functions) == 8, 'STATISTICS must cover all exact eight public C functions')
    require(STATISTICS == {name for name in function_by_id if name.startswith('GNUNET_STATISTICS_')}, 'compiler STATISTICS capture differs from explicit operation inventory')
    cases, verified_cases = {}, 0
    for function in stat_functions:
        require(function.get('criterion_id') == 'api.' + function['symbol'] and function.get('cases'), 'STATISTICS function lacks concrete behavior cases')
        for case in function['cases']:
            require(case.get('id') not in cases, 'duplicate behavioral criterion')
            cases[case.get('id')] = case
    for case in statistics.get('cross_operation_cases', []):
        require(case.get('id') not in cases, 'duplicate cross-operation criterion')
        cases[case.get('id')] = case
    expected_document=statistics_document()
    expected_cases={case['id'] for function in expected_document['public_functions'] for case in function['cases']} | {case['id'] for case in expected_document['cross_operation_cases']}
    require(set(cases)==expected_cases, 'required STATISTICS lifecycle case missing or replaced')
    implemented_cases=0
    for ident, case in cases.items():
        require(isinstance(ident, str) and ident.startswith('statistics.client.') and case.get('required') is True and case.get('requirement'), 'missing STATISTICS lifecycle requirement')
        require(case.get('status') in STATES, 'unknown behavioral implementation status')
        if case['status'] in {'implemented','verified'}:
            require(case.get('test_commands'), 'verified behavior has no executed-test command')
            for command in case['test_commands']:
                argv(command)
            implemented_cases+=1
            verified_cases += int(case['status']=='verified')
        requirements['statistics'].add(ident)
    require(statistics.get('full_client_api_verified') is False, 'inventory cannot self-assert full client verification')
    control_inputs=catalog.get('control_source_inputs',[])
    controls={row['path']:row['sha256'] for row in control_inputs}
    require(len(controls)==len(control_inputs) and set(controls)=={'src/include/meson.build','src/include/gnunet_config.h.in','src/service/meson.build'}, 'normative source controls missing/duplicated')
    expected_sources={header['origin']['path']:header['origin']['sha256'] for header in headers if header['origin']['kind']=='tracked'}
    for unit in units:
        require(unit['path'] not in expected_sources or expected_sources[unit['path']]==unit['source_sha256'], 'conflicting source identity')
        expected_sources[unit['path']]=unit['source_sha256']
    for header in headers:
        if header['origin']['kind']=='generated':
            template=header['origin'].get('template',{})
            require(template.get('path') in controls and template.get('sha256')==controls[template['path']], 'generated header template binding differs')
    expected_sources.update(controls)
    source_inputs=operations.get('source_inputs',[])
    input_map={row['path']:row['sha256'] for row in source_inputs}
    require(len(input_map)==len(source_inputs) and input_map==expected_sources, 'source inputs differ from exact tracked-header/TU/control provenance')
    source_verified = False
    if source is not None:
        source = source.resolve()
        revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True, timeout=30).strip()
        require(revision == COMMIT, 'reference checkout is not pinned')
        subprocess.run(['git', '-C', str(source), 'diff', '--quiet', COMMIT, '--'], check=True, timeout=30)
        for item in operations.get('source_inputs', []):
            hash_value(item.get('sha256'))
            require(digest(safe_file(source, item.get('path')).read_bytes()) == item['sha256'], 'upstream source input changed: ' + item['path'])
        source_verified = True
    build_verified = False
    if build is not None:
        build = build.resolve()
        for header in headers:
            origin = header['origin']
            if origin['kind'] == 'generated':
                path = origin['path'].removeprefix('@build/')
                require(digest(safe_file(build, path).read_bytes()) == origin['sha256'], 'generated C header/profile changed')
        profile = declarations['profile']['private_configuration']
        require(digest(safe_file(build, profile['path'].removeprefix('@build/')).read_bytes()) == profile['sha256'], 'private C configuration/profile changed')
        build_verified = True
    gaps = sum(function['scope'] == 'required' and function['availability'] != 'validated' for function in functions)
    profile_pending = declarations['profile'].get('availability_review') != 'reviewed'
    additional_profiles=declarations['profile'].get('additional_profile_reviews',[])
    require({row.get('id') for row in additional_profiles}=={'linux-full','conditional-and-backend-profiles'}, 'additional profile obligations disappeared')
    profile_pending = profile_pending or any(row.get('status')!='reviewed' or not row.get('reason') for row in additional_profiles)
    signature_pending=sum(function['scope']=='required' and function.get('signature_review')!='reviewed' for function in functions)
    ready = not (unverified or pending_surfaces or gaps or signature_pending or scope_pending or conditional_pending or operation_pending or profile_pending or implemented_cases != len(cases))
    return {'status': 'valid' if ready else 'valid-incomplete', 'inventory_ready': ready, 'full_gnunet_conformance_claim': False,
            'evidence_validation_required_externally': True, 'source_verified': source_verified, 'build_profile_verified': build_verified,
            'subsystems': len(subsystem_rows), 'headers': len(headers), 'function_declaration_sites': len(function_sites),
            'logical_functions': len(functions), 'function_availability': dict(availability_counts), 'callbacks': callback_count,
            'macros': summary['active_GNUNET_macro_definitions'], 'production_translation_units': len(units),
            'pending_required_functions': unverified, 'pending_function_signature_reviews':signature_pending, 'pending_required_nonfunction_surfaces':pending_surfaces, 'nonfunction_surfaces':len(surfaces), 'required_function_profile_gaps': gaps,
            'pending_header_scope_reviews': scope_pending, 'pending_header_conditional_reviews': conditional_pending,
            'pending_subsystem_operation_reviews': operation_pending, 'pending_profile_review': profile_pending,
            'statistics_required_cases': len(cases), 'statistics_verified_cases': verified_cases, 'statistics_implemented_cases':implemented_cases,
            'required_criteria': {key: sorted(value) for key, value in requirements.items()}}


class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog, cls.declarations, cls.operations, cls.statistics = read_bundle(ROOT, ROOT / 'spec/gnunet/api/catalog.json')

    def altered(self, mutation):
        values = copy.deepcopy((self.catalog, self.declarations, self.operations, self.statistics))
        mutation(*values)
        with self.assertRaises(Invalid):
            validate(*values)

    def test_real_inventory_counts_remain_incomplete(self):
        result = validate(self.catalog, self.declarations, self.operations, self.statistics)
        self.assertFalse(result['inventory_ready'])
        self.assertEqual(result['subsystems'], 34)
        self.assertEqual(result['statistics_required_cases'], 51)
        self.assertGreater(result['function_availability']['recovered'], 0)
        self.assertEqual(result['statistics_verified_cases'], 0)

    def test_header_source_provenance_cannot_diverge_from_inputs(self):
        def mutate(c,d,o,s):
            header=next(header for header in d['headers'] if header['id']=='gnunet_statistics_service.h')
            header['origin']['sha256']='0'*64
            next(binding for binding in c['header_bindings'] if binding['id']==header['id'])['origin']['sha256']='0'*64
        self.altered(mutate)
        self.altered(lambda c,d,o,s:o['source_inputs'].pop())

    def test_report_pointers_cannot_create_a_normative_hash_cycle(self):
        def mutate(c,d,o,s):
            s['public_functions'][0]['cases'][0]['verification']={'path':'target/evidence.json','sha256':'0'*64}
        self.altered(mutate)

    def test_missing_statistics_operation_is_rejected(self):
        self.altered(lambda c, d, o, s: s['public_functions'].pop())

    def test_missing_public_type_or_macro_is_rejected(self):
        self.altered(lambda c,d,o,s:d['surfaces'].pop())

    def test_missing_installed_header_is_rejected(self):
        self.altered(lambda c,d,o,s:d['headers'].pop())

    def test_production_unit_cannot_be_dropped_or_reowned(self):
        self.altered(lambda c,d,o,s:o['translation_units'].pop())
        self.altered(lambda c,d,o,s:o['translation_units'][0].__setitem__('owner','statistics'))

    def test_whole_wire_variant_cannot_be_dropped(self):
        self.altered(lambda c,d,o,s:o['subsystems'][1]['message_candidates'].pop())

    def test_cascaded_header_scope_demotion_is_rejected(self):
        def mutate(c,d,o,s):
            header=next(header for header in d['headers'] if header['id']=='gnunet_statistics_service.h')
            header['scope']='inactive_installed'
            ids=set(header['declaration_ids'])
            for site in d['declarations']:
                if site['id'] in ids:site['scope']='inactive_installed'
            by_id={site['id']:site for site in d['declarations']}
            for record in d['functions']+[entry for entry in d['surfaces'] if entry['kind']=='declaration']:
                members=[by_id[ident] for ident in record['declaration_ids']]
                record['scope']='required' if any(site['scope']=='required' for site in members) else members[0]['scope']
            for surface in d['surfaces']:
                if surface['kind']=='macro' and surface['header']==header['origin']['path']:surface['scope']='inactive_installed'
        self.altered(mutate)

    def test_required_function_cannot_lose_owners_through_its_sites(self):
        def mutate(c,d,o,s):
            function=next(function for function in d['functions'] if function['id']=='GNUNET_STATISTICS_create')
            function['owners']=[];function['foundation_owners']=[]
            for site in d['declarations']:
                if site['id'] in function['declaration_ids']:site['owners']=[];site['foundation_owners']=[]
            next(entry for entry in o['subsystems'] if entry['id']=='statistics')['function_ids'].remove(function['id'])
        self.altered(mutate)

    def test_wire_obligations_cannot_be_removed(self):
        self.altered(lambda c,d,o,s:o['subsystems'][1]['message_candidates'][0].pop('criterion_id'))
        result=validate(self.catalog,self.declarations,self.operations,self.statistics)
        self.assertIn('wire-message.statistics.STATISTICS_WATCH_VALUE', result['required_criteria']['statistics'])

    def test_reviewed_generic_behavior_still_requires_real_test_claim(self):
        def mutate(c,d,o,s):
            entry=next(row for row in o['subsystems'] if row['id']=='zonemaster')
            entry['operation_review']='reviewed'
            entry['behavior_cases']=[{'id':'zonemaster.publish','required':True,'requirement':'actual publication','status':'verified','test_commands':[],'verification':None}]
        self.altered(mutate)

    def test_missing_lifecycle_case_is_rejected(self):
        self.altered(lambda c,d,o,s:s['public_functions'][0]['cases'].pop())

    def test_missing_subsystem_is_rejected(self):
        self.altered(lambda c, d, o, s: o['subsystems'].pop())

    def test_callback_cannot_count_as_function(self):
        def mutate(c, d, o, s):
            callback = next(site for site in d['declarations'] if site['kind'] == 'TypedefDecl' and site.get('callback'))
            d['functions'][0]['declaration_ids'] = [callback['id']]
        self.altered(mutate)

    def test_required_function_and_type_scopes_cannot_be_demoted(self):
        def demote_function(c,d,o,s):
            next(function for function in d['functions'] if function['scope']=='required')['scope']='inactive_installed'
        self.altered(demote_function)
        def demote_type(c,d,o,s):
            next(surface for surface in d['surfaces'] if surface['scope']=='required')['scope']='inactive_installed'
        self.altered(demote_type)

    def test_recovered_function_cannot_be_promoted(self):
        def mutate(c, d, o, s):
            recovered = next(function for function in d['functions'] if function['availability'] == 'recovered')
            recovered['availability'] = 'validated'
        self.altered(mutate)

    def test_false_verified_status_has_no_credit(self):
        def mutate(c, d, o, s):
            recovered = next(function for function in d['functions'] if function['availability'] == 'recovered')
            recovered['status'] = 'verified'
        self.altered(mutate)

    def test_count_or_registry_tampering_is_rejected(self):
        self.altered(lambda c, d, o, s: d['summary'].__setitem__('logical_functions', 1))
        self.altered(lambda c, d, o, s: o['subsystems'][1]['message_candidates'][0].__setitem__('number', 9999))

    def test_empty_filter_and_unbacked_behavior_cannot_verify(self):
        def mutate(c, d, o, s):
            case = s['public_functions'][0]['cases'][0]
            case['status'] = 'verified'
            case['test_commands'] = []
        self.altered(mutate)

    def test_paths_cannot_escape_repository(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with self.assertRaises(Invalid):
                safe_file(root, '../outside.json')
            with self.assertRaises(Invalid):
                safe_file(root, '/etc/passwd')

    def test_duplicate_criterion_and_headerless_behavior_are_rejected(self):
        self.altered(lambda c, d, o, s: s['cross_operation_cases'].append(copy.deepcopy(s['public_functions'][0]['cases'][0])))
        def mutate(c, d, o, s):
            row = next(row for row in o['subsystems'] if row['id'] == 'exit')
            row['operation_review'] = 'reviewed'
        self.altered(mutate)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path, default=ROOT / 'spec/gnunet/api/catalog.json')
    parser.add_argument('--source', type=Path)
    parser.add_argument('--build', type=Path)
    parser.add_argument('--strict', action='store_true')
    parser.add_argument('--json', action='store_true', help='emit full machine-readable result including required_criteria for all 42 owners')
    parser.add_argument('--requirements', action='store_true', help='include per-owner IDs for the parent evidence validator')
    parser.add_argument('--show', choices=REQUIRED, help='show one subsystem operation inventory')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(BoundaryTests))
        print(json.dumps({'status': 'passed' if result.wasSuccessful() and result.testsRun else 'failed', 'executed_checks': result.testsRun}))
        return 0 if result.wasSuccessful() and result.testsRun else 1
    try:
        bundle = read_bundle(ROOT, args.catalog)
        result = validate(*bundle, source=args.source, build=args.build)
        if args.show:
            print(json.dumps(next(row for row in bundle[2]['subsystems'] if row['id'] == args.show), indent=2))
        else:
            if not (args.requirements or args.json):
                result.pop('required_criteria')
            print(json.dumps(result, sort_keys=True))
        if args.strict:
            return 0 if result['inventory_ready'] and result['source_verified'] and result['build_profile_verified'] else 1
        return 0
    except (Invalid, ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError, AttributeError) as error:
        print(json.dumps({'status': 'invalid', 'error': str(error)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
