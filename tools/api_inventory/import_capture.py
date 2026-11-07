#!/usr/bin/env python3
"""Import a compiler capture into the versioned API ledger without granting credit.

The input is produced by extract.py with the exact pinned C source/build. This
command is an explicit catalog mutation, never run by a read-only verifier.
"""
import argparse
from collections import Counter
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REQUIRED = ('util statistics testbed arm peerstore nat nat-auto pils transport core nse hostlist topology dns identity namecache namestore datacache datastore dht cadet seti setu regex revocation vpn gns zonemaster fs exit pt reclaim messenger rest').split()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    # One header/function/subsystem per logical line keeps the capture compact
    # while allowing review with ordinary line-oriented source tools.
    path.write_text(json.dumps(value, separators=(',', ':'), ensure_ascii=True) + '\n')


def build(capture, source, output):
    raw = json.loads((capture / 'configured-api-inventory.json').read_text())
    operations = json.loads((capture / 'api-operation-catalog.json').read_text())
    by_header = {Path(row['path']).name: row for row in operations['headers']}
    install_plan=Path(raw['build'])/'meson-info/intro-install_plan.json'
    if sha(install_plan)!=raw['source_install_manifest_sha256']:raise ValueError('Meson install manifest changed')
    installed=json.loads(install_plan.read_text())['headers']
    expected_capture={Path(path).name for path in installed if Path(path).name.startswith(('gnunet_','gnu_name_system_'))} | {'gnunet_config.h'}
    if {Path(header['path']).name for header in raw['headers']}!=expected_capture:raise ValueError('partial compiler header capture cannot become a full API inventory')
    declarations, headers, grouped = [], [], {}
    def macro_metadata(macro):
        definition=macro['definition']
        literal=definition if re.fullmatch(r'(?:[0-9]+|0[xX][0-9a-fA-F]+)',definition) else None
        return {**{key:value for key,value in macro.items() if key!='definition'}, 'definition':literal,
                'definition_sha256':hashlib.sha256(definition.encode()).hexdigest(),
                'definition_kind':'integer-literal' if literal is not None else ('function-macro' if macro['function_like'] else 'expression-or-alias')}
    for header in raw['headers']:
        name = Path(header['path']).name
        role = by_header[name]
        generated = name == 'gnunet_config.h'
        origin = {'kind': 'generated' if generated else 'tracked', 'path': '@build/src/include/gnunet_config.h' if generated else header['path'], 'sha256': header['source_sha256']}
        if generated:
            origin['template'] = {'path': 'src/include/gnunet_config.h.in', 'sha256': sha(source / 'src/include/gnunet_config.h.in')}
        availability = 'validated' if header['clang_exit_code'] == header['preprocess_exit_code'] == 0 else 'recovered'
        scope = 'required' if role['owners'] or role['foundation_owners'] else 'inactive_installed'
        owners = role['owners']
        gap = None
        if name == 'gnunet_op_lib.h':
            availability, scope, owners = 'unsupported_profile', 'unresolved_installed', []
            gap = 'Installed declarations are absent from the documented util umbrella, configured Meson sources and actual libgnunetutil exports; source/API exclusion needs review.'
        if availability == 'recovered':
            gap = 'Configured native header preprocessing failed (missing libpq-fe.h). Recovered AST types are not validated C signatures.'
        ids = []
        for original in header['declarations']:
            row = {key: value for key, value in original.items() if key not in ('documentation_brief', 'documentation_tags')}
            row['id'] = header['path'].split('/')[-1] + ':' + row['kind'] + ':' + row['name'] + ':' + str(row.get('offset'))
            row['header'] = origin['path']
            row['availability'] = availability
            row['scope'] = scope
            row['owners'] = owners
            row['foundation_owners'] = role['foundation_owners']
            row['deprecated'] = 'DeprecatedAttr' in row['attributes'] or any(tag.get('name') == 'deprecated' for tag in original['documentation_tags'])
            ids.append(row['id'])
            declarations.append(row)
            if row['kind'] == 'FunctionDecl':
                grouped.setdefault(row['name'], []).append(row)
        headers.append({'id': name, 'origin': origin, 'installed_destination': header['configured_install_destination'],
                        'availability': availability, 'scope': scope, 'owners': owners, 'foundation_owners': role['foundation_owners'],
                        'gap': gap, 'declaration_ids': ids,
                        'compiler': {'ast_exit_code': header['clang_exit_code'], 'preprocessor_exit_code': header['preprocess_exit_code'],
                                     'ast_sha256': header['ast_sha256'], 'preprocessed_sha256': header['preprocessed_sha256'],
                                     'translation_unit': header['translation_unit'], 'translation_unit_sha256': header['translation_unit_sha256']},
                        'conditional_directives': header['conditional_directives'], 'include_guard': header['include_guard'],
                        'macros': [macro_metadata(macro) for macro in header['macros']], 'scope_review': {'status': 'pending', 'reason': None},
                        'conditional_review': {'status': 'pending', 'reason': None}})
    # Meson installs two platform/gettext compatibility headers outside the
    # GNUNET_* namespace. Account for them explicitly instead of silently
    # treating their absence from a GNUNET-symbol filter as feature completion.
    for name in ('compat.h', 'gettext.h'):
        path = 'src/include/' + name
        headers.append({'id': name, 'origin': {'kind': 'tracked', 'path': path, 'sha256': sha(source / path)},
                        'installed_destination': 'include/gnunet/' + name, 'availability': 'unsupported_profile',
                        'scope': 'platform_equivalence_review', 'owners': ['util'], 'foundation_owners': [],
                        'gap': 'C platform/translation shim outside the GNUNET_* namespace; requires explicit Rust/native equivalence review, not function-count credit.',
                        'declaration_ids': [], 'compiler': None, 'conditional_directives': [], 'include_guard': None, 'macros': [],
                        'scope_review': {'status': 'pending', 'reason': None}, 'conditional_review': {'status': 'pending', 'reason': None}})
    functions = []
    for name, sites in sorted(grouped.items()):
        levels = {site['availability'] for site in sites}
        availability = 'validated' if 'validated' in levels else ('recovered' if 'recovered' in levels else 'unsupported_profile')
        scope = 'required' if any(site['scope'] == 'required' for site in sites) else sites[0]['scope']
        functions.append({'id': name, 'kind': 'function', 'declaration_ids': [site['id'] for site in sites],
                          'signatures': sorted({site['type'] for site in sites}), 'signature_review': 'pending',
                          'availability': availability, 'scope': scope, 'owners': sorted({owner for site in sites for owner in site['owners']}),
                          'foundation_owners': sorted({owner for site in sites for owner in site['foundation_owners']}),
                          'deprecated': any(site['deprecated'] for site in sites),
                          'status': 'in_progress' if name.startswith('GNUNET_STATISTICS_') else 'missing',
                          'rust_equivalence': [], 'required_criterion_ids': ['api.' + name] if scope == 'required' else [],
                          'test_commands': [], 'verification': None})
    surface_groups={}
    for site in declarations:
        if site['kind']=='FunctionDecl':continue
        category='callback' if site['kind']=='TypedefDecl' and site.get('callback') else ('constant' if site['kind']=='VarDecl' else 'type')
        ident='api-surface.'+category+'.'+site['kind']+'.'+site['name']
        surface_groups.setdefault(ident,[]).append(site)
    surfaces=[]
    for ident,sites in sorted(surface_groups.items()):
        levels={site['availability'] for site in sites}
        level='validated' if 'validated' in levels else ('recovered' if 'recovered' in levels else 'unsupported_profile')
        scope='required' if any(site['scope']=='required' for site in sites) else sites[0]['scope']
        surfaces.append({'id':ident,'kind':'declaration','declaration_ids':[site['id'] for site in sites],
                         'availability':level,'scope':scope,'owners':sorted({owner for site in sites for owner in site['owners']}),
                         'foundation_owners':sorted({owner for site in sites for owner in site['foundation_owners']}),
                         'status':'missing','rust_equivalence':[],'test_commands':[],'verification':None})
    for header in headers:
        for macro in header['macros']:
            if macro['name']==header['include_guard']:continue
            surfaces.append({'id':'api-surface.macro.'+header['id']+'.'+macro['name'],'kind':'macro',
                             'header':header['origin']['path'],'name':macro['name'],'definition':macro['definition'],'definition_sha256':macro['definition_sha256'],
                             'availability':header['availability'],'scope':header['scope'],'owners':header['owners'],
                             'foundation_owners':header['foundation_owners'],'status':'missing',
                             'rust_equivalence':[],'test_commands':[],'verification':None})
    header_names = {row['id']: row for row in headers}
    services = []
    for item in operations['subsystems']:
        ident = item['id']
        public_headers = [header_names[Path(path).name]['origin']['path'] for path in item['public_headers'] if Path(path).name != 'gnunet_op_lib.h']
        services.append({'id': ident, 'required': True, 'scope': item['scope_from_current_ledger'], 'public_headers': public_headers,
                         'function_ids': [entry['id'] for entry in functions if ident in entry['owners']],
                         'surface_ids':[entry['id'] for entry in surfaces if ident in entry['owners']],
                         'no_dedicated_public_api_reason': item['direct_public_api_reason'] if not public_headers else None,
                         'meson_targets': [{key: value for key, value in target.items() if key != 'artifacts'} for target in item['meson_targets']],
                         'production_translation_units': item['production_translation_units'],
                         'message_candidates': [{**message,'criterion_id':'wire-message.'+ident+'.'+message['name'].removeprefix('GNUNET_MESSAGE_TYPE_'),'review_status':'pending'} for message in item['wire_message_candidates']],
                         'operation_review': 'pending', 'behavior_cases': [], 'verified': False})
    units = [{key: item[key] for key in ('path', 'owner', 'targets', 'status', 'exit_code', 'source_sha256', 'preprocessed_sha256', 'references')} for item in operations['active_preprocessed_translation_units']]
    exports = [{**{key: item[key] for key in ('sha256', 'symbols', 'scope')}, 'library': Path(item['path']).name} for item in operations['actual_exported_libraries']]
    profile = {'id': 'gnunet-0.29.1-darwin-arm64-clang21', 'os': 'Darwin', 'architecture': 'arm64',
               'compiler_version': raw['compiler_version'], 'source_install_plan_sha256': raw['source_install_manifest_sha256'],
               'private_configuration': {'path': '@build/gnunet_private_config.h', 'sha256': sha(Path(raw['build']) / 'gnunet_private_config.h')},
               'availability_review': 'pending', 'required_additional_profiles': ['Linux/full supported dependency configuration', 'Conditional/optional API and backend profiles after explicit scope review'],
               'additional_profile_reviews':[{'id':'linux-full','status':'pending','reason':None},{'id':'conditional-and-backend-profiles','status':'pending','reason':None}],
               'missing_dependencies': ['PostgreSQL libpq headers: libpq-fe.h'],
               'method': 'Actual configured Meson install/compile graph; Clang JSON AST and preprocessor capture; util include marker enables isolated protected-header discovery. No production C FFI.'}
    source_inputs = {row['origin']['path']: row['origin']['sha256'] for row in headers if row['origin']['kind'] == 'tracked'}
    source_inputs.update({row['path']: row['source_sha256'] for row in units})
    for path in ('src/include/meson.build', 'src/include/gnunet_config.h.in', 'src/service/meson.build'):
        source_inputs[path] = sha(source / path)
    declaration_data = {'schema': 1, 'profile': profile, 'headers': sorted(headers, key=lambda x: x['id']),
                        'declarations': declarations, 'functions': functions, 'surfaces':surfaces,
                        'summary': {'header_entries': len(headers), 'compiler_header_captures': len(raw['headers']),
                                    'declaration_sites': len(declarations), 'function_declaration_sites': sum(row['kind'] == 'FunctionDecl' for row in declarations),
                                    'logical_functions': len(functions), 'nonfunction_surface_entries':len(surfaces), 'function_availability': dict(Counter(row['availability'] for row in functions)),
                                    'callback_declaration_sites': sum(row['kind'] == 'TypedefDecl' and row.get('callback', False) for row in declarations),
                                    'active_GNUNET_macro_definitions': sum(len(row['macros']) for row in headers),
                                    'deprecated_logical_functions': sum(row['deprecated'] for row in functions)}}
    operation_data = {'schema': 1, 'subsystems': services, 'translation_units': units, 'actual_library_exports': exports,
                      'source_inputs': [{'path': path, 'sha256': value} for path, value in sorted(source_inputs.items())],
                      'limitations': operations['limitations'], 'awards_implementation_or_verification_credit': False}
    output.mkdir(parents=True, exist_ok=True)
    save(output / 'declarations.json', declaration_data)
    save(output / 'operations.json', operation_data)
    catalog = {'schema': 1, 'baseline': {'tag': 'v0.29.1', 'commit': raw['baseline_revision'], 'repository': 'https://git.gnunet.org/gnunet.git'},
               'control_source_inputs':[{'path':path,'sha256':sha(source/path)} for path in ('src/include/meson.build','src/include/gnunet_config.h.in','src/service/meson.build')],
               'header_bindings':[{key:header[key] for key in ('id','scope','owners','foundation_owners','origin')} for header in sorted(headers,key=lambda item:item['id'])],
               'production_unit_bindings':[{key:unit[key] for key in ('path','owner','source_sha256','preprocessed_sha256')} for unit in units],
               'expected_owner_messages':{entry['id']:sorted(message['name'] for message in entry['message_candidates']) for entry in services},
               'required_subsystems': REQUIRED, 'expected_header_ids':sorted([Path(path).name for path in installed]+['gnunet_config.h']), 'profile_ids': [profile['id']],
               'policy': {'function_counts_are_feature_coverage': False, 'recovered_declarations_can_be_verified': False,
                          'deprecated_means_automatically_excluded': False, 'installed_means_automatically_active': False,
                          'no_public_header_means_no_required_behavior': False, 'evidence_validated_by': 'existing source/binary/log-bound GNUnet conformance evidence validator'},
               'files': [{'role': 'declarations', 'path': 'spec/gnunet/api/declarations.json', 'sha256': sha(output / 'declarations.json')},
                         {'role': 'operations', 'path': 'spec/gnunet/api/operations.json', 'sha256': sha(output / 'operations.json')}],
               'readiness': 'pending', 'full_gnunet_conformance_claim': False}
    save(output / 'catalog.json', catalog)
    print(json.dumps(declaration_data['summary']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'spec/gnunet/api')
    args = parser.parse_args()
    build(args.capture.resolve(), args.source.resolve(), args.output.resolve())


if __name__ == '__main__':
    main()
