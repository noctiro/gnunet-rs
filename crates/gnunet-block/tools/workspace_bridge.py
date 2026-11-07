"""Use the reviewed complete-workspace tool contract; no subset Cargo generation."""
import json
import os
from pathlib import Path
import sys
import types

BLOCK_PATH=Path('crates/gnunet-block')
TOOLS=Path(__file__).resolve().parent
_helper=None


def repository(package):
    path=Path(package).resolve()
    for parent in (path,*path.parents):
        manifest=parent/'Cargo.toml'
        if manifest.is_file()and '[workspace]'in manifest.read_text():
            if not(parent/'tests/embedded/noalloc/Cargo.toml').is_file():
                raise ValueError('actual full Root workspace/noalloc fixture required')
            if path!=(parent/BLOCK_PATH).resolve():
                raise ValueError('actual gnunet-block member path required')
            return parent
    raise ValueError('full workspace root not found')


def helper(explicit=None):
    global _helper
    selected=explicit or os.environ.get('BLOCK_WORKSPACE_HELPER')
    if selected is None:
        for parent in TOOLS.parents:
            path=parent/'crates/gnunet-tcp-communicator-core/tools/session_inputs.py'
            if path.is_file():selected=path;break
    if selected is None:raise ValueError('explicit reviewed workspace helper required for independent tools')
    path=Path(selected).resolve()
    if _helper is not None:
        if Path(_helper.__file__).resolve()!=path:raise ValueError('workspace helper changed within process')
        return _helper
    module=types.ModuleType('block_complete_workspace_helper');module.__file__=str(path)
    exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__)
    for name in('tree','same','workspace_contract','copy_workspace','Commands','disjoint_output'):
        if not hasattr(module,name):raise ValueError('reviewed complete workspace helper API absent: '+name)
    _helper=module
    return module


def inputs(package):
    root=repository(package);shared=helper()
    return{'complete_workspace':shared.tree(root),'actual_block_tools':shared.tree(TOOLS),
           'workspace_helper':{'path':str(Path(shared.__file__).resolve()),'sha256':shared.sha(shared.__file__)}}


def member(metadata,package):
    path=(Path(package)/'Cargo.toml').resolve()
    found=[p for p in metadata['packages']if p['name']=='gnunet-block'and p['source']is None
           and Path(p['manifest_path']).resolve()==path and p['id']in metadata['workspace_members']]
    if len(found)!=1:raise ValueError('unique actual BLOCK workspace member required')
    return found[0]


def fixture_root(metadata):
    root=metadata.get('resolve',{}).get('root')
    found=[p for p in metadata['packages']if p['id']==root and p['name']=='gnunet-noalloc-check']
    if len(found)!=1 or not Path(found[0]['manifest_path']).as_posix().endswith('/tests/embedded/noalloc/Cargo.toml'):
        raise ValueError('actual embedded/noalloc fixture graph required, not workspace feature union')
    return root


def examples(commands,workspace):
    output=commands.run('release-probes',['cargo','+1.99.1','build','--manifest-path',Path(workspace)/'Cargo.toml',
        '--locked','--offline','-p','gnunet-block','--release','--examples','--message-format=json','-j','1'])
    rows=[json.loads(line)for line in output.splitlines()if line.startswith(b'{')]
    finished=[r for r in rows if r.get('reason')=='build-finished']
    if len(finished)!=1 or finished[0].get('success')is not True:raise ValueError('successful actual Cargo artifact build required')
    result={}
    for name in('probe','vectors'):
        found=[r for r in rows if r.get('reason')=='compiler-artifact'and r['target']['name']==name
               and 'example'in r['target']['kind']and r.get('executable')
               and Path(r['manifest_path']).resolve()==(Path(workspace)/BLOCK_PATH/'Cargo.toml').resolve()]
        if len(found)!=1:raise ValueError('unique actual BLOCK Cargo artifact required: '+name)
        result[name]=commands.bind(found[0]['executable'])
    return result
