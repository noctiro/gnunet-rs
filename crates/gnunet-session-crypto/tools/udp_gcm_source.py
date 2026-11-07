"""Exact pinned UDP communicator crypto functions; normal linked libraries only."""
import hashlib,json,re
from pathlib import Path
from udp_source import generate as key_profile,SOURCE,SHA256

def sha(data):return hashlib.sha256(data).hexdigest()
def body(text,pattern):
    matches=list(re.finditer(pattern,text,re.M))
    if len(matches)!=1:raise ValueError('ambiguous source component '+pattern)
    start=matches[0].start();brace=text.index('{',matches[0].end());end=brace+1;depth=1
    while depth:
        if text[end]=='{':depth+=1
        elif text[end]=='}':depth-=1
        end+=1
    if text[start:].startswith('struct '):
        if text[end]!=';':raise ValueError('missing original struct terminator')
        end+=1
    return text[start:end],text[:start].count('\n')+1

def generate(source,output):
    path=Path(source)/SOURCE;data=path.read_bytes()
    if sha(data)!=SHA256:raise ValueError('unreviewed UDP communicator source')
    text=data.decode();output=Path(output);output.mkdir(parents=True,exist_ok=False)
    key=key_profile(source,output/'key-profile')
    selected=[];pieces=['/* Exact AGPL-3.0-or-later GNUnet test components; no production C FFI. */','#include "key-profile/gnunet_udp_profile.h"']
    for name in ('InitialKX','UDPConfirmation','UDPAck','UDPBox','SharedSecret'):
        value,line=body(text,r'^struct '+name+r'\s*\n')
        pieces.append(value);selected.append({'kind':'struct','name':name,'line':line,'sha256':sha(value.encode())})
    pieces.append('static struct GNUNET_STATISTICS_Handle *stats; /* disabled NULL is an official legal no-op handle */')
    for name,return_type in (('get_kid','void'),('calculate_cmac','void'),('setup_cipher','void'),('try_decrypt','int')):
        value,line=body(text,r'^static '+return_type+r'\s*\n'+name+r'\s*\(')
        pieces.append(value);selected.append({'kind':'function','name':name,'line':line,'sha256':sha(value.encode())})
    header=output/'gnunet_udp_gcm_profile.h';header.write_text('\n\n'.join(pieces)+'\n')
    result={'kind':'exact-source-UDP-GCM-with-normal-gcrypt-util-statistics','source':str(path),'source_sha256':SHA256,'key_iv_component':key,'selected':selected,'generated':str(header),'generated_sha256':sha(header.read_bytes()),'whole_communicator_execution':False,'statistics_profile':'normal GNUNET_STATISTICS_update with legal disabled NULL handle; no shim/no service'}
    (output/'result.json').write_text(json.dumps(result,indent=2)+'\n');return result
