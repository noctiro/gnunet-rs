"""Pinned UDP key/IV source component, not a complete communicator oracle."""
import hashlib
import json
from pathlib import Path
import re

SOURCE = 'src/service/transport/gnunet-communicator-udp.c'
SHA256 = '2e8b3085910489bcd5ce81994133ce5fee89c3b8cf37065f09efec9a61f43cd7'


def generate(source, output):
    path = Path(source) / SOURCE
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('unreviewed UDP communicator source')
    text = data.decode()
    macros = []
    for name in ('AES_KEY_SIZE', 'AES_IV_SIZE', 'GCM_TAG_SIZE'):
        matches = re.findall(r'^#define ' + name + r'[^\n]*$', text, re.M)
        if len(matches) != 1:
            raise ValueError('ambiguous UDP source macro ' + name)
        macros.append(matches[0])
    name = text.index('\nget_iv_key (')
    start = text.rfind('static void', 0, name)
    brace = text.index('{', name)
    end, depth = brace + 1, 1
    while depth:
        if text[end] == '{':
            depth += 1
        elif text[end] == '}':
            depth -= 1
        end += 1
    body = text[start:end]
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    header = output / 'gnunet_udp_profile.h'
    header.write_text('/* Test-only original GNUnet AGPL-3.0-or-later source component. */\n'
                      + '\n'.join(macros) + '\n' + body + '\n')
    receipt = {
        'kind': 'exact-source-get_iv_key-with-normal-utility-library',
        'source': str(path), 'source_sha256': SHA256,
        'macros': macros,
        'function_body_sha256': hashlib.sha256(body.encode()).hexdigest(),
        'generated': str(header),
        'generated_sha256': hashlib.sha256(header.read_bytes()).hexdigest(),
        'whole_communicator_execution': False,
    }
    (output / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt
