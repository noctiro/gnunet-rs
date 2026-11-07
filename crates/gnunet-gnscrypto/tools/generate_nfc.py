#!/usr/bin/env python3
"""Reproduce only Unicode 18 canonical NFC tables and official test vectors.

Download the three pinned inputs from https://www.unicode.org/Public/18.0.0/ucd/
then run: python3 tools/generate_nfc.py /path/to/ucd
No network or third-party Python module is used by this generator.
"""
import hashlib
import pathlib
import struct
import sys

PINS = {
    'UnicodeData.txt': '0736451de439ae7baf1425136617da495e09ee5afbe6e394374db7009ea08950',
    'DerivedNormalizationProps.txt': '98ac7f67d985fe781e317f6182e885e94cabb0c314769e6dd73e48b226931ccd',
    'NormalizationTest.txt': '25a50d816764b04abfb4a646d3eb2b2a803284c3873d9a06757b94fe4513dde3',
}

def main():
    data = pathlib.Path(sys.argv[1])
    root = pathlib.Path(__file__).resolve().parent.parent
    texts = {}
    for name, digest in PINS.items():
        raw = (data / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise SystemExit('source hash mismatch: ' + name)
        texts[name] = raw.decode('utf-8')
    ccc, direct, excluded = {}, {}, set()
    for line in texts['UnicodeData.txt'].splitlines():
        fields = line.split(';')
        cp = int(fields[0], 16)
        if int(fields[3]):
            ccc[cp] = int(fields[3])
        if fields[5] and not fields[5].startswith('<'):
            direct[cp] = tuple(int(x, 16) for x in fields[5].split())
    for line in texts['DerivedNormalizationProps.txt'].splitlines():
        line = line.split('#')[0].strip()
        if not line:
            continue
        fields = [v.strip() for v in line.split(';')]
        if fields[1] != 'Full_Composition_Exclusion':
            continue
        bounds = fields[0].split('..')
        excluded.update(range(int(bounds[0], 16), int(bounds[-1], 16) + 1))
    def decomposition(cp):
        return tuple(v for x in direct[cp] for v in decomposition(x)) if cp in direct else (cp,)
    flat, entries = [], []
    for cp in sorted(direct):
        seq = decomposition(cp)
        entries.append((cp, len(flat), len(seq)))
        flat.extend(seq)
    compose = sorted(((a << 21) | b, cp) for cp, seq in direct.items()
                     if cp not in excluded and len(seq) == 2 for a, b in [seq])
    lines = ['//! Generated Unicode 18.0.0 canonical NFC data. DO NOT EDIT.',
             '//! Source/license/reproduction: ../UPSTREAM.md and tools/generate_nfc.py.',
             '#[rustfmt::skip]', 'pub(super) const CCC: &[(u32, u8)] = &[']
    lines += [f'    (0x{cp:x}, {v}),' for cp, v in sorted(ccc.items())]
    lines += ['];', '#[rustfmt::skip]', 'pub(super) const DECOMP: &[(u32, u16, u8)] = &[']
    lines += [f'    (0x{cp:x}, {start}, {n}),' for cp, start, n in entries]
    lines += ['];', '#[rustfmt::skip]', 'pub(super) const DECOMP_CHARS: &[u32] = &[']
    lines += ['    ' + ', '.join(f'0x{cp:x}' for cp in flat[i:i + 12]) + ',' for i in range(0, len(flat), 12)]
    lines += ['];', '#[rustfmt::skip]', 'pub(super) const COMPOSE: &[(u64, u32)] = &[']
    lines += [f'    (0x{pair:x}, 0x{cp:x}),' for pair, cp in compose]
    lines += ['];', '']
    (root / 'src/nfc_data.rs').write_text('\n'.join(lines))
    corpus = bytearray()
    count = 0
    for line in texts['NormalizationTest.txt'].splitlines():
        line = line.split('#')[0].strip()
        if not line or line.startswith('@'):
            continue
        strings = [''.join(chr(int(x, 16)) for x in field.split()).encode() for field in line.split(';')[:5]]
        for value in strings:
            corpus += struct.pack('>H', len(value)) + value
        count += 1
    (root / 'tests/fixtures/normalization-18.bin').write_bytes(corpus)
    print(f'ccc={len(ccc)} decompositions={len(entries)} compositions={len(compose)} conformance_rows={count}')

if __name__ == '__main__':
    main()
