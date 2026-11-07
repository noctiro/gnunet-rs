#!/usr/bin/env python3
"""Comparator controls only; stored fixtures are not fresh C acceptance evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
from comparison import compare


def controls(c, rust):
    assert compare(c, rust)['equal_common_rows'] == 58
    mutations = [c.replace('io|partial|0|3|', 'io|partial|0|4|', 1),
                 c.replace('backoff|0|1000|1000\n', '', 1),
                 c.replace('io|zero|1|0|0|1|2|1|0|0', 'io|zero|1|0|0|1|2|2|0|0', 1),
                 c.replace('io|fatal|0|0|1|0|0|0|0|1', 'io|fatal|0|0|0|1|1|1|0|1', 1),
                 c.replace('clock-overflow|5000|18446744073709551615', 'clock-overflow|5000|18446744073709551614', 1)]
    for mutation in mutations:
        assert mutation != c
        try:
            compare(mutation, rust)
        except AssertionError:
            continue
        raise AssertionError('altered semantic trace accepted')
    return {'status': 'passed', 'positive_control': 1, 'rejected_mutations': len(mutations)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c-trace', type=Path)
    parser.add_argument('--rust-output', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if bool(args.c_trace) != bool(args.rust_output):
        parser.error('both trace inputs must be specified together')
    root = Path(__file__).resolve().parent
    c = args.c_trace or root/'testdata/comparator-c.trace'
    rust = args.rust_output or root/'testdata/comparator-rust.trace'
    result = controls(c.read_text(), rust.read_text())
    result['input_kind'] = 'caller supplied traces' if args.c_trace else 'stored comparator fixtures; no fresh conformance claim'
    result['inputs'] = {str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest() for path in [c, rust]}
    text = json.dumps(result, indent=2)+'\n'
    if args.output:
        args.output.write_text(text)
    print(text, end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
