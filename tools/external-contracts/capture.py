#!/usr/bin/env python3
"""Capture a discovery proposal into a new file; never update reviewed locks."""
import argparse
import json
from pathlib import Path

from scan import discover


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--node-path", type=Path, default=Path(__file__).resolve().parents[2] / "spec/gnunet/external/node-path.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    node = json.loads(args.node_path.read_text())
    proposal = discover(args.source, node["input_files"])
    with args.output.open("x", encoding="utf-8") as output:
        output.write(json.dumps(proposal, indent=2) + "\n")
    print("Discovery proposal captured; review semantic requirements and old/new delta. No lock or conformance status was updated.")


if __name__ == "__main__":
    main()
