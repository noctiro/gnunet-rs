#!/usr/bin/env python3
"""Check ordinary Ed25519 purpose-region vectors with independent OpenSSL."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

PIN = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165"
SOURCE = "src/lib/util/crypto_ecc.c"
SOURCE_SHA256 = "8b7124466b75768125c028c63d51c4892c35aff5c2b6bc560b120a90659d6273"


def run(*argv):
    return subprocess.check_output(argv, stderr=subprocess.STDOUT, timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    source = args.source.resolve()
    assert run("git", "-C", str(source), "rev-parse", "HEAD").decode().strip() == PIN
    assert hashlib.sha256((source / SOURCE).read_bytes()).hexdigest() == SOURCE_SHA256
    # This is the official HELLO purpose's complete 80-byte signed region:
    # size_be32 || purpose_be32 || expiry_be64 || address_hash64. The bytes are
    # deliberately public fixture data; the test does not authenticate a contact.
    region = bytes.fromhex("00000050000000070102030405060708") + bytes(range(128, 192))
    seed = bytes(range(32))
    with tempfile.TemporaryDirectory(prefix="gnunet-eddsa-openssl-") as work:
        work = Path(work)
        # RFC 8410 PKCS#8 contains the same 32-byte Ed25519 seed as the C API.
        (work / "key.der").write_bytes(bytes.fromhex("302e020100300506032b657004220420") + seed)
        (work / "region.bin").write_bytes(region)
        public_der = run("openssl", "pkey", "-in", str(work / "key.der"), "-inform", "DER", "-pubout", "-outform", "DER")
        assert public_der[:12] == bytes.fromhex("302a300506032b6570032100")
        public = public_der[12:]
        assert len(public) == 32
        signature = run("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(work / "key.der"), "-keyform", "DER", "-in", str(work / "region.bin"))
        assert len(signature) == 64
        (work / "public.der").write_bytes(public_der)
        (work / "signature.bin").write_bytes(signature)
        run("openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(work / "public.der"), "-keyform", "DER", "-in", str(work / "region.bin"), "-sigfile", str(work / "signature.bin"))
    fixtures = Path(__file__).parent / "fixtures"
    values = {"peer-public.bin": public, "peer-purpose.bin": region, "peer-purpose.sig": signature}
    for name, data in values.items():
        path = fixtures / name
        if args.write:
            fixtures.mkdir(exist_ok=True)
            path.write_bytes(data)
        else:
            assert path.read_bytes() == data, name
    provenance = {
        "upstream_commit": PIN,
        "source": {"path": SOURCE, "sha256": SOURCE_SHA256},
        "generator": "OpenSSL ordinary Ed25519 pkeyutl -sign -rawin; seed bytes 00..1f",
        "openssl_version": run("openssl", "version").decode().strip(),
        "fixture_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in values.items()},
        "scope": "Independent primitive and purpose-region representation vectors; no C daemon, GNS suite, CORE or communicator claim.",
    }
    if args.write:
        (fixtures / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    else:
        recorded = json.loads((fixtures / "provenance.json").read_text())
        for field in ["upstream_commit", "source", "generator", "fixture_sha256", "scope"]:
            assert recorded[field] == provenance[field], field
    print("OpenSSL Ed25519 oracle: public key, 80-byte official purpose region and signature matched")


if __name__ == "__main__":
    main()
