"""Read the current upstream identity selected by the compatibility policy."""

import json
from pathlib import Path
import re


POLICY = Path(__file__).resolve().parents[1] / "spec/gnunet/compatibility-policy.json"


def reference_target(path=POLICY):
    """Return the validated release tag and commit of the active reference."""
    target = json.loads(path.read_text(encoding="utf-8"))["reference_target"]
    release, revision = target["release"], target["revision"]
    if not isinstance(release, str) or re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", release) is None:
        raise ValueError("expected a GNUnet release tag in the compatibility policy")
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("expected an exact Git commit in the compatibility policy")
    return release, revision
