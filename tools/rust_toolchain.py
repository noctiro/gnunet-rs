"""Select the checked-out Rust toolchain for repository verification tools."""

from pathlib import Path
import re


_CHANNEL = r"[A-Za-z0-9_.][A-Za-z0-9_.-]*"


def rust_channel(repository, override=None):
    """Return the command-line Rustup channel, including an explicit override."""
    if override is not None:
        if re.fullmatch(_CHANNEL, override) is None:
            raise ValueError(f"invalid Rustup channel: {override!r}")
        return override
    manifest = Path(repository) / "rust-toolchain.toml"
    # The checked-in manifest uses a plain Rustup channel string. Read only
    # that field so reference tools also work with macOS's system Python 3.9.
    sections = re.split(r"(?m)^\s*\[([^\]\n]+)\][ \t]*(?:#.*)?$", manifest.read_text(encoding="utf-8"))
    channels = [
        value
        for name, body in zip(sections[1::2], sections[2::2])
        if name.strip() == "toolchain"
        for value in re.findall(r"(?m)^[ \t]*channel[ \t]*=[ \t]*(.*)$", body)
    ]
    match = re.fullmatch(r"""(["'])(""" + _CHANNEL + r""")\1[ \t]*(?:#.*)?""", channels[0]) if len(channels) == 1 else None
    if match is None:
        raise ValueError(f"expected one plain toolchain.channel in {manifest}")
    return match.group(2)
