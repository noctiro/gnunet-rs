"""Read the Android SDK profile for the shell builder and CI."""

import argparse
import re
from pathlib import Path


PROFILE = Path(__file__).resolve().parents[1] / "sdk-profile.properties"
SETTINGS = {
    "minSdk": r"[1-9][0-9]*",
    "compileSdk": r"[1-9][0-9]*",
    "buildTools": r"[0-9]+\.[0-9]+\.[0-9]+",
    "ndk": r"[0-9]+\.[0-9]+\.[0-9]+",
    "cmake": r"[0-9]+\.[0-9]+\.[0-9]+",
    "gradleVersion": r"[0-9]+(?:\.[0-9]+)+",
    "gradleSha256": r"[0-9a-f]{64}",
}


def read_profile(path=PROFILE):
    settings = {}
    targets = {}
    for line in path.read_text(encoding="ascii").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, sep, value = line.partition("=")
        if sep and name in SETTINGS and name not in settings and re.fullmatch(SETTINGS[name], value):
            settings[name] = value
            continue
        match = re.fullmatch(r"target\.([a-z0-9_-]+)", name)
        if sep and match and match[1] not in targets and re.fullmatch(r"[a-z0-9_-]+ [a-z0-9_-]+", value):
            targets[match[1]] = tuple(value.split())
            continue
        raise ValueError(f"invalid or duplicate Android SDK profile key: {name}")
    if missing := SETTINGS.keys() - settings.keys():
        raise ValueError(f"missing Android SDK profile keys: {', '.join(sorted(missing))}")
    rust_targets = {rust for rust, _ in targets.values()}
    if not targets or len(rust_targets) != len(targets):
        raise ValueError("expected at least one Android ABI and one Rust target per ABI")
    if int(settings["minSdk"]) > int(settings["compileSdk"]):
        raise ValueError("Android minimum SDK exceeds the compile SDK")
    return settings, targets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("projection", choices=("sdk-packages", "rust-targets", "build-plan"))
    args = parser.parse_args()
    try:
        settings, targets = read_profile()
    except (OSError, ValueError) as exc:
        parser.exit(1, f"{PROFILE}: {exc}\n")
    if args.projection == "sdk-packages":
        print(f"platforms;android-{settings['compileSdk']}")
        print(f"build-tools;{settings['buildTools']}")
        print(f"ndk;{settings['ndk']}")
        print(f"cmake;{settings['cmake']}")
    elif args.projection == "rust-targets":
        print(*(rust for rust, _ in targets.values()), sep="\n")
    else:
        keys = ("minSdk", "compileSdk", "buildTools", "ndk", "cmake", "gradleVersion", "gradleSha256")
        print(*(settings[name] for name in keys))
        for abi, (rust, ndk) in targets.items():
            print(abi, rust, ndk)


if __name__ == "__main__":
    main()
