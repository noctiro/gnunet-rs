# Selected official C build

`conversation_build.py` builds the unchanged v0.29.1 Conversation dependency graph
from existing tools/dependencies. `conversation_build_stage.py` stages its actual
runtime closure. This builder does not download dependencies, patch C source,
perform a system install or run GNUnet services/audio helpers.

```sh
python3 tools/reference/conversation_build.py \
  --request /path/to/build-request.json \
  --approval /path/to/build-approval.json \
  --output /tmp/fresh-conversation-build
```

## Request

The request binds the official source/handbook revisions, exact tool paths/hashes,
input receipts, read-only dependency roots, library/pkg-config directories and
reviewed compiler environment. `jobs` is 1..16; `build_seconds` is finite and
applies to the whole build. The approval input binds the request, builder sources,
allowed effects and expiry. The script validates these inputs before execution.

Only the fresh output is writable. Git uses local objects without network fetch,
hooks or global configuration. Meson uses `--wrap-mode=nodownload`, a private
prefix, disabled autostart and the declared normal targets. Compiler-generated
configuration probes may execute; GNUnet products are not launched.

## Products and staging

Selected targets are the Conversation/GNS backbone services and clients, TCP
communicator and required SQLite/block/record plugins. The unchanged Meson graph
builds linked libraries. Missing targets or unavailable Conversation backends
fail rather than creating substitute artifacts.

Staging reads Meson's installed-target metadata and the real Mach-O/ELF linked
closure. It copies verified artifacts, sonames/plugins and generated defaults
into the private prefix/dependency tree. No linked binary is rewritten.

The result retains command exits/reaping, logs, source cleanliness, build inputs,
artifact hashes, dependency closure and defaults. The normal build index feeds
the [runtime controller](conversation-controller.README.md). A successful build
is distinct from loader, service or peer qualification.
