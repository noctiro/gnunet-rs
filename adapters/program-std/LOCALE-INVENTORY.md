# Native locale work — current required source inventory

This inventory describes the native locale boundary and its source contracts.
[Native ownership](NATIVE-CONTRACT.md) defines the required locale lifetime rules.

Authoritative source candidates:

- Native boundary: [locale adapter](../native-std/src/locale.rs)
- Configuration: [configuration adapter](../config-std/README.md)
- PROGRAM: this package's `src/{locale,program,policy,logging}.rs`
- Composition: explicit configuration and native capabilities supplied by the caller

Native ABI is implemented for ordinary macOS and Linux GNU libc; execution
here is Darwin. Unknown libc/loader profiles return Unsupported.
SDK `<xlocale/_string.h>`, `_locale_posix2008.h`, `_types/_locale_t.h` and pinned
libc0.2.191 declarations are primary ABI inputs. `newlocale` NULL base creates new
ownership; `uselocale(NULL)` is a query; `duplocale` produces independent ownership.
NULL strings are never passed to strcasecmp/strncasecmp, even with zero length.
Empty spans and embedded-NUL prefixes are handled before bounded native calls.

| Pinned source readpoint | Required Rust treatment | State |
| --- | --- | --- |
| configuration.c455 find_section;728 find_entry | Selected C/snapshot/current-thread equality, stored spelling/list order intact | Implemented; normal switch/update/remove/duplicate proofs passed |
| 934/950/966 directive keyword comparison | Same selected native comparator, including Turkish I | Implemented; normal C/R proof passed |
| 1252..1271 PATHS serialization exclusions | Same comparator for section and excluded option names | Implemented; normal C/R proof passed |
| 2176 section iterator;2233 remove_section | Same comparator, first current matching section; no rehash/merge on locale selection | Implemented; normal C/R proof passed |
| 2612 choices; YES/NO through choices | Same native/C comparator for value/choice bytes | Implemented; normal C/R proof passed |
| 893/898 line trim;1043/1049/1052 key/value trim | Native unsigned-byte isspace, preserving source whitespace-only-line quirks | Implemented; normal full256 byte space/256×256 case tables passed |
| 940/956/974/991 directive argument space scan | Rust safely classifies unsigned bytes; C negative signed-char inputs are undefined and never executed | Exact source-only exclusion; ASCII/valid-domain cases still required |
| 2449 get_value_number sscanf `%llu%1s` | Snapshot-native decimal prefix + trailing native space; reject unrepresentable C scanf probes | Implemented via defined strtoull_l/current-thread strtoull; normal parse-number profiles passed |
| 2467/2501 float set/get | Source explicitly selects a C numeric locale with NULL base; do not infer comma acceptance from global locale | CurrentThread uses masked native locale + defined range preflight + typed scanf/snprintf; normal get/set/reset/thread proof passed |
| 2506 failed float scan | C returns before restoring prior thread locale; separate defined source quirk, not a claim that comma is valid | Owned per-thread TLS effect implemented and normal observed; late TLS error/exit independently Rust tested; no overflowing scanf |
| strings.c convert_with_table | strtoull + case-insensitive unit comparisons in selected locale; ASCII-space strtok delimiters | Implemented local profile; source-error unsafe relative wrapper remains excluded |
| configuration dollar expansion PATHS lookup | Shared selected context including recursion bookkeeping | Implemented; normal C/R proof passed |
| get_data Crockford aliases | Explicit source aliases and safe invalid-character rejection; no broad Unicode guesses | Existing source-derived implementation retained; invalid-negative-shift C exclusions unchanged |
| PROGRAM before main | cfg exists before locale.configure; attach explicit shared context, native installer publishes after selection | Implemented; config created before configure + shared duplicate context normal proof passed |
| common_logging get_type/rule levels | Same selected comparison context; parsed-once rules/cache retain original semantics | Implemented native comparer; normal PROGRAM/NLS/locale source profiles exercised |
| common_logging strtol line whitespace | Native selected unsigned-byte space class | Implemented; source returns early on strtol errno and negative narrowed int; native long-width non-native execution remains required |

`CaseContext` is explicit caller-owned mutable selection. Immutable snapshots do
not automatically track external setlocale/uselocale calls; the separately acquired
CurrentThread capability reads that calling thread at each synchronous source read
point under its documented foreign-mutator/lifetime contract. Configurations/duplicates/secret
children sharing that context observe later selection replacements without
rewriting names, values or order. Retained `CaseSnapshot` views keep independent
native ownership alive after replacement/context Drop. PROGRAM's native installer
owns/publishes one such context. Embedders can bind an existing context before
config creation/duplication to model one C caller's effective locale.

Current finite evidence:134 normal C/R profiles include context switching,
byte tables, trim/number, INLINE/SECRET/MATCHING, PATHS/dollar/choices, float get,
set and failed-scan thread effect/global reset. Five Rust native lifecycle tests
include independent snapshots after source thread exit and late TLS-destructor
failure. Three exact UI capability/privacy negatives plus a positive compile.
M13 composed checkpoint trial3 passed55 main tests/28 config tests-docs/15 normal,
source-NLS, native and UI components before the subsequent locale-fixed Regex
correction. Fresh full current-source proof is required after that correction.
Native source uses supported ordinary Darwin/glibc profile; other libc/OS
execution is not claimed. No status/count grants owner or whole-goal completion.
