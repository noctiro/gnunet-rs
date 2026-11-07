# TRANSPORT node

`gnunet-transport-node -c official.conf --state-directory NEW_RUST_STATE` runs
the Rust TRANSPORT and companion public PEERSTORE composition. It connects to
the configured PILS service and uses asynchronous signing. `--local-pils-key`
explicitly enables matching against the existing configured peer private root;
service mode does not read that root. It does not start the other node services.

`[PILS] PROFILE` selects the identity client and local managed HELLO policy
before storage or socket setup. The default is `reference029`; `deterministic`
selects the official conditional address-derived identity. Their aliases are
`reference-0.29.1` and `reference-deterministic`. The optional existing
`[transport-rust] PILS_PROFILE` must agree. `lsd0014-text` remains an explicit
published textual profile without official interoperability qualification.

`[transport-rust] HELLO_PROFILE` independently selects remote HELLO discovery
verification; absent an override it follows the selected identity profile's HELLO
policy. A remote discovery choice does not change local key derivation. Managed
snapshot reopening uses the selected local policy and rejects a mismatched
signature. Public records are retained as public values rather than being
implicitly promoted to managed records. The Rust snapshot format, original
writer fence, unknown transaction ownership and identity-epoch retirement
behavior remain the same. See [the runtime](../../adapters/transport-runtime-std/README.md)
for its bounded lifecycle and component evidence scope.
