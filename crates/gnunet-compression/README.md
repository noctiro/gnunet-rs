# Bounded compression

Complete-member zlib for protocol owners such as SETU. Callers provide input
and output storage. Both backends reject trailing bytes, truncated members and
invalid checksums.

## Backends

- `fixed-zlib` provides `FixedZlib::new()` for allocation-free workspace. Its
  encoder uses fixed Huffman blocks and a 32 KiB DEFLATE history window.
- `alloc` provides `Zlib::new()` with the reusable miniz compressor.

Both types expose `compress(input, output)` and `decompress(input, output)`,
returning the exact number of output bytes. Treat output as usable only after
success. The protocol owner chooses the output size and decides whether to
send the compressed member.
