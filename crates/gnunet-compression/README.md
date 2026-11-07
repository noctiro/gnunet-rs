# Bounded compression

An independent complete-member zlib primitive extracted from the existing SETU
provider. Caller-owned reusable miniz compressor/inflater state writes into
explicitly bounded caller storage and rejects trailing or truncated members. The default feature allocates nothing; `alloc` enables that concrete state.

Protocol-specific compressed/uncompressed selection, exact output lengths,
retained memory accounting and original operation ownership remain with each
protocol. This package grants no SET/SETU wire or interoperability equivalence.
