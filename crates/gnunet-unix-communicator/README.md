# UNIX testing communicator wire

Default noalloc packet/address codec for the installed v0.29.1 testing-only UNIX communicator. Canonical producer emits a 36-byte outer header with zero type, claimed public sender and one complete GNUnet frame. Consumer retains ignored type and trailing bytes like the official consumer. This provides no sender authentication.

The inner MTU is the minimum of the independent Unix datagram and standard TRANSPORT Incoming envelopes: 65447 on the 65535-byte profile, 2012 on the Darwin 2048-byte profile. Capacity/invalid input leaves output unchanged. No socket, crypto or interoperability qualification is claimed.
