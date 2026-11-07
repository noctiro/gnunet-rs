# Independent normal-C mechanism vectors

Unmodified GNUnet v0.29.1 commit346358e26d4dcc2dc4f51bef5d52dca29c7d8165 public libgnunetutil produced peer SHA512/Bloom bits and EdDSA purpose6 signatures. Official DHT declarations produced local IPC bytes. The exact original GNUNET_DHT_verify_path function was separately extracted and linked to that library: valid chain0, tampered first signature1, explicit verified suffix0. This is one algorithm extraction and normal public primitive execution, not an DHT daemon, native host, routing or multi-hop interoperability proof.

Stored vectors cover the component operations described above. Their original
producer receipt is not distributed here and cannot establish current-source
interop or routing acceptance. Fresh results belong under `target/`.

Test-only deterministic signing seeds are bytes01,02,03 repeated32. Payload excludes C string terminator. Recipient is bytes04 repeated32. Expiration is0102030405060708 in network byte order. Paths contain signature64 + recorded signer32. Local request IDs remain copied opaque bytes8001fe03dc05ba07, without native/network numeric conversion.
