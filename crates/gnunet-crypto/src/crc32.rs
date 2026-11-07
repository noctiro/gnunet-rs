//! Shared exact GNUnet CRC32 byte primitive; no allocation or native ABI.
const fn crc_table() -> [u32; 256] {
    let mut table = [0; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 != 0 {
                (value >> 1) ^ 0xedb8_8320
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
}
const CRC: [u32; 256] = crc_table();
/// Exact preset/inverted CRC32 used by `GNUNET_CRYPTO_crc32_n`.
/// This is an unauthenticated checksum, not a cryptographic identity or MAC.
#[must_use]
pub fn crc32_n(input: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in input {
        crc = (crc >> 8) ^ CRC[((crc ^ u32::from(*byte)) & 255) as usize];
    }
    !crc
}
