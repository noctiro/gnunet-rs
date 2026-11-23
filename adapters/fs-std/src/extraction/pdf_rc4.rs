//! RC4 transforms for existing PDF document and CMS ciphertext.

use zeroize::Zeroizing;

pub(super) fn apply(data: &mut [u8], key: &[u8]) {
    let mut permutation = Zeroizing::new([0; 256]);
    for (slot, value) in permutation.iter_mut().zip(0..=u8::MAX) {
        *slot = value;
    }
    let mut right = 0_u8;
    for (left, &key_byte) in (0..=u8::MAX).zip(key.iter().cycle()) {
        right = right
            .wrapping_add(permutation[usize::from(left)])
            .wrapping_add(key_byte);
        permutation.swap(usize::from(left), usize::from(right));
    }

    let mut left = 0_u8;
    right = 0;
    for byte in data {
        left = left.wrapping_add(1);
        right = right.wrapping_add(permutation[usize::from(left)]);
        permutation.swap(usize::from(left), usize::from(right));
        let index = permutation[usize::from(left)].wrapping_add(permutation[usize::from(right)]);
        *byte ^= permutation[usize::from(index)];
    }
}
