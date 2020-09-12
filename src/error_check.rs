pub fn checksum8(data: &[u8]) -> u8 {
    let mut sum: u16 = 0;
    for &n in data {
        sum += u16::from(n);
    }
    while sum >> 8 != 0 {
        sum = (sum & 0x00ff) + (sum >> 8);
    }

    (!sum) as u8
}

pub fn u16_slice_to_sum16(slice: &[u16]) -> u16 {
    let sum = slice.iter().fold(0u64, |acc, &i| acc + (i as u64));

    let carry_add =
        (sum & 0xffff) + ((sum >> 16) & 0xffff) + ((sum >> 32) & 0xffff) + ((sum >> 48) & 0xffff);
    ((carry_add & 0xffff) + (carry_add >> 16)) as u16
}

pub fn u8_slice_to_sum16(slice: &[u8]) -> u16 {
    let mut sum = (0..slice.len() / 2 * 2).step_by(2).fold(0u64, |acc, i| {
        acc + u64::from_be_bytes([0, 0, 0, 0, 0, 0, slice[i], slice[i + 1]])
    });

    if slice.len() & 1 != 0 {
        sum += (slice[slice.len() - 1] as u64) << 8;
    }

    let carry_add =
        (sum & 0xffff) + ((sum >> 16) & 0xffff) + ((sum >> 32) & 0xffff) + ((sum >> 48) & 0xffff);
    ((carry_add & 0xffff) + (carry_add >> 16)) as u16
}

pub fn u16_checksum16(slice: &[u16]) -> u16 {
    !u16_slice_to_sum16(slice)
}

pub fn u8_checksum16(slice: &[u8]) -> u16 {
    !u8_slice_to_sum16(slice)
}
