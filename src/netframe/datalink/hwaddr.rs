use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;

use crate::clone_into_array;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct HwAddr([u8; 6]);

impl HwAddr {
    pub fn octets(&self) -> [u8; 6] {
        self.0
    }

    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xffu8; 6]
    }
}

impl FromStr for HwAddr {
    type Err = ParseIntError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut result = [0; 6];

        for (i, byte) in value.split(|c| c == ':' || c == '-').enumerate() {
            if i > 5 {
                u8::from_str_radix("error", 10)?;
            }

            result[i] = u8::from_str_radix(byte, 16)?;
        }

        Ok(HwAddr(result))
    }
}

impl From<[u8; 6]> for HwAddr {
    fn from(value: [u8; 6]) -> HwAddr {
        HwAddr(value)
    }
}

impl<'a> From<&'a [u8]> for HwAddr {
    fn from(value: &'a [u8]) -> HwAddr {
        HwAddr(clone_into_array(&value[0..=5]))
    }
}

impl fmt::Display for HwAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}
