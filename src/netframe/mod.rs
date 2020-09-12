pub mod datalink;
pub mod internet;
pub mod transport;

pub struct UnknownFrame<'a> {
    type_id: u16,
    payload: &'a [u8],
}

impl<'a> UnknownFrame<'a> {
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
    pub fn from_u8_slice(payload: &'a [u8], type_id: u16) -> Self {
        Self { payload, type_id }
    }

    pub fn type_id(&self) -> u16 {
        self.type_id
    }
}


