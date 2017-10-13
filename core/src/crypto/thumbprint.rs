use opcua_types::ByteString;

/// The thumbprint holds a 20 byte representation of a certificate that can be used as a hash,
/// handshake comparison, a filename hint or similar purpose where a shortened representation
/// of a cert is required. Thumbprint size is dictated by the OPC UA spec
pub struct Thumbprint {
    /// Thumbprint is relatively small and fixed size, so use array to hold value instead of a vec
    /// just to save heap
    pub value: [u8; Thumbprint::THUMBPRINT_SIZE],
}

impl Into<ByteString> for Thumbprint {
    fn into(self) -> ByteString {
        ByteString::from(&self.value)
    }
}

impl Thumbprint {
    pub const THUMBPRINT_SIZE: usize = 20;

    /// Constructs a thumbprint from a message digest which is expected to be the proper length
    pub fn new(digest: &[u8]) -> Thumbprint {
        if digest.len() != Thumbprint::THUMBPRINT_SIZE {
            panic!("Thumbprint is not the right length");
        }
        let mut value: [u8; Thumbprint::THUMBPRINT_SIZE] = Default::default();
        value.clone_from_slice(digest);
        Thumbprint { value }
    }

    pub fn as_byte_string(&self) -> ByteString {
        ByteString::from(&self.value)
    }

    /// Returns the thumbprint as a string using hexdecimal values for each byte
    pub fn as_hex_string(&self) -> String {
        let mut hex_string = String::with_capacity(self.value.len() * 2);
        for b in self.value.iter() {
            hex_string.push_str(&format!("{:02x}", b))
        }
        hex_string
    }
}
