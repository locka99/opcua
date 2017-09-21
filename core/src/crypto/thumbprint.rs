use opcua_types::ByteString;

/// Thumbprint size is dictated by the OPC UA spec

/// The thumbprint is a 20 byte representation of a certificate that can be used as a hash, a filename
/// or some other purpose.
pub struct Thumbprint {
    pub value: [u8; Thumbprint::THUMBPRINT_SIZE],
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
        // Add a bit of space in case caller intends to append a file extension
        let mut hex_string = String::with_capacity(self.value.len() * 2 + 8);
        for b in self.value.iter() {
            hex_string.push_str(&format!("{:02x}", b))
        }
        hex_string
    }
}
