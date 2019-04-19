use crate::supported_message::SupportedMessage;

#[test]
fn size() {
    // Test that the SupportedMessage size isn't huge
    use std::mem;
    let size = mem::size_of::<SupportedMessage>();
    println!("SupportedMessage size = {}", size);
    assert!(size <= 16);
}
