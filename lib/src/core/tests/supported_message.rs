use crate::core::supported_message::SupportedMessage;

#[test]
fn size() {
    // This test just gets the byte size of SupportedMessage to ensure it isn't too big
    use std::mem;
    let size = mem::size_of::<SupportedMessage>();
    println!("SupportedMessage size = {}", size);
    assert!(size <= 16);
}
