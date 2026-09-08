
pub type PEMDER = (&'static str, &'static [u8]);

/// Private key and certificate usually used for the client
pub const ALICE_CERTIFICATE: PEMDER = (
    include_str!  ("./assets/alice_cert.pem"),
    include_bytes!("./assets/alice_cert.der")
);

pub const ALICE_PRIVATE_KEY: PEMDER = (
    include_str!  ("./assets/alice_key.pem"),
    include_bytes!("./assets/alice_key.der")
);

/// Private key and certificate usually used for the server
pub const BOB_CERTIFICATE: PEMDER = (
    include_str!  ("./assets/bob_cert.pem"),
    include_bytes!("./assets/bob_cert.der")
);

pub const BOB_PRIVATE_KEY: PEMDER = (
    include_str!  ("./assets/bob_key.pem"),
    include_bytes!("./assets/bob_key.der")
);

/// Private key and certificate usually used by the fuzzer as a client
pub const MALLORY_CERTIFICATE: PEMDER = (
    include_str!  ("./assets/mallory_cert.pem"),
    include_bytes!("./assets/mallory_cert.der")
);

pub const MALLORY_PRIVATE_KEY: PEMDER = (
    include_str!  ("./assets/mallory_key.pem"),
    include_bytes!("./assets/mallory_key.der")
);

/// Private key and certificate usually used by the fuzzer as a server
pub const OSCAR_CERTIFICATE: PEMDER = (
    include_str!  ("./assets/oscar_cert.pem"),
    include_bytes!("./assets/oscar_cert.der")
);

pub const OSCAR_PRIVATE_KEY: PEMDER = (
    include_str!  ("./assets/oscar_key.pem"),
    include_bytes!("./assets/oscar_key.der")
);