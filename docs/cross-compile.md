# Cross-compiling OPC UA for Rust

IMPORTANT - These notes cut and pasted from the sources below. They have not been tested.

A [bug](https://github.com/locka99/opcua/issues/24) was raised asking how to 
cross-compile OPC UA for Rust and someone kindly answered with references to the following
links:

Raspberry Pi is the target architecture.

1. Install cross-compile utilities as shown [here](https://github.com/sodiumoxide/sodiumoxide)
2. Follow malbarbo's answer [here](https://stackoverflow.com/questions/37375712/cross-compile-rust-openssl-for-raspberry-pi-2)

Below is the pertinent information extracted from these links:

## Cross-Compiling for armv7-unknown-linux-gnueabihf

(from sodiumoxide readme)

1. Install dependencies and toolchain:

```
sudo apt update
sudo apt install build-essential gcc-arm-linux-gnueabihf libc6-armhf-cross libc6-dev-armhf-cross -y
rustup target add armv7-unknown-linux-gnueabihf
```

2. Add the following to a .cargo/config file:

```
[target.armv7-unknown-linux-gnueabihf]
linker = "arm-linux-gnueabihf-gcc"
```

3. Build by running:

```
cargo build --release --target armv7-unknown-linux-gnueabihf
```


## Download and build OpenSSL

Take from stackoverflow answer:

```
cd /tmp

wget https://www.openssl.org/source/openssl-1.0.1t.tar.gz
tar xzf openssl-1.0.1t.tar.gz
export MACHINE=armv7
export ARCH=arm
export CC=arm-linux-gnueabihf-gcc
cd openssl-1.0.1t && ./config shared && make && cd -

export OPENSSL_LIB_DIR=/tmp/openssl-1.0.1t/
export OPENSSL_INCLUDE_DIR=/tmp/openssl-1.0.1t/include
cargo new xx --bin
cd xx
mkdir .cargo
cat > .cargo/config << EOF
[target.armv7-unknown-linux-gnueabihf]
linker = "arm-linux-gnueabihf-gcc"
EOF

cat > src/main.rs << EOF
extern crate openssl;

fn main() {
    println!("{}", openssl::version::version())
}
EOF

cargo add openssl # requires cargo install cargo-add
cargo build --target armv7-unknown-linux-gnueabihf
```