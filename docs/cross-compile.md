# Cross-compiling OPC UA for Rust

## Credit

These notes are derived from the following sources 

1. Install cross-compile utilities as shown [here](https://github.com/sodiumoxide/sodiumoxide)
2. Follow malbarbo's answer [here](https://stackoverflow.com/questions/37375712/cross-compile-rust-openssl-for-raspberry-pi-2)

## Intro

The [bug](https://github.com/locka99/opcua/issues/24) was raised asking how to 
cross-compile OPC UA for Rust and someone kindly answered with references. The links above were
derived into a known working solution.

Raspberry Pi is the target architecture and I used Linux Subsystem for Windows with Debian to work
through the steps.

## Install toolchain for ARM7

These steps are derived from from sodiumoxide [readme](https://github.com/sodiumoxide/sodiumoxide):

### Install cross-compiler packages:

Debian has convenient packages for cross compilation and emulation.

```
sudo apt update
sudo apt install build-essential gcc-arm-linux-gnueabihf libc6-armhf-cross libc6-dev-armhf-cross qemu-system-arm qemu-user-static -y
```

## Download and build OpenSSL

Derived from stackoverflow [answer](https://stackoverflow.com/questions/37375712/cross-compile-rust-openssl-for-raspberry-pi-2) and adapted to opcua:

```
cd /tmp

wget https://www.openssl.org/source/openssl-1.0.1t.tar.gz
tar xzf openssl-1.0.1t.tar.gz
export MACHINE=armv7
export ARCH=arm
export CC=arm-linux-gnueabihf-gcc
cd openssl-1.0.1t && ./config shared && make && cd -
```

## Build OPC UA for Rust

### Add cross compiler to Rust

The `rustup` tool allows us to add another target to the Rust toolchain.

```
rustup target add armv7-unknown-linux-gnueabihf
```

### Add target to OPC UA for Rust

With the compiler ready, we move onto the project and set up the target.

```
cd /my/path/to/opcua
mkdir .cargo
cat > .cargo/config << EOF
[target.armv7-unknown-linux-gnueabihf]
linker = "arm-linux-gnueabihf-gcc"
EOF
```

You now have the following in a `opcua/.cargo/config` file:

```
[target.armv7-unknown-linux-gnueabihf]
linker = "arm-linux-gnueabihf-gcc"
```

### Build

Building is straightforward and just requires we specify where OpenSSL was built before invoking `cargo` with the 
correct build target.

```
export OPENSSL_LIB_DIR=/tmp/openssl-1.0.1t/
export OPENSSL_INCLUDE_DIR=/tmp/openssl-1.0.1t/include
export OPENSSL_STATIC=1
cargo build --target armv7-unknown-linux-gnueabihf
```

Note `OPENSSL_STATIC=1`, causes `rust-openssl` to link to OpenSSL's static library which saves a
little effort in the next step. Alternatively you can copy the `libcrypto.so`, `libcrypto.so.1.0.0`, `libssl.so` and 
`libssl.so.1.0.0` from `$OPENSSL_LIB_DIR` into `$QEMU_LD_PREFIX/lib` below.

## Run

Qemu can run Arm binaries from your host environment with a `qemu-arm-static` command - convenient! 
So now we can test if our build has worked:


```
export QEMU_LD_PREFIX=/usr/arm-linux-gnueabihf
cd samples/simple-client
qemu-arm-static ../../target/armv7-unknown-linux-gnueabihf/debug/opcua-simple-client
```
