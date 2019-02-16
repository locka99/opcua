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

## Cross-Compiling for armv7-unknown-linux-gnueabihf

These steps are derived from from sodiumoxide [readme](https://github.com/sodiumoxide/sodiumoxide):

1. Install dependencies and toolchain:

```
sudo apt update
sudo apt install build-essential gcc-arm-linux-gnueabihf libc6-armhf-cross libc6-dev-armhf-cross qemu-system-arm qemu-user-static -y
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

Derived from stackoverflow [answer](https://stackoverflow.com/questions/37375712/cross-compile-rust-openssl-for-raspberry-pi-2) and adapted to opcua:

```
cd /tmp

wget https://www.openssl.org/source/openssl-1.0.1t.tar.gz
tar xzf openssl-1.0.1t.tar.gz
export MACHINE=armv7
export ARCH=arm
export CC=arm-linux-gnueabihf-gcc
cd openssl-1.0.1t && ./config shared && make && cd -

cd /my/path/to/opcua
mkdir .cargo
cat > .cargo/config << EOF
[target.armv7-unknown-linux-gnueabihf]
linker = "arm-linux-gnueabihf-gcc"
EOF

export OPENSSL_LIB_DIR=/tmp/openssl-1.0.1t/
export OPENSSL_INCLUDE_DIR=/tmp/openssl-1.0.1t/include
export OPENSSL_STATIC=1

cargo build --target armv7-unknown-linux-gnueabihf
```

Note `OPENSSL_STATIC=1`, causes rust-openssl to be statically linked to it which saves you having to copy the 
shared lib. 

And then:

```
export QEMU_LD_PREFIX=/usr/arm-linux-gnueabihf
cd samples/simple-client
qemu-arm-static ../../target/armv7-unknown-linux-gnueabihf/debug/opcua-simple-client
```
