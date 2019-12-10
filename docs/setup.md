This is the in-depth documentation about the OPC UA implementation in Rust.

# Setup

OPC UA for Rust generally requires the most recent stable version of Rust to compile. 
The recommendation is to install [rustup](https://rustup.rs/) to manage your toolchain and keep it 
up to date.

## Windows

Rust supports two compiler backends - gcc or MSVC. The preferred way to build OPC UA is with gcc and MSYS2 but you can
also use Microsoft Visual Studio 201x if you manually install OpenSSL.

### MSYS2

MSYS2 is a Unix style build environment for Windows.

1. Install [MSYS2 64-bit](http://www.msys2.org/)
2. Update all the packages `pacman -Syuu`
3. `pacman -S gcc mingw-w64-x86_64-gcc mingw-w64-x86_64-gdb mingw-w64-x86_64-pkg-config openssl openssl-devel pkg-config`
4. Use rustup to install the `stable-x86_64-pc-windows-gnu` toolchain during setup or by typing `rustup toolchain install stable-x86_64-pc-windows-gnu` from the command line.

You should use the MSYS2/MingW64 Shell. You may have to tweak your .bashrc to ensure that the `bin/` folders for both Rust and 
MinGW64 binaries are on your `PATH`. 

### Visual Studio

1. Install [Microsoft Visual Studio](https://visualstudio.microsoft.com/). You must install C++ and 64-bit platform support.
2. Use rustup to install the `install stable-x86_64-pc-windows-msvc` during setup or by typing `rustup toolchain install stable-x86_64-pc-windows-msvc` from the command line.
3. Download and install OpenSSL 64-bit binaries, e.g. from https://slproweb.com/products/Win32OpenSSL.html
4. Set an environment variable `OPENSSL_DIR` to point to the installation location, e.g. `C:\OpenSSL-Win64`

Also ensure that `%OPENSSL_DIR%\bin` is on your `PATH`.

```
set PATH=%PATH%;%OPENSSL_DIR%\bin
```

32-bit builds should also work by using the 32-bit toolchain and OpenSSL.

## Linux

These instructions apply for `apt-get` but if you use DNF on a RedHat / Fedora system then substitute the equivalent packages
and syntax using `dnf`. 

1. Install gcc and OpenSSL development libs & headers, e.g. `sudo apt-get gcc libssl-dev`.
2. Use rustup to install the latest stable rust during setup.

Package names may vary by dist but as you can see there isn't much to setup.

## Vendored OpenSSL

The `openssl` crate can fetch, build and statically link to a copy of OpenSSL without it being in your environment. 
See the crate's [documentation](https://docs.rs/openssl/0.10.18/openssl/) for further information but essentially
it has a `vendored` feature that can be set to enable this behaviour.

You need to have a C compiler, Perl and Make installed to enable this feature.

This might be useful in situations such as cross-compilation so OPC UA for Rust exposes the feature 
as `vendored-openssl` which on the `opcua-core`, `opcua-server` and `opcua-client`
crates. i.e. when you specify `--features=vendored-openssl` it will pass `vendored` through
to the `openssl` crate. 

The `demo-server` demonstrates how to use it:

```
cd samples/demo-server
cargo build "--features=vendored-openssl"
```

Note that Rust OPC UA is just passing through this feature so refer to the openssl documentation for any issues 
encountered while using it.

## Conditional compilation

The OPC UA server crate also provides some other features that you may or may not want to enable:

* `generated-address-space` - When enabled (the default), the `AddressSpace::new()` will create and populate the address space
  with the default OPC UA node set. When disabled, the address space will only contain a root node, thus saving
  memory and also some disk footprint.
* `discovery-server-registration` - When enabled, the server will periodically attempt to register itself with
  a local discovery server. This requires the OPC UA client crate when disabled (the default) this feature can save memory.
* `http` - When enabled, the server can start an HTTP server (see `demo-server`) providing diagnostic and metrics information about
  how many active connections there are, what they're monitoring as well as the internal health of the server. This
  is useful for development and debugging. When disabled (the default), no http server is started, saving memory and reducing
  build dependencies (primarily `actix-web` and what that pulls in). 

## Workspace Layout

OPC UA for Rust follows the normal Rust conventions. There is a `Cargo.toml` per module that you may use to build the module
and all dependencies. e.g.

```bash
cd opcua/samples/demo-server
cargo build
```

There is also a workspace `Cargo.toml` from the root directory. You may also build the entire workspace like so:

```bash
cd opcua
cargo build
```
