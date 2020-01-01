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

## OpenSSL 

The major external dependency is OpenSSL. If you have trouble building the `openssl-*` crates or trouble running them
then refer to that project's [documentation](https://docs.rs/openssl/0.10.26/openssl/). 

## Vendored OpenSSL

The `openssl` crate has a `vendored` feature that can fetch, build and statically link to a copy of OpenSSL without it 
being in your environment. 

This might be useful for cross-compiling. OPC UA for Rust exposes the feature as `vendored-openssl` which is
on the `opcua-core`, `opcua-server` and `opcua-client` crates. i.e. when you specify `--features=vendored-openssl` it will
pass `vendored` through to the `openssl` crate. 

Note that Rust OPC UA is just passing through this feature so refer to the openssl documentation for any issues 
and troubleshooting required to use it.

## Conditional compilation

The OPC UA server crate also provides some other features that you may or may not want to enable:

* `generated-address-space` - When enabled (default is enabled), the `AddressSpace::new()` will create and populate the address space
  with the default OPC UA node set. When disabled, the address space will only contain a root node, thus saving
  memory and also some disk footprint.
* `discovery-server-registration` - When enabled (default is disabled), the server will periodically attempt to register itself with
  a local discovery server. The server will use the on the client crate which requires more memory.
* `http` - When enabled (default disabled), the server can start an HTTP server (see `demo-server`) providing diagnostic and metrics information about
  how many active connections there are, what they're monitoring as well as the internal health of the server. This
  is useful for development and debugging. Enabling the http server adds dependencies on `actix-web` and requires more memory. 

## Workspace Layout

OPC UA for Rust follows the normal Rust conventions. There is a `Cargo.toml` per module that you may use to build the module
and all dependencies. e.g.

```bash
$ cd opcua/samples/demo-server
$ cargo build
```

There is also a workspace `Cargo.toml` from the root directory. You may also build the entire workspace like so:

```bash
$ cd opcua
$ cargo build
```
