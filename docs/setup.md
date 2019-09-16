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

You should use the MSYS2/MingW64 Shell. You may have to tweak your .bashrc to ensure that both Rust and 
MinGW64 binaries are on your `PATH` but once that's done you're good to go. 

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

# Design details

## Minimizing code through convention

The API will use convention and idiomatic rust to minimize the amount of code that needs to be written.

Here is a minimal, functioning server. 

```rust
extern crate opcua_server;

use opcua_server::prelude::*;

fn main() {
    let server: Server = ServerBuilder::new_sample().server().unwrap();
    server.run();
}
```

This server will accept connections, allow you to browse the address space and subscribe to variables. 

Refer to the `samples/simple-server/` and `samples/simple-client/` examples for something that adds variables to the
address space and changes their values.

## Types

OPC UA defines a lot of types, some of which are primitives, basic types, structures or request / response messages.
All types are defined in the `opcua-types` crate. 

### Primitives

OPC UA primitive types are referred to by their Rust equivalents, i.e. if the specification says `Int32`, the signature of the function / struct will use `i32`:

* `Boolean` to `bool`
* `SByte` to `i8`
* `Byte` to `u8`
* `Int16` to `i16`
* `UInt16` to `u16`
* `Int32` to `i32`
* `UInt32` to `u32`
* `Int64` to `i64`
* `UInt64` to `u64`
* `Float` to `f32`
* `Double` to `f64`

### Strings

The OPC UA type `String` is not directly analogous to a Rust `String`. The OPC UA definition maintains the 
distinction between being a null value and being an empty string. This affects how the string is encoded 
and could impact on application logic too.

For this reason, `String` is mapped onto a new Rust type `UAString` type which captures this behaviour. The name is
`UAString` because `String` is such a fundamental type that it is easier to disambiguate by calling it something else
rather than through module prefixing. 

### Basic types

All of the basic OPC UA types are implemented by hand.

* `ByteString`
* `DateTime`
* `QualifiedName`
* `LocalizedText`
* `NodeId`
* `ExpandedNodeId`
* `ExtensionObject`
* `Guid`
* `NumericRange`
* `DataValue`
* `Variant`

A `Variant` is a special catch-all enum which can hold any other primitive or basic type, including arrays of the same.
The implementation uses a `Box` (allocated memory) for larger kinds of type to keep the stack size down.

### Machine generated types

The `tools/schema/` directory contains NodeJS scripts that will generate Rust code from from OPC UA schemas in
`schemas/1.0.3`. 

* Status codes
* Node Ids (objects, variables, references etc.)
* Data structures including serialization.
* Request and Response messages including serialization
* Address space nodes

Enums are handwritten but could be machine generated.

## Handling OPC UA names in Rust

All OPC UA enums, structs, fields, constants etc. will conform to Rust lint rules where it makes sense. 
i.e. OPC UA uses pascal case for field names but the impl will use snake case, for example `requestHeader` is defined 
as `request_header`.

```rust
struct OpenSecureChannelRequest {
  pub request_header: RequestHeader
}
```

The OPC UA type SecurityPolicy value `INVALID_0` will an enum `SecurityPolicy` with a value `Invalid` with a scalar value 
of 0.

```rust 
pub enum SecurityPolicy {
  Invalid = 0,
  None = 1
  ...
}
```

The enum will be turned in and out of a scalar value during serialization via a match.

Wherever possible Rust idioms will be used - enums, options and other conveniences of the language will be used to 
represent data in the most efficient and strict way possible. e.g. here is the ExtensionObject

```rust
#[derive(PartialEq, Debug, Clone)]
pub enum ExtensionObjectEncoding {
    None,
    ByteString(ByteString),
    XmlElement(XmlElement),
}

/// A structure that contains an application specific data type that may not be recognized by the receiver.
/// Data type ID 22
#[derive(PartialEq, Debug, Clone)]
pub struct ExtensionObject {
    pub node_id: NodeId,
    pub body: ExtensionObjectEncoding,
}
```

Rust enables the `body` payload to be `None`, `ByteString` or `XmlElement` and this is handled during serialization.

### Lint exceptions for OPC UA

OPC UA has some some really long PascalCase ids, many of which are further broken up by underscores. I've tried converting the 
name to upper snake and they look terrible. I've tried removing underscores and they look terrible.

So the names and underscores are preserved as-in in generated code even though they generate lint errors. 
The lint rules are disabled for generated code.

For example:

```rust
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum VariableId {
    //... thousands of ids, many like this or worse
    ExclusiveRateOfChangeAlarmType_LimitState_LastTransition_EffectiveTransitionTime = 11474,
}
```

### Status codes

Most uses of a status code will be via a `StatusCode` enum. Values such as `Good`, `BadUnexpectedError` etc.

The enum will also implement `Copy` so that status codes are copy on assign. The enum provides helpers `is_good()`,
`is_bad()`, `name()` and `description()` for testing and debugging purposes. It also provides functions for turning the
code into and out of a UInt32 and masking status / info bits.

## Formatting

All code (with the exceptions noted for OPC UA) should be follow the most current Rust RFC coding guidelines for naming
conventions, layout etc.

Code should be formatted with the IntelliJ rust plugin, or with rustfmt.

## Implementation plan

Client and server will work their ways through OPC UA profiles to the point of usability. But presently they are working
towards.

* Nano Embedded Device Server Profile, which has these main points
  * UA-TCP binary
  * SecurityPolicy of None (i.e. no encryption / signing)
  * Username / Password support (plaintext)
  * Address space
  * Discovery Services
  * Session Services (minimum, single session)
  * View Services (basic)
* Micro Embedded Device Server Profile. This is a bump up from Nano.
  * UA secure conversation
  * 2 or more sessions
  * Data change notifications via a subscription.
* Embedded UA Server Profile
  * Standard data change notifications via a subscription
    * Queueing
    * Deadband filter
    * CallMethod service
    * GetMonitoredItems via call
    * ResendData via call

This [OPC UA link](http://opcfoundation-onlineapplications.org/ProfileReporting/index.htm) provides interactive and descriptive information about
profiles and relevant test cases.

## Major 3rd party dependencies

* log - for logging / auditing
* openssl - cryptographic functions for signing, certifications and encryption/decryption
* serde, server_yaml - for processing config files
* clap - used by sample apps & certificate creator for command line argument processing
* byteorder - for serializing values with the proper endian-ness
* tokio - for asynchronous IO and timers
* chrono - for high quality time functions
* time - for some types that chrono still uses, e.g. Duration
* random - for random number generation in some places

## 3rd-party servers

There are also a couple of [node-opcua](https://github.com/node-opcua) scripts in `3rd-party/node-opcua`.

1. `client.js` - an OPC UA client that connects to a server and subscribes to v1, v2, v3, and v4.
2. `server.js` - an OPC UA server that exposes v1, v2, v3 and v4 and changes them from a timer.

These are functionally analogous to `simple-server` and `simple-client` so the Rust code can be tested against
an independently written implementation of OPC UA that works in the way it is expecting. This is useful for debugging
and isolating bugs / differences.

To use them:

1. Install [NodeJS](https://nodejs.org/) - LTS should do, but any recent version should work.
2. `cd 3rd-party/node-opcua`
3. `npm install` 
4. `node server.js` or `node client.js`

# Testing

See the [testing](./testing.md) document.