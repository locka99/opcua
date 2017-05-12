# License

The code is licenced under [MPL-2.0](https://opensource.org/licenses/MPL-2.0). Like all open source code, you use this code at your own risk. 

# Introduction

This is an [OPC UA](https://opcfoundation.org/about/opc-technologies/opc-ua/) server / client API implemented in Rust. 
It is work in progress but is aiming for embedded profile support according to the specification.

OPC UA is an industry standard for live monitoring of data. It's intended for embedded devices, industrial control, IoT, 
PCs, mainframes, cars - just about anything that has data that something else wants to monitor or visualize. It is
a huge standard defined by compliance to profiles and facets. This implementation will comply with the smallest profiles 
growing outwards until it reaches a usable level of functionality. 

## Rationale - OPC UA for Rust?

Rust is a natural choice for OPC UA.

* Implementations in C/C++ are vulnerable to memory leaks, dangling pointers, complexity in their interface
* Implementations in Java, JavaScript etc. would suffer from fluctuating memory consumption, performance issues

An implementation in Rust should deliver high levels of performance without many of the risks associated with C/C++.
HOWEVER, there are a number of mature OPC UA libraries for other platforms. This is a new project so bugs in logic are 
likely and inevitable. Certain features found elsewhere may not be implemented or implemented incorrectly.

# Compliance

The implementation will attempt to comply with the specification and other implementations working out from simpler profiles to more complex. 

## OPC UA Binary 

This implementation will only implement the opc.tcp:// protocol and OPC UA Binary format. It *might* in time, 
add binary over https. It will **not** implement OPC UA over XML. XML hasn't see much adoption so this is no great 
impediment.

## Server

The server implements (more or less) the OPC UA micro profile. Over time compliance will expand out to embedded support and possibly further.

### Supported services

The following services are supported fully, partially (marked with a *) or as a stub / work in progress (marked !). That means a client
may call them and receive a response. 

Anything not listed is totally unsupported. Calling an unsupported service will terminate the session. Partial / stub
implementations are expected to receive more functionality over time.

* Discovery service set
    * GetEndpoints

* Attribute service set
    * Read
    * Write

* Session service set
    * CreateSession
    * ActivateSession
    * CloseSession

* View service set
    * Browse
    * BrowseNext (!). Implemented to do nothing
    * TranslateBrowsePathsToNodeIds (!). Stub to silence some clients that call it.

* MonitoredItem service set
    * CreateMonitoredItems. Data change filter including dead band filtering. 
    * ModifyMonitoredItems
    * DeleteMonitoredItems

* Subscription
    * CreateSubscription
    * ModifySubscription
    * Publish
    * Republish (!). Implemented to always return a service error
    * SetPublishingMode

### Nodeset

The standard OPC UA node set and address space is expressed in XML schemas, broken down by the document parts that 
define those nodes.

OPC UA for Rust uses a script to generate code to create and populate the standard address space. Most of this 
data is static however some server state variables will reflect the actual state of the server. 

### Supported security profiles / authentication

The server supports the following security mode / profiles:

1. Anonymous/None, i.e. no authentication
2. User/password (plaintext password)

Not supported:

1. User/password using encrypted password.
2. Public key authentication, signing and encryption. This will happen later once unencrypted functionality is working.

### Current limitations

Currently the following are not supported

* Diagnostic info. OPC UA allows for you to ask for diagnostics with any request. None is supplied at this time
* Session resumption. If your client disconnects, all information is discarded.
* Encryption will come after basically functionality is working in the clear.
* Chunks are 1 chunk only. 
* Default nodeset is mostly static. Certain fields of server information will contain their default values unless explicitly set.

## Client

Client support is still work in progress. Stubs have been created for the client lib, sample-client and some basic functionality.

# Building and testing

## Setup

1. Install latest stable rust, e.g. using rustup
2. Install gcc and OpenSSL development libs & headers. 

### Windows

You need OpenSSL to build OPC UA. The easiest way is to install the stable-x86_64-pc-windows-gnu Rust toolchain
and then install [MSYS2 64-bit](http://www.msys2.org/). Read the instructions on the site but you are recommended
to follow the instructions to update via `pacman -Syuu`.

Once MSYS2 has installed & updated you must bring in the MingW 64-bit compiler toolchain and OpenSSL

```bash
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-gdb mingw-w64-x86_64-pkg-config openssl-devel
```

Now ensure that these ensure both Rust and MinGW64 binaries are on your PATH and you should be ready:

```bash
set PATH=C:\msys64\mingw64\bin;C:\Users\MyName\.cargo\bin;%PATH%
```

You can use MSVC or 32-bit GNU but you may run into issues which are not covered by this document.

## Layout

OPC UA for Rust follows the normal Rust conventions. There is a Cargo.toml per module that you may use to build the module and all dependencies. You may also
build the entire workspace from the top like so:

```bash
cd opcua
cargo build --all
```

## Sample Server

The sample server creates a handful of variables that you can monitor within the address space.

```bash
cd opcua/sample-server
cargo run
```

The sample server is designed to be super terse and simple to demonstrate how the library uses convention as much as possible
to allow simple servers to be created with a very small number of lines of code.  

## Crypto

At the moment crypto isn't implemented fully however OpenSSL is a dependency of opcua and you must be able to build it.
You are advised to read the OpenSSL [documentation](https://github.com/sfackler/rust-openssl) for that to set up your 
environment.

### Certificate pki structure

When crypto is enabled, the intention is that trusted/rejected certificates will be stored and managed on disk:

```
pki/
  own/
    cert.der - your server/client's public certificate
  private/
    key.pem  - your server/client's private key
  trusted/
    ...      - contains certs from client/servers you've connected with and you trust
  rejected/
    ...      - contains certs from client/servers you've connected with and you don't trust
```

The idea is that when you first receive an encrypted connnection from an untrusted client the server will write the
cert to the rejected/ folder and the connection will fail. You, the administrator will explicitly move the cert
to the trusted/ folder to permit connections from that client in future. They might also have to do admin in their
client to move the server cert to the client's trusted folder.

More sophisticated trust based off hostnames, signed certs etc. is unlikely in the short term. 

### Certificate creator

The `tools/certificate-creator` tool will create a public self-signed cert and private key. You need OpenSSL to build the
tool.

For usage type:
 
```bash
cd tools\certificate-creator
cargo run --features crypto -- --help
```

A minimal usage:

```bash
cargo run --features crypto --
```

# Implementation details

## Minimizing code through convention

The API is designed on the principle of convention by default to minimize the amount of customization you need to make 
it do something. 

This is all the code you need to write a minimal, functioning server. 

```rust
extern crate opcua_server;

use opcua_server::prelude::*;

fn main() {
    Server::new_default().run();
}
```

This server will accept connections, allow you to browse the address space and subscribe to variables. 

Refer to the sample-server/ example for something that adds variables to the address space and changes their values on a timer.

## Type generation from schemas

Scripts will be used to generate Rust source code from schemas for the following:

* Status codes
* Node Ids (objects, variables, references etc.)
* Request and Response messages including serialization
* Address space

Generated code will reside in generated/ modules and pulled in by the rest of the code. Core types like String, 
ByteString, Variant, DataValue, NodeId, ExtensionObject etc. are handwritten.

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

Another change from the spec, is status codes. All status codes will be values of a `StatusCode` enum.
At present, values are represented as `SNAKE_CASE` and the `StatusCode::` enum namespace will not be a necessary prefix. 

So code will contain values such as `GOOD`, `BAD_UNEXPECTED_ERROR` etc. without qualification.

Note: the decision to upper case codes is subject to review because it is inconsistent with node ids above.

The enum will also implement `Copy` so that status codes are copy on assign. The enum also provides helpers such 
as `is_good()`, `is_bad()`, `name()` and `description()` for testing and debugging purposes.

```rust
#[allow(non_camel_case_types)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum StatusCode {
    GOOD = 0,
    //...
    UNCERTAIN_REFERENCE_OUT_OF_SERVER = 0x406C0000,
    UNCERTAIN_NO_COMMUNICATION_LAST_USABLE_VALUE = 0x408F0000,
    //...
    BAD_UNEXPECTED_ERROR = 0x80010000,
    BAD_INTERNAL_ERROR = 0x80020000,
    BAD_ENCODING_LIMITS_EXCEEDED = 0x80080000,
    BAD_UNKNOWN_RESPONSE = 0x80090000,
    BAD_TIMEOUT = 0x800A0000,
    //...
}
// Everything in StatusCode:: becomes immediately accessible
pub use self::status_codes::StatusCode::*;
```

## Formatting

All code (with the exceptions noted for OPC UA) should be follow the most current Rust RFC coding guidelines for naming
conventions, layout etc.

Code should be formatted with the IntelliJ rust plugin, or with rustfmt.

## Implementation plan

### Server

The intention is that the implementation will work its way through OPC UA profiles from nano to embedded to standard to attain a level of functionality acceptable to most consumers of the API.

Profiles are defined in "OPC UA Part 7 - Profiles 1.03 Specification"

This [OPC UA link](http://opcfoundation-onlineapplications.org/ProfileReporting/index.htm) provides interactive and descriptive information about
profiles and relevant test cases.

* Phase 0: Types, project structure, code generation tools, basic connectivity, binary transport format, services framework
* Phase 1. This phase mostly implements the Nano Embedded Device Server Profile, which has these main points
  * SecurityPolicy of None (i.e. no encryption / signing)
  * Username / Password support (plaintext)
  * Address space
  * Discovery Services
  * Session Services (minimum, single session)
  * View Services (basic)
* **Phase 2:** Micro Embedded Device Server Profile. This is a bump up from Nano, supporting 2 or more sessions and data change notifications via a subscription. Internally, first efforts at writing a client may start here. Clients share most of the same structs as the server as well as utility code such as chunking etc. Where the client differs is that where a server deserializes certain messages and serializes others, the client does the opposite. So code must serialize and deserialize correctly. In addition the client has its own client side state starting with the HELLO, open secure channel, subscription state etc. 
* Phase 3: Phase 3 Embedded UA Server Profile. This phase will bring the UA server up to the point that it is probably useful for most day-to-day functions and most clients. It includes support for Basic1238Rsa15 and PKI infrastructure. Internally, chunks can be signed and optionally encrypted. This means code that reads data from a chunk will have to be decrypted first and any padding / signature removed. Crypto happens on a per-chunk level so chunks have to be verified, decrypted and then stitched together to be turned into messages. In addition the open secure channel code needs to cope with crypto, trust / cert failures, reissue tokens and all the other issues that may occur. 
* Phase 4 Standard UA Server Profile - Basically embedded + enhanced data change subscription server facet + X509 user token server facet

### Client

Client functionality takes second place to server functionality. Client will not happen until at least a nano server exists.

In some respects implementing the client is HARDER than server since it must maintain state and attempt to reconnect when the 
connection goes down. Client OPC UA is governed by its own core characteristics. These will be implemented to test the server functionality in general order:

* Base client behaviour facet - 
* Core client facet (crypto, security policy)
* Attribute read / write
* Datachange subscriber
* Durable subscription client (i.e. ability to reconnect and re-establish group after disconnect)

## Major 3rd party dependencies

* log - for logging / auditing
* openssl - cryptographic functions for signing, certifications and encryption/decryption
* serde, server_yaml - for processing config files
* byteorder - for serializing values with the proper endian-ness
* chrono - for high quality time functions
* time - for some types that chrono still uses, e.g. Duration
* random - for random number generation in some places

# Testing

## Unit tests

The plan is for unit tests for at least the following

* All data types, request and response types will be covered by a serialization
* Chunking messages together, handling errors, buffer limits
* Limit validation on string, array fields which have size limits
* OpenSecureChannel, CloseSecureChannel request and response
* Sign, verify, encrypt and decrypt (when implemented)
* Data change filters
* Subscription state engine

## Integration testing

Integration testing shall wait for client and server to be implemented. At that point it shall be possible to write a unit test that initiates a connection from a client to a server and simulates scenarios such as.

* Discovery service
* Connect / disconnect
* Create session
* Subscribe to values
* Encryption (when implemented)

## OPC UA test cases

See this [OPC UA link](http://opcfoundation-onlineapplications.org/ProfileReporting/index.htm) and click
on the test case links associated with facets.

There are a lot of tests. Any that can be sanely automated or covered by unit / integration tests will be. 
The project will not be a slave to these tests, but it will try to ensure compatibility.

## 3rd party testing

The best way to test is to build the sample-server and use a 3rd party client to connect to it. 

If you have NodeJS then the easiest 3rd party client to get going with is node-opcua opc-commander client. 

```bash
npm install -g opcua-commander
```

Then build and run the sample server:

```bash
cd sample-server
cargo run
```

And in another shell

```bash
opcua-commander -e opc.tcp://localhost:1234
```

