# Introduction

This is an [OPC UA](https://opcfoundation.org/about/opc-technologies/opc-ua/) server / client API implemented in Rust. 

OPC UA is an industry standard for monitoring of data. It's used extensively for embedded devices, industrial control, IoT, 
etc. - just about anything that has data that something else wants to monitor, control or visualize. 

Rust is a systems programming language and is therefore a natural choice for implementing OPC UA. This implementation 
will support the embedded profile.  

# License

The code is licenced under [MPL-2.0](https://opensource.org/licenses/MPL-2.0). Like all open source code, you use this code at your own risk. 

# Feature Support  

## OPC UA Binary Transport Protocol

This implementation will implement the opc.tcp:// binary format. It will **not** implement OPC UA over XML. XML hasn't
see much adoption so this is no great impediment. Binary over https:// might happen at a later time.

## Server

The server shall implement the OPC UA capabilities:

* http://opcfoundation.org/UA-Profile/Server/Behaviour - base server profile
* http://opcfoundation.org/UA-Profile/Server/EmbeddedUA - embedded UA profile

### Server services

The following services are supported:

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
    * BrowseNext
    * TranslateBrowsePathsToNodeIds

* MonitoredItem service set
    * CreateMonitoredItems - Data change filter including dead band filtering. 
    * ModifyMonitoredItems
    * DeleteMonitoredItems
    * SetMonitoringMode

* Subscription service set
    * CreateSubscription
    * ModifySubscription
    * DeleteSubscriptions
    * Publish
    * Republish
    * SetPublishingMode

Other service calls are unsupported. Calling an unsupported service will terminate the session. 

### Address Space / Nodeset

The standard OPC UA address space will be exposed. OPC UA for Rust uses a script to generate code to create and
populate the standard address space. 

### Configuration

Server and client can be configured programmatically or by configuration file. See the `samples/` folder for examples
of client and server side configuration. The config files are specified in YAML.

### Encryption modes

The server supports endpoints with the standard message security modes:

* None - no encryption
* Sign - no encryption but messages are digitally signed to ensure integrity
* SignAndEncrypt - signed messages which are then encrypted

The following security policies are supported.

* None (no encryption)
* Basic128Rsa15
* Basic256
* Basic256Rsa256

### User identities 

The server supports the following user identities

1. Anonymous/None, i.e. no authentication
2. User/password - plaintext password only

User/pass identities are defined by configuration

### Current limitations

Currently the following are not supported

* Diagnostic info. OPC UA allows for you to ask for diagnostics with any request. None is supplied at this time
* Session resumption. If your client disconnects, all information is discarded.
* Default nodeset is mostly static. Certain fields of server information will contain their default values unless explicitly set.

## Client

The client shall provide synchrononous and asynchronous calls corresponding to the functionality of the server. It will
also support these additional calls.

* FindServers
* RegisterServer (for servers to register themselves with a discovery server)

# Building and testing

## Setup

1. Install latest stable rust, e.g. using rustup
2. Install gcc and OpenSSL development libs & headers. 

On Linux this should be straightforward. On Windows, read below.

### Windows

You need OpenSSL to build OPC UA. The easiest way is to install the stable-x86_64-pc-windows-gnu Rust toolchain
and then install [MSYS2 64-bit](http://www.msys2.org/). Read the instructions on the site especially on updating to the
latest packages via `pacman -Syuu`.

Once MSYS2 has installed & updated you must install the MingW 64-bit compiler toolchain and OpenSSL packages.

```bash
pacman -S gcc mingw-w64-x86_64-gcc mingw-w64-x86_64-gdb mingw-w64-x86_64-pkg-config openssl openssl-devel pkg-config
```

Now ensure that these ensure both Rust and MinGW64 binaries are on your PATH and you should be ready:

```bash
set PATH=C:\msys64\mingw64\bin;C:\Users\MyName\.cargo\bin;%PATH%
```

Note: It should be possible to build using MSVC but you should read the Rust OpenSSL docs for how to set up your paths properly.

## Layout

OPC UA for Rust follows the normal Rust conventions. There is a Cargo.toml per module that you may use to build the module and all dependencies. You may also
build the entire workspace from the top like so:

```bash
cd opcua
cargo build
```

## Simple Server

The crate simple-server demonstrates a server that creates a handful of variables that you can monitor within the address space.

```bash
cd opcua/samples/simple-server
cargo run
```

The sample is designed to be super terse and to demonstrate what you can do with a small amount of code.

default user: sample and password: sample1
default endpoint: opc.tcp://localhost:4855

## Crypto

At present OPC UA for Rust uses OpenSSL bindings for Rust for crypto. The product makes extensive use of various 
cryptographic algorithms for signing, verifying, encrypting and decrypting data. In addition it needs to be able 
to create, load and save various file formats for certificates and keys.

So we use OpenSSL for the time being. Almost all OpenSSL code is isolated and could be removed if a pure Rust implementation
of the same functionality becomes viable.

You are advised to read the OpenSSL [documentation](https://github.com/sfackler/rust-openssl) to set up your 
environment.

### Certificate pki structure

The server / client uses the following directory structure to manage trusted/rejected certificates:

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

For encrypted connections the following applies:

* The server will reject the first connection from an unrecognized client. It will create a file representing 
the cert in its the `pki/rejected/` folder and you, the administrator must move the cert to 
the `trusted/` folder to permit connections from that client in future.
* Likewise, the client shall reject unrecognized servers in the same fashion, and the cert must be moved from the 
`rejected/` to `trusted/` folder for connection to succeed.

### Certificate creator

The `tools/certificate-creator` tool will create a demo public self-signed cert and private key. 
It can be built from source, or the crate:

```bash
cargo install --force opcua-certificate-creator
```

A minimal usage might be something like this inside samples/simple-client and/or samples/simple-server:

```bash
 opcua-certificate-creator --pkipath ./pki
```

A full list of arguments can be obtained by ```--help``` and you are advised to set fields such
as expiration length, description, country code etc to your requirements.

# Design details

## Minimizing code through convention

The API will use convention by default to minimize the amount of code that needs to be written.

Here is a minimal, functioning server. 

```rust
extern crate opcua_types;
extern crate opcua_core;
extern crate opcua_server;

use std::sync::{Arc, RwLock};

use opcua_server::prelude::*;

fn main() {
    Server::run(Arc::new(RwLock::new(Server::new_default())));
}
```

This server will accept connections, allow you to browse the address space and subscribe to variables. 

Refer to the `samples/simple-server/` and `samples/simple-client/` examples for something that adds variables to the address space and changes their values.

## Type generation from schemas

Fundamental types are implemented by hand. Structures such as requests/responses are machine generated by script.

The `tools/schema/` directory contains NodeJS scripts that will generate the following from OPC UA schemas.

* Status codes
* Node Ids (objects, variables, references etc.)
* Data structures including serialization.
* Request and Response messages including serialization
* Address space

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

Certain enums use Boxed types to avoiding being overly large. e.g. the Variant enum boxes complex values such as DataValue,
arrays etc. to prevent being too bloated.

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

All status codes will be values within the `StatusCode` enum. Values such as `Good`, `BadUnexpectedError` etc.

The enum will also implement `Copy` so that status codes are copy on assign. The enum provides helpers `is_good()`,
`is_bad()`, `name()` and `description()` for testing and debugging purposes.

## Formatting

All code (with the exceptions noted for OPC UA) should be follow the most current Rust RFC coding guidelines for naming
conventions, layout etc.

Code should be formatted with the IntelliJ rust plugin, or with rustfmt.

## Implementation plan

### Server

Implemented:

* Types, project structure, code generation tools, basic connectivity, binary transport format, services framework
* Nano Embedded Device Server Profile, which has these main points
  * SecurityPolicy of None (i.e. no encryption / signing)
  * Username / Password support (plaintext)
  * Address space
  * Discovery Services
  * Session Services (minimum, single session)
  * View Services (basic)
* Micro Embedded Device Server Profile. This is a bump up from Nano.
  * 2 or more sessions
  * Data change notifications via a subscription. 

Work in progress:

* Multiple chunks
* Registration to local discovery server

This [OPC UA link](http://opcfoundation-onlineapplications.org/ProfileReporting/index.htm) provides interactive and descriptive information about
profiles and relevant test cases.

### Client

Implemented:

* Base client behaviour facet
* Attribute read / write
* Discovery
* Subscriptions / monitored items + datachange callback 

Eventually:

* Core client facet (crypto, security policy)
* Error recovery state (i.e. ability to reconnect and re-establish state after disconnect)

## Major 3rd party dependencies

* log - for logging / auditing
* openssl - cryptographic functions for signing, certifications and encryption/decryption
* serde, server_yaml - for processing config files
* byteorder - for serializing values with the proper endian-ness
* chrono - for high quality time functions
* time - for some types that chrono still uses, e.g. Duration
* random - for random number generation in some places

# Testing

The plan is for unit tests for at least the following

* All data types, request and response types will be covered by a serialization
* Chunking messages together, handling errors, buffer limits, multiple chunks
* Limit validation on string, array fields which have size limits
* OpenSecureChannel, CloseSecureChannel request and response
* Service calls
* Sign, verify, encrypt and decrypt (when implemented)
* Data change filters
* Subscription state engine
* Encryption

## Integration testing

Integration testing shall wait for client and server to be complete. At that point it shall be possible to write a unit test that initiates a connection from a client to a server and simulates scenarios such as.

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
opcua-commander -e opc.tcp://localhost:4855
```

