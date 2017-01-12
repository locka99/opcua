# Introduction

OPC UA is an industry standard for live monitoring of data. It's intended for on embedded devices, industrial 
control, IoT, PCs, mainframes, cars - just about anything that has data that something else wants to monitor
or visualize.

This is an OPC UA server / client API implemented in Rust. 

# License

MPL-2.0

https://opensource.org/licenses/MPL-2.0

# Current progress

Phase 0 - just building the fundamentals

# OPC UA for Rust?

Rust is a natural choice for OPC UA due in part to the complexity of OPC UA itself and the
fact that Rust is a systems programming language.

* Implementations in C/C++ would be vulnerable to memory leaks, dangling pointers, complexity in their interface
* Implementations in Java, JavaScript etc. would be vulnerable to fluctuating memory consumption, performance issues
* An implementation in Rust should deliver C/C++ levels of performance without some of the risks

HOWEVER, there are a number of mature OPC UA libraries for other platforms that have had time
to offer more complete implementation so bugs in logic are still possible and likely.

All communication is over TCP, optionally encrypted and defined by a bunch of services that the server
must / may implement and the client must / may call to connect, subscribe, browse etc. The standard is
very complex and therefore broken up into profiles. 

This implementation will attempt to work its way from nano server profile (no crypto, limited services),
up to at least embedded profile.

This implementation will only implement the opc.tcp:// protocol and OPC UA Binary format. It *might*
add binary over https in time. It will **not** implement XML format. XML hasn't see much adoption so this 
is no great impediment.

# Coding style

Enums, structs, fields, constants etc. will conform to Rust lint rules. i.e. OPC UA uses pascal case for field
names but the impl will use snake case.

```rust
struct OpenSecureChannelRequest {
  pub request_header: RequestHeader
}
```

If a enum value is called INVALID_0 it will be called Invalid with a value of 0 in the Rust enum.

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

We can see an ExtensionObject has a node id and a body payload. The body is an enumeration which is either
empty or holds a byte string or xml element. When the type is serialized it will follow the spec,
having an encoding byte, length, payload. But in memory we can force the correct type and control what goes
in and out of the type.

## Formatting

All code should be follow the most current Rust RFC coding guidelines for naming conventions, layout
etc.

Code should be formatted with the IntelliJ rust plugin, or with rustfmt.

## Lint exceptions for OPC UA

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

# Testing

## Unit tests

The plan is for unit tests for at least the following

* All data types, request and response types will be covered by a serialization
* Chunking messages together, handling errors, buffer limits
* Limit validation on string, array fields which have size limits
* OpenSecureChannel, CloseSecureChannel request and response
* Sign and encrypt (when implemented)

## Integration testing

* Discovery service
* Connect / disconnect
* Create session
* Subscribe to values
* Encryption (when implemented)

## OPC UA test cases

See this [OPC UA link](http://opcfoundation-onlineapplications.org/ProfileReporting/index.htm) and click
on the test case links associated with facets.

There are a lot of tests. Any that can be sanely automated or covered by unit / integration tests will be.

## 3rd party testing

The best way to test is to build the sample-server and use a 3rd party client to connect to it. 

If you have NodeJS then the easiest 3rd party client to get going with is node-opcua opc-commander client. 

npm install -g opcua-commander

Then build and run the sample server:

cd sample-server
cargo run

And in another shell

opcua-commander -e opc.tcp://localhost:1234

# Server - Implementation plan

The intention is that the implementation will work its way through OPC UA profiles from nano to embedded to standard to attain a level of functionality acceptable to most consumers of the API.

Profiles are defined in "OPC UA Part 7 - Profiles 1.03 Specification"

This [OPC UA link](http://opcfoundation-onlineapplications.org/ProfileReporting/index.htm) provides interactive and descriptive information about
profiles and relevant test cases.

## Phase 0: Types, basic functionality

This phase will focus on the project structure, dependencies, tools to generate source from schemas,
basic connectivity, binary transport format, services framework and other foundational work.

NodeJS will be used for any script work, e.g. tools that transform OPC UA schemas / data into 
Rust source. Reasons for this include:

* It's cross platform
* It's easy to write code in and understand it afterwards (unlike Perl)
* Node has lots and lots of modules for dealing with esoteric file formats and quickly processing them.

Potentially we could write these scripts as Rust software, but not any time soon.

### Expected 3rd party dependencies

* log - for logging / auditing
* OpenSSL - required for crypto
* serde, server_yaml - for processing config files
* byteorder - for serializing values with the proper endian-ness
* chrono - for high quality time functions

## Phase 1: Nano Embedded Device Server Profile

This phase mostly implements the Core Server Facet which has these main points:

* SecurityPolicy of None (i.e. no encryption / signing)
* Username / Password support
* Address space
* Discovery Services
* Session Services (minimum, single session)
* View Services (basic)

Internally, the code for TCP and chunking is expected to improve. Preferably the code should use
non-blocking IO and code that consumes or produces chunks should be able to cope with multiple
chunks. i.e. chunks are received into a buffer and when the final / final abort chunk arrives, 
the buffer is processed and cleared.

### From specification

Table (below) describes the details of the Nano Embedded Device Server Profile. This Profile is a FullFeatured Profile intended for chip level devices with limited resources. This Profile is functionally equivalent to the Core Server Facet and defines the OPC UA TCP binary protocol as the required transport profile.
Exposing types in the AddressSpace is optional for this Profile except if custom types (i.e. types that are derived from well-known ObjectTypes, VariableTypes, ReferenceType or DataTypes) are used. Exposing all supported types in the AddressSpace is mandatory in some higher level Profiles.

| Group | Conformance Unit / Profile Title | Optional 
| --- | --- | ---
| *Profile* | Core Server Facet | False
| *Profile* | UA-TCP UA-SC UA Binary | False
| Base Information | Base Info Diagnostics | True
| Base Information | Base Info Custom Type System | True

## Phase 2: Micro Embedded Device Server Profile

This is a bump up from the nano server

* Supports 2+ sessions
* Data change notifications via subscription

Internally, first efforts at writing a client may start here. Clients share most of the same structs as the server as
well as utility code such as chunking etc. Where the client differs is that where a server deserializes certain messages
and serializes others, the client does the opposite. So code must serialize and deserialize correctly. In addition
the client has its own client side state starting with the HELLO, open secure channel, subscription state etc. 

### From specification

Table (below) describes the details of the Micro Embedded Device Server Profile. This Profile is a FullFeatured Profile intended for small devices with limited resources. This Profile builds upon the Nano Embedded Device Server Profile. The most important additions are: support for subscriptions via the Embedded Data Change Subscription Server Facet and support for at least two sessions. A complete Type System is not required; however, if the Server implements any non-UA types then these types and their super-types must be exposed.

| Group | Conformance Unit / Profile Title | Optional
| --- | --- | ---
| *Profile* | Embedded DataChange Subscription Server Facet | False
| *Profile* | Nano Embedded Device Server Profile | False
| Session Services | Session Minimum 2 Parallel | False

## Phase 3 Embedded UA Server Profile

This phase will bring the UA server up to the point that it is probably useful for most day-to-day functions.

* Security Basic128Rsa15
* PKI infrastructure

Internally, chunks can be signed and optionally encrypted. This means code that reads data from a
chunk will have to be decrypted first and any padding / signature removed. Crypto happens on a per-chunk level so
chunks have to be verified, decrypted and then stitched together to be turned into messages. In addition the open secure 
channel code needs to cope with crypto, trust / cert failures, reissue tokens and all the other issues that may occur. 

The server / client layout needs a pki/ folder with trusted, rejected subdirs. Rejected certs should
be saved in the rejected folder so a user may manually drag and drop them to the trusted folder.

### From specification

Table (below) describes the details of the Embedded UA Server Profile. This Profile is a FullFeatured Profile that is intended for devices with more than 50 MBs of memory and a more powerful processor. This Profile builds upon the Micro Embedded Device Server Profile. The most important additions are: support for security via the Security Policy – Basic128Rsa15 Facet, and support for the Standard DataChange Subscription Server Facet. This Profile also requires that servers expose all OPC-UA types that are used by the Server including their components and their super-types.

| Group | Conformance Unit / Profile Title | Optional
| --- | --- | ---
| *Profile* | Micro Embedded Device Server Profile | False
| *Profile* | SecurityPolicy – Basic128Rsa15 | False
| *Profile* | Standard DataChange Subscription Server Facet | False
| *Profile* | User Token – X509 Certificate Server Facet | False
| Base Information | Base Info Engineering Units | True
| Base Information | Base Info Placeholder Modelling Rules | True
| Base Information | Base Info Type System | False
| Security | Security Default ApplicationInstanceCertificate | False

## Phase 4 Standard UA Server Profile

TODO - Basically embedded + enhanced data change subscription server facet + X509 user token server facet


# Client - implementation plan

Client functionality takes second place to server functionality. Client will not happen until at least a nano server exists.

In some respects implementing the client is HARDER than server since it must maintain state and attempt to reconnect when the 
connection goes down.

Client OPC UA is governed by its own core characteristics. These will be implemented to test the server functionality in general order:

* Base client behaviour facet - 
* Core client facet (crypto, security policy)
* Attribute read / write
* Datachange subscriber
* Durable subscription client (i.e. ability to reconnect and re-establish group after disconnect)


