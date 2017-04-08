# License

The code is licenced under [MPL-2.0](https://opensource.org/licenses/MPL-2.0).

# Introduction

[OPC UA](https://opcfoundation.org/about/opc-technologies/opc-ua/) is an industry standard for live monitoring of data. It's intended for on embedded devices, industrial 
control, IoT, PCs, mainframes, cars - just about anything that has data that something else wants to monitor
or visualize.

This is an OPC UA server / client API implemented in Rust. To say OPC UA is a big standard is an understatement so the implementation
will comply with the smallest profiles first until it reaches a usable level of functionality. 

## Example - A minimal server

The API is designed on the principle of convention by default to minimize the amount of customization you need to make it 
do something. Here is a minimal server:

```rust
use opcua_server::prelude::*;

fn main() {
    Server::new_default().run();
}
```

Obviously you'll do probably want to do more than this, but refer to the sample-server example. A server would
want to create elements in the address space, update variables on a timer or listener and things of that nature.

# Compliance

## Server

The server is compliant (more or less) with OPC UA micro profile.

### Supported services

The following services are supported fully, partially (marked with a *) or as a stub / work in progress (marked !). That means a client
may call them and receive a response. Anything not listed is totally unsupported. Calling an unsupported service will terminate the session.

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
    
* MonitoredItem service set
    * CreateMonitoredItems. Data change filter only
    * ModifyMonitoredItems(*). Data change filter only
    * DeleteMonitoredItems(*)

* Subscription
    * CreateSubscription
    * ModifySubscription
    * Publish
    * Republish (!). Implemented to always return a service error
    * SetPublishingMode

### Nodeset

The server implements a basic nodeset to satisfy most clients. It is likely that the nodeset will be generated automatically
from the .xml schemas in the future. For now it is handwritten.

### Supported security profiles / authentication

The server supports the following security mode / profiles:

1. Anonymous/None, i.e. no authentication
2. User/password (plaintext password)

Encryption will happen later once unencrypted functionality is working.

### Current limitations

Currently the following are not supported

* Diagnostic info. OPC UA allows for you to ask for diagnostics with any request. None is supplied at this time
* Session resumption. If your client disconnects, all information is discarded.
* Encryption will come after basically functionality is working in the clear.
* Chunks are 1 chunk only. 
* Default nodeset is mostly static

## Client

Client support is still work in progress. Stubs have been created for the client lib, sample-client and some basic functionality.

# Rationale - OPC UA for Rust?

Rust is a natural choice for OPC UA due in part to the complexity of OPC UA itself and the
fact that Rust is a systems programming language.

* Implementations in C/C++ would be vulnerable to memory leaks, dangling pointers, complexity in their interface
* Implementations in Java, JavaScript etc. would be vulnerable to fluctuating memory consumption, performance issues
* An implementation in Rust should deliver C/C++ levels of performance without some of the risks

HOWEVER, there are a number of mature OPC UA libraries for other platforms. Bugs in logic are likely, and 
certain features found elsewhere may be implemented.

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

There are a lot of tests. Any that can be sanely automated or covered by unit / integration tests will be. The project will not be a slave to these tests, but it will try to ensure compatibility.

## 3rd party testing

The best way to test is to build the sample-server and use a 3rd party client to connect to it. 

If you have NodeJS then the easiest 3rd party client to get going with is node-opcua opc-commander client. 

```
npm install -g opcua-commander
```

Then build and run the sample server:

```
cd sample-server
cargo run
```

And in another shell

```
opcua-commander -e opc.tcp://localhost:1234
```

# Implementation plan

## Server

The intention is that the implementation will work its way through OPC UA profiles from nano to embedded to standard to attain a level of functionality acceptable to most consumers of the API.

Profiles are defined in "OPC UA Part 7 - Profiles 1.03 Specification"

This [OPC UA link](http://opcfoundation-onlineapplications.org/ProfileReporting/index.htm) provides interactive and descriptive information about
profiles and relevant test cases.

* Phase 0: Types, basic functionality - This phase focussed on the project structure, dependencies, tools to generate source from schemas,
basic connectivity, binary transport format, services framework and other foundational work.
* Phase 1. This phase mostly implements the Nano Embedded Device Server Profile, which has these main points
  * SecurityPolicy of None (i.e. no encryption / signing)
  * Username / Password support
  * Address space
  * Discovery Services
  * Session Services (minimum, single session)
  * View Services (basic)
* Phase 2: Micro Embedded Device Server Profile. This is a bump up from Nano, supporting 2 or more sessions and data change notifications via a subscription. Internally, first efforts at writing a client may start here. Clients share most of the same structs as the server as well as utility code such as chunking etc. Where the client differs is that where a server deserializes certain messages and serializes others, the client does the opposite. So code must serialize and deserialize correctly. In addition the client has its own client side state starting with the HELLO, open secure channel, subscription state etc. 
* Phase 3: Phase 3 Embedded UA Server Profile. This phase will bring the UA server up to the point that it is probably useful for most day-to-day functions and most clients. It includes support for Basic1238Rsa15 and PKI infrastructure. Internally, chunks can be signed and optionally encrypted. This means code that reads data from a chunk will have to be decrypted first and any padding / signature removed. Crypto happens on a per-chunk level so chunks have to be verified, decrypted and then stitched together to be turned into messages. In addition the open secure channel code needs to cope with crypto, trust / cert failures, reissue tokens and all the other issues that may occur. 
* Phase 4 Standard UA Server Profile - Basically embedded + enhanced data change subscription server facet + X509 user token server facet

## Client

Client functionality takes second place to server functionality. Client will not happen until at least a nano server exists.

In some respects implementing the client is HARDER than server since it must maintain state and attempt to reconnect when the 
connection goes down. Client OPC UA is governed by its own core characteristics. These will be implemented to test the server functionality in general order:

* Base client behaviour facet - 
* Core client facet (crypto, security policy)
* Attribute read / write
* Datachange subscriber
* Durable subscription client (i.e. ability to reconnect and re-establish group after disconnect)

## Expected 3rd party dependencies

* log - for logging / auditing
* OpenSSL - required for crypto
* serde, server_yaml - for processing config files
* byteorder - for serializing values with the proper endian-ness
* chrono - for high quality time functions
* time - for some types that chrono still uses, e.g. Duration


