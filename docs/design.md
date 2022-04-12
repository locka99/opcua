# Design

## OPC UA

OPC UA is a very large standard. The specification runs across THIRTEEN(!) parts that describe services, address space, security, information model, mappings (communication protocol), alarms, history, discovery, aggregates and more.

This implementation obviously does not implement all that. Instead it is equivalent to the OPC UA Embedded profile, which allows for:

* Communication over opc.tcp://
* Encryption
* Endpoints
* Services
* Subscriptions and monitored items
* Events

As the project proceeds more functionality will be added with a lot of code backfilling.

## Project Layout

OPC UA for Rust is split over several crates which are periodically published:

* [`opcua-types`](../types) - contains machine generated types and handwritten types
* [`opcua-core`](../core) - contains functionality common to client and server such as encoding / decoding chunks.
* [`opcua-crypto`](../crypto) - contains all encryption functionality
* [`opcua-client`](../client) - contains the client side API
* [`opcua-server`](../server) - contains the server side API. The server may optionally use `opcua-client` to register the server with a local discovery server.
* [`opcua-certificate-creator`](../tools/certificate-creator) - a command-line tool for creating OPC UA compatible public cert and private key.

These are all published on [crates.io](https://crates.io). Generally speaking there is a 4-6 month gap between releases unless a breaking bug is found. The API tend to receive breaking changes between releases but the functionality grows and becomes more complete.

The workspace also contains some other folders:

* [`samples`](../samples) - containing various client and server examples.
* [`tools`](../tools) - various scripts and tools including scripts that machine generate OPC UA status codes, structs and node ids.
* [`integration`](../integration) - integration tests

## Testing

Unit and integration tests will cover all functional aspects of the project. In addition the implementation will be tested with 3rd party OPC UA implementations so the client / server parts can be tested in isolation.

See the [testing](./testing.md) document.

## Minimizing code through convention

OPC UA for Rust uses convention and idiomatic Rust to minimize the amount of code that needs to be written.

Here is a minimal, functioning server.

```rust
extern crate opcua;

use opcua::server::prelude::*;

fn main() {
    let server: Server = ServerBuilder::new_sample().server().unwrap();
    server.run();
}
```

This server will accept connections, allow you to browse the address space and subscribe to variables.

Refer to the [`samples/simple-server/`](../samples/simple-server) and [`samples/simple-client/`](../samples/simple-client) examples
for something that adds variables to the address space and changes their values.

## Types

OPC UA defines a lot of types. Some of those correspond to Rust primitives while others are types, structures or enums which are used by the protocol. All types are defined in the [`opcua-types`](../types) crate.

All types can be encoded / decoded to a stream according to the opc.tcp:// binary transport. They do so by implementing a `BinaryEncoder` trait. The three functions on this trait allow a struct to be deserialized, serialized, or the byte size of it to be calculated.

Typically encoding will begin with a structure, e.g. `CreateSubscriptionRequest` whose implementation will encode each member in turn.

Types can also be encoded into `ExtensionObject`s in a simple fashion.

```rust
let operand = AttributeOperand { /* ... */ };
let obj = ExtensionObject::from_encodable(ObjectId::AttributeOperand_Encoding_DefaultBinary, operand);
```

And out:

```rust
let decoding_options = DecodingOptions::default();
let operand = obj.decode_inner::<AttributeOperand>(&decoding_options)?;
```

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

The OPC UA type `String` is not directly analogous to a Rust `String`. The OPC UA definition maintains a distinction between being a null value and being an empty string. This affects how the string is encoded and could impact on application logic too.

For this reason, `String` is mapped onto a new Rust type `UAString` type which captures this behaviour. Basically it is a struct that holds an optional `String` where `None` means null. The name is `UAString` because `String` is such a fundamental type that it is easier to disambiguate by calling it something else rather than through module prefixing.

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

A `Variant` is a special catch-all enum which can hold any other primitive or basic type, including arrays of the same. The implementation uses a `Box` (allocated memory) for larger kinds of type to keep the stack size down.

### Machine generated types

Machine generated types reside in `types/src/service_types`. The `enums.rs` holds all of the enumerations. A special `impls.rs` contains additional hand written functions that are associated with types.

The `tools/schema/` directory contains NodeJS scripts that will generate Rust code from OPC UA schemas.

* Status codes
* Node Ids (objects, variables, references etc.)
* Data structures including serialization.
* Request and Response messages including serialization
* Address space nodes

## Handling OPC UA names in Rust

All OPC UA enums, structs, fields, constants etc. will conform to Rust lint rules where it makes sense. i.e. OPC UA uses pascal case for field names but the impl will use snake case, for example `requestHeader` is defined as `request_header`.

```rust
struct OpenSecureChannelRequest {
  pub request_header: RequestHeader
}
```

Enums are scalar.

```rust
pub enum SecurityPolicy {
  Invalid = 0,
  None = 1
  ...
}
```

The enum will be turned in and out of a scalar value during serialization via a match.

Wherever possible Rust idioms will be used - enums, options and other conveniences of the language will be used to represent data in the most efficient and strict way possible. e.g. here is the ExtensionObject

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

OPC UA has some really long PascalCase ids, many of which are further broken up by underscores. I've tried converting the name to upper snake and they look terrible. I've tried removing underscores and they look terrible.

So the names and underscores are preserved as-in in generated code even though they generate lint errors. The lint rules are disabled for generated code.

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

The enum will also implement `Copy` so that status codes are copy on assign. The enum provides helpers `is_good()`, `is_bad()`, `name()` and `description()` for testing and debugging purposes. It also provides functions for turning the code into and out of a UInt32 and masking status / info bits.

## Formatting

All code (with the exceptions noted for OPC UA) should be follow the most current Rust RFC coding guidelines for naming conventions, layout etc.

Code should be formatted with the IntelliJ rust plugin, or with rustfmt.

## Encryption

OPC UA for Rust uses OpenSSL for encryption. This decision was basically made for me since there is no Rust crate at this time that satisfies the requirements for OPC UA. That includes:

* Message digest - SHA1, SHA256
* Symmetric encryption algorithms - AES128 CBC, AES256 CBC
* Asymmetric encryption algorithms - RSA_15, RSA_OAEP
* Hash message authentication codes - HMACs
* Certificate creation - X509
* Reading and writing certificate and private key file formats - .pem and .der
* Random numbers - PRNG

## Address Space

The server maintains an address space. The `AddressSpace` struct manages the address space.

Each nodes in the address space is stored in a big hash map keyed by their `NodeId`. The value is enum called a `NodeType` that is one of the standard OPC UA node types:

* DataType
* Method
* Object
* ObjectType
* ReferenceType
* Variable
* VariableType
* View

References are managed by a `References` struct which has a map of vectors of outgoing references from a node. Each `Reference` has a reference type id (a `NodeId`) indicating what the refeence is, and the `NodeId` of the target node. `References` also maintains a reverse lookup map so it can tell if a target is referenced by another node.

### Generated nodeset

Calling `Address::new()` automatically populates itself with the default nodeset. The population code is machine generated and resides under `server/src/address_space/generated`.

## Encryption

Encryption is through functions that call onto OpenSSL. See this [document](crypto.md) for information.

## Networking

### Asynchronous I/O

Tokio is used to provide asynchronous I/O and timers.

* Futures based - actions are defined as promises which are executed asynchronously.
* I/O is non-blocking.
* Inherently multi-threaded via Tokio's executor.
* Supports timers and other kinds of asynchronous operation.

The penalty for this is that asynchronous programming can be _hard_. Fortunately Rust has acquired  new `async` and `await`
keyword functionality that simplifies the async logic a bit, but it can still get hairy in places. 

In the new async world a session is a state machine:

* `New`
* `WaitingHello` - waiting for a client to send a HEL message.
* `ProcessMessages` - main processing
* `Finished(StatusCode)` - Session is finished, sockets are closed. The `StatusCode` indicates why the session finished which might be
  `Good` if a normal termination occurred or another OPC UA error otherwise.

There are tasks running to monitor the health of the session and finish it if it goes into error. When it goes into error the socket must close and all tasks terminate.

The main loop for a server is this:

1. for_each socket
    1. Spawn looping task
        1. Spawn hello timeout task (mpsc sender). Runs at connect waiting for HELLO and then exits or sets Finished if it timesout.
        2. Spawn reading task (mpsc sender). The reader waits for complete messages to arrive
        3. Spawn writing task (mpsc receiver). The writer waits on messages to either quit or write something.
        4. Spawn finished monitor task (mpsc sender). Checks for finished state.

Each of the tasks would terminate if the state goes to `Finished`. Any task can also set the state to `Finished`
for whatever reason - timeout, encoding error etc. The mpsc senders can send a Quit to the writer to wait it from its
slumber and shutdown the socket.

So if the Hello task times out it sets the session to `Finished`, sends a quit to the writer. This breaks the reader and
writer loop and also the finished monitor.

When a session ends in a Finished state it will hold a status code explaining the reason for finishing.

## Implementation plan

Client and server will work their ways through OPC UA profiles to the point of usability. But presently they are working towards.

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

This [OPC UA link](http://opcfoundation-onlineapplications.org/ProfileReporting/index.htm) provides interactive and descriptive information about profiles and relevant test cases.

## Major 3rd party dependencies

* log - for logging / auditing
* openssl - cryptographic functions for signing, certifications and encryption/decryption
* serde, server_yaml - for processing config files
* clap - used by sample apps & certificate creator for command line argument processing
* byteorder - for serializing values with the proper endian-ness
* tokio - for asynchronous IO and timers
* futures - for futures used by tokio
* chrono - for high quality time functions
* time - for some types that chrono still uses, e.g. Duration
* random - for random number generation in some places

## 3rd-party servers

There are also a couple of [node-opcua](https://github.com/node-opcua) scripts in `3rd-party/node-opcua`.

1. `client.js` - an OPC UA client that connects to a server and subscribes to v1, v2, v3, and v4.
2. `server.js` - an OPC UA server that exposes v1, v2, v3 and v4 and changes them from a timer.

These are functionally analogous to `simple-server` and `simple-client` so the Rust code can be tested against an independently written implementation of OPC UA that works in the way it is expecting. This is useful for debugging and isolating bugs / differences.

To use them:

1. Install [NodeJS](https://nodejs.org/) - LTS should do, but any recent version should work.
2. `cd 3rd-party/node-opcua`
3. `npm install`
4. `node server.js` or `node client.js`
