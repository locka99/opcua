# Changelog

## 0.10
- Starting from 0.10, OPC UA for Rust is a single crate with features to enable client, server and some other optional extras. What this means is
  that `opcua_server::` becomes `opcua::server`, `opcua_client` becomes `opcua::client` and so on. Now you only reference `opcua` from your `Cargo.toml`.
- Replace Appveyor and Travis with Github Actions for CI/CD pipeline

## 0.9
- Multiple chunk support in client and server, sending and receiving.
- Upgrade from Tokio 0.1 to 1.x long term support and use `async` / `await` semantics to simplify tasks
- Support `Aes256-Sha256-RsaPss` security policy
- Support `rsa-oaep-sha2-256` encryption for identity tokens
- Check that the server's key length is sufficient for every endpoint it is configured for
- Improve client performance by removing polling loop sleep interval and using oneshot channels
- Compliance improvements

## 0.8
- Numerous OPC UA compliance fixes with emphasis on nano / micro profile server compliance.
- Support single dimension index range on Attribute service read 
- Cryptography functionality has been moved into an opcua-crypto crate
- Update to OPC UA 1.04 schemas and definitions
- Replace `clap` for `pico-args` to process command line args. This reduces dependencies, compilation time and binary size.
- Simplify `opcua-types`:
- TCP types and url helpers have moved to `opcua-core`
- `SupportedMessage` and helper macros have moved `opcua-core`
- New `NodeClassMask` bitflags.
- Move `BrowseDescriptionResultMask` from `opcua-server` to `opcua-types`.
- The `gen_nodeset.js` script can be used to compile external NodeSet files into Rust and there is some documentation in the
folder's [README](./tools/schema/README.md) on how to do it.
- Support `Aes128-Sha256-RsaOaep` security policy.
- Audit events are generated for the session service and certificate errors.
- Reject connection if the certificate key length is outside the min/max length range for the security profile.
- Add copyright info to all source code with exception of test files

## 0.7
- Minimum compiler is Rust 1.37 or later due to use of Self on enums and other uses of refined syntax.
- Fixed a memory leak issue when some client tasks failed to terminate causing tokio / threads to not terminate.
- Fixed resource leaks where server would not close the socket or could leave tasks running even after the session
  ended.
- Events are supported
   - Servers can raise / purge events and the monitored item service supports `EventFilter` for filtering
     and selecting results. 
   - Clients can subscribe to the event notifier attribute on nodes using `EventFilter`.
   - Sample `web-client` has a simple web interface prefilled for subscribing to items & events from `demo-server`.
- Address space
   - Server side `AddressSpace` has been made more generic and less complex.
   - Every node type has a builder, e.g. `Variable` has a `VariableBuilder`. Builders can
     be used to set the attributes and common references for that type.
   - Nodes are more memory efficient. In 0.6 every attribute was held in `DataValue` arrays 
     which bloated memory. Now only the `value` attribute remains stored as a `DataValue` 
     and primitives are used for all other attributes.
   - Superfluous hierarchical references between nodes have been removed.
   - New gen_nodeset.js script that can do node set generation from a schema. The script
     gen_address_space.js refactored into a helper nodeset.js to reuse the code for this.
- Add conditional build features to server's `Cargo.toml` to disable the default address space nodeset and local
  discovery server registration. Turning off these features can save memory.      
- Client and server side support for encrypted passwords within user name identity tokens.
- Client and server side support for X509 identity tokens.
- New `modbus-server` sample server connects to a MODBUS device and presents values through OPC UA.
- Tutorials for [Client](docs/client.md) and [Server](docs/server.md). 
- More control over limits on the server - number of subscriptions, monitored items, sessions, min publishing interval
- Integration test framework with tests for some basic client / server scenarios such as connecting / disconnecting
  with different security policies.
- Enumerations defined in the OPC UA schema are now machine generated instead of hand-written.

## 0.6
- Rust 2018. All `Cargo.toml` files now contain `edition = "2018"` and the code has been cleaned up to benefit from 
  some of the improvements in the language. e.g. many `extern crate` declarations have been removed. Your own code
  can be Rust 2015 but you must build with Rust 1.31 or later.
- Client API has been simplified for ad hoc connections and with better documentation.
- Client API will reconnect and restore subscriptions after a disconnect from a server. Reconnection is 
  controlled by a session retry policy.
- Improved subscription & monitored item behaviour in server, e.g. notifications are acknowledged upon
  receiving a publish request (per spec) instead of later so clients complaining about available
  notifications they've already acknowledged. 
- TranslateBrowsePathsToNodeIds service has been fixed
- AddNodes, AddReferences, DeleteNodes and DeleteReferences added to the Node Management service set. Note
  that the server config / builder must set `clients_can_modify_address_space` to be true or these will return an 
  error. Only minimal model constraint checking is performed.
- RegisterNodes and UnregisterNodes added to View service set. Servers must implement callbacks for these
  to do anything.
- SetTriggering and SetMonitoringMode added to the Monitored Item service set
- TransferSubscriptions service is implemented as a stub. Most clients will see the error response and failover
  to manually reconstructing their subscription state.
- New `web-client` sample is a OPC UA client that provides a simple websocket connect/disconnect/subscribe interface that
  streams notifications to a browser.
- Support `vendored-openssl` feature of OpenSSL (see [setup](./docs/setup.md) documentation.

## 0.5
- Tokio codec - use a codec and frame reader to read message chunks.
- Better documentation both in markdown and for the client / server APIs.
- Server diagnostics in address space / metrics are more complete
- Http status page is nicer to look at and more compact
- Status codes are changed from an enum to using bitflags!() macro. Other flags are also changed to use bitflags.
- Builder patterns - `ServerBuilder` and `ClientBuilder` simplify creating a `Server` and `Client` respectively.
- Server enforces decoding limits on strings, byte strings and arrays. 
- Implement the mqtt-client sample
  
## 0.4
- General
  - More rigorous security checks server side and new client side certificate checking.
  - Changes to codebase for more idiomatic Rust, e.g. replacing lots of loops with iterators, providing
    `Into<Foo>` implementations instead of a multitude of constructors.
  - Certificate creator tool has new arguments to set application uri and control alternate DNS names.
  - Various OPC UA correctness fixes.
  - Updates to various dependencies.
- Client
  - Client network IO has been rewritten using `tokio` and `futures`. Note that the client API is still synchronous, 
    i.e your code calls a function that returns with a result or an error.
  - Client side encryption
  - Moved discovery / endpoints / connection into a helper fn
  - Better failure behaviour when server goes down or becomes unreachable.
  - Better subscription support - number of publish requests scale with number of subscriptions
  - Client validates the server's cert to its hostname and application uri and rejects if it does not match.
- Server
  - Server network IO has been rewritten using `tokio` and `futures`. Sessions have moved from being per-thread 
    to being asynchronous tasks on the tokio / futures framework. It should be more scalable. 
  - Hostname resolution works. Previously endpoints had to be an IP address.
  - Subscriptions are far more reliable than before. 0.3 could drop notifications and had reporting problems when
    monitored items had their own sampling intervals.
  - If the `discovery_server_url` property is set in the configuration, the server will periodically
    register itself with that discovery server. You may have to make your discovery server trust your server's 
    public cert for registration to succeed.
  - Using timers to poll/change values is simplified and now uses tokio timer behind the covers.
  - The server api provides a basic web server for metrics monitoring which can be enabled through code and the
    compile feature `http`. This is not support for OPC over http. See the demo_server/ sample which starts a server
    on localhost:8585
  - Finer grained locking has been used around access to structures where only read access is required.
  - The server implements the OPC UA `Method::Call()` service and `GetMonitoredItems`. Add a callback framework to 
    address space allowing other methods to be implemented.
 - Samples
  - `simple-client` now takes arguments to change what config to read and to set which endpoint to use.
  - `gfx-client` is a new graphical client that subscribes to values and renders them. May not work on all platforms, 
     especially wayland on some Linux dists.
  - `mqtt-client` is work in progress client that will publish to mqtt.
 - Certificate creator
  - Now sets the application uri and alt hostnames properly and has new arguments to control how alt hostnames are
    added.
 - Testing
  - More unit tests.
  - `integration` is a new integration testing suite that allows the code to create a server and then connect to it
    from a client. This has to be run manually and is not part of the standard `cargo test` because tests must be
    run sequentially. Refer to `integration/README.md`.

## 0.3
- General
  - Numerous enhancements
  - Replace a lot of conventional loops with iterators using filter, find, map, collect etc.
  - More impls of From<> and Into<> traits, replacing proprietary functions
  - Reduce the amount of imports by refactoring code, moving types to their own files
- Core and types
  - StatusCode values have switched naming convention from BAD_UNEXPECTED to BadUnexpected 
  - Code generation produce nicer output with less unused imports
  - Generated types now go into types/src/service_types
  - Security channel code is more server / client agnostic
  - Crypto cert generator inserts a random serial # value which some 3rd party OPC impls check for
  - Implement NumericRange
  - Simplify implementation of DateTime
  - Simplify implementation of Guid
  - Fix some issues with numeric node ids serialization. Implement binary node ids
- Client side
  - Add client side helpers that call most services implemented server side
  - Add a discovery api
  - Add configuration file support
  - Add subscription and monitored items support
  - A lot of work to get crypto working client side (but its not there yet)
- Server side
  - Better implementation of subscription / monitored item.
  - Implement Republish
  - Revised config file format to more cleanly support different token types
  - Changes to how locks are held on major components like address space, server, session
  - Partial impl of discovery server
  - Partial impl of diagnostics 
- Samples
  - simple-client now has a --subscribe arg to exercise new subscription APIs
  - New sample discovery-client demonstrates a client which calls a discovery server
  - New sample demo-server tests all standard OPC UA variant types. It will grow to add more in time.
  - Some http server stubbing done to allow metrics to be published. Not functional.
  
## 0.2 
- server side crypto / pki architecture
- Implements service calls that were stubbed or partially implemented in 0.1.
- New sample chess-server
- Improved test cases
- Refactor code to reduce build times.
  
## 0.1 initial release 
- Nano implementation

# More future work
  
This work is note earmarked for any release and is aspirational in nature:

## Short term

- identify issue with monitored items stalling sometimes, spurious acknowledgment errors on some clients
- Session restore after disconnect in server. The server has to stash sessions that were 
  abnormally disconnected so the session state can be restored if a new connection provides the token.
- Prevent nested arrays from being deserialized.
- Add more session diagnostics to the address space
- Better access control, i.e. user access level reflecting the active session
- Certificate trust via signed certificate chain / trusted cert store
- ReadValueId and HistoryReadValueId should check the data_encoding field, validate it and attempt
    to return the DataValue with the value encoding as per spec.
- ReadValueId should check the index_range field to return an element or range of elements from an array.
- Certificate should support .pem format, or allow either .pem or .der. A .pem certificate can have a chain of 
    signatures rather than just a single signer.
  
## Longer term

- More asynchronous actions internal to the server and client, possibly also the client api and some callbacks. 
    - On the server side certain service calls could be handled asynchronously and not in order, whereas some others cannot. 
    At the moment messages are processed in the order received, even for potentially lengthy operations such as reads & writes.
- User-level permission model, i.e. ability to limit access to address space based on identity
- Replace more OpenSSL with a native Rust equivalent library. Must support all the crypto, hashing / digest and key
  creation APIs required by the lib. See this [doc](./docs/crypto.md) for the effort required.
- Tokio codec - use a codec and frame writer to write message chunks
- Model enforcement rules for address space data coherence. At present, the server is expected to just know what it is
  doing. Perhaps that is a reasonable thing to assume.
- There should be some helper macros for Methods that enforce the number of args and ensure the type of arguments
