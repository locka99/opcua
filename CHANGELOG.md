# Changelog

Planned future work is listed at the bottom.

## Known issues

  - Integration tests are broken and need to be fixed
  - Subscriptions / monitored items generates spurious errors on some clients

## 0.7 (in progress)
  - Address space nodes have been made more memory efficient, saving about 3MB of runtime space with
    the standard node set.
  - TODO address space. Add a create on demand callback
  - TODO gen_types.js. Refactor so it could be used to generate code for any model
  - TODO support events 
  - TODO More control over limits on the server - number of subscriptions, monitored items, sessions
  - TODO UserNameIdentityToken with encrypted password support. Plaintext password is already supported
  - TODO X509IdentityToken support 
  - TODO Integration tests are broken and need to be fixed. Integration tests should also become part
    of normal build to prevent breakages with tests tagged with `#[ignore]`
  - TODO Multiple chunk support in client and server, sending and receiving
  - TODO Session restore after disconnect in server. The server has to stash sessions that were 
    abnormally disconnected so the session state can be restored if a new connection provides the token.

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
  - New `web-client` sample is a OPCUA client that provides a simple websocket connect/disconnect/subscribe interface that
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


# Future work

## Short term
  

## Longer term
  
ASPIRATIONAL - a short list of things that would be nice to implement in the future

  - Code that generates Option<Vec<Foo>> should probably return Vec<Foo> instead to simplify access to the list
  - Multiple chunks
  - User-level permission model, i.e. ability to limit access to address space based on identity
  - Replace more OpenSSL with `ring` equivalent functions. Ring doesn't do X509 so code is still
    dependent on OpenSSL until a drop-in replacement appears - need something which can generate, read and write X509
    certs, private keys and their corresponding .der, .pem file formats.
  - Tokio codec - use a codec and frame writer to write message chunks
  - Tokio/Futures/`async`/`await` - Rust 2018 will implement new async functionality over time
    and this project will reflect best practice.
