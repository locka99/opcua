# Changelog

ASPIRATIONAL - a short list of things that would be nice to implement in the near future

  - Replace more OpenSSL with `ring` equivalent functions. Ring doesn't do X509 so code is still
    dependent on OpenSSL until a drop-in replacement appears - need something which can generate, read and write X509
    certs, private keys and their corresponding .der, .pem file formats.

## 0.5 (WORK IN PROGRESS - WIP)
  - Tokio codec - use a codec and frame reader to read message chunks.
  - (WIP) Rust 2018. All code will be ported to the 2018 spec. This will clean up code like match statements, extern crates etc. 
    that benefit from greater inference.
  - (WIP) Tokio codec - use a codec and frame writer to write message chunks
  - Better documentation both in markdown and for the client / server APIs.
  - (WIP) Session restore after disconnect in server. The server has to stash sessions that were abnormally disconnected
    so the session state can be restored if a new connection provides the token.
  - (WIP) Session restore after disconnect in client, i.e. attempt to reconnect and resume session first and if that
    fails manually reconstruct the session - subscriptions and monitored items.
  - Server diagnostics in address space / metrics are more complete
  - Http status page is nicer to look at and more compact
  - Status codes are changed from an enum to using bitflags!() macro. Other flags are also changed to use bitflags.
  - Add a `ServerBuilder` and `ClientBuilder` to simplify creating a `Server` and `Client` respectively.
  - Server enforces decoding limits on strings, byte strings and arrays. 
  
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

