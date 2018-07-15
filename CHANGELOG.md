# Changelog

ASPIRATIONAL - a short list of things that would be nice to implement in the near future
  - Fix subscription publish lost notifications.
  - Diagnostics.
  - Session restore after disconnect in server.
  - Session restore after disconnect in client, i.e. reconnect and resume session first and then try reconnect and recreate session.
  - Replace openssl with ring + webpki for more (but not total) rust implementation.
  - Use tokio client side. The problem here is that synchronous calls are far easier to work with, and how to make it
    work with tokio under the covers.

## 0.4 (IN PROGRESS)
  - General
    - More rigorous security checks server side and new client side certificate checking.
    - Changes to codebase for more idiomatic Rust, e.g. replacing lots of loops with iterators, providing
      `Into<Foo>` implementations instead of a multitude of constructors.
    - Certificate creator tool has new arguments to set application uri and control alternate DNS names.
    - New integration testing framework. Disabled by default, but when enabled allows client/server scenerios to be tested.
  - Client side
    - Implements client side encryption for security policies & modes other than None.
    - Moved discovery / endpoints / connection into a helper to save writing that in every client.
    - Better failure behaviour when server goes down or becomes unreachable.
    - Client crypto validates the server's cert to its hostname and rejects if it does not match.
  - Server side
    - The server network IO has been rewritten using `tokio` and `futures`. Sessions have moved from being per-thread 
      to being asynchronous tasks on the tokio / futures framework. It should be more scalable. The downside is writing
      asynchronous code is a steep learning curve.
    - Hostname resolution works. Previously endpoints had to be an IP address.
    - If the `discovery_server_url` property is set in the configuration, the server will periodically
      register itself with that discovery server. Note that the server uses the strongest endpoint to talk to the discovery
      server so you may have to make your discovery server trust the server's public cert.
    - Setting timers to poll/change values is simplified and uses tokio behind the covers. This should also be more
      efficient, however note that tokio_timer uses a "wheel" system with a 100ms granularity - any lower than this 
      and things go haywire and consume a lot of CPU.
    - The server api provides a basic web api which can be enabled through code and the compile feature `http`.
      See the demo_server/ sample which starts a server on localhost:8585
    - Finer grained locking has been used around access to structures where only read access is required
    - The server implements the OPC UA `Method::Call()` service and `GetMonitoredItems`. Add a callback framework to 
      address space allowing other methods to be implemented.
   - Samples
    - `simple-client` now takes arguments to change what config to read and to set which endpoint to use.
    - `gfx-client` is a new graphical client that subscribes to values and renders them. May not work on all platforms, 
       especially wayland on some Linux dists.
    - `mqtt-client` is work in progress client that will publish to mqtt.

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

