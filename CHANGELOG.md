# Changelog

ASPIRATIONAL - a short list of things that would be nice to implement in the near future
  - Fix subscription publish lost notifications
  - Diagnostics
  - Session restore after disconnect in server
  - Session restore after disconnect in client, i.e. reconnect and resume session first and then try reconnect and recreate session.
  - More security / validation / enforcement around client certs that do not match app descriptions or DNS info
  - Replace openssl with ring + webpki for more (but not total) rust implementation
  - Use tokio client side. The problem here is that synchronous calls are far easier to work with, and how to make it
    work with tokio under the covers.

## 0.4 (IN PROGRESS)
  - General
    - More rigorous security checks server side
    - Changes to codebase for more idiomatic Rust
  - Client side
    - Add client side encryption for security policies & modes other than None. At present the client
      doesn't validate the server's cert as stringently as it should.
    - Simple-client sample takes arguments to change what config to read and to set which endpoint to use.
    - Moved discovery / endpoints / connection into a helper to save writing that in every client
    - Better failure behaviour when server goes down or becomes unreachable
  - Server side
    - The server network IO is rewritten using tokio and futures. Sessions move from being a thread each with its own
      synchronous IO to sharing threads and asynchronous IO. It should be more scalable. The downside is writing
      asynchronous code is a steep learning curve.
    - If discovery_server_url property is set in the config the server shall attempt to periodically
      register itself with a discovery server. Note that the server uses the strongest endpoint to talk to the discovery
      server so you may have to make your discovery server trust the server's public cert.
    - Setting timers to poll/change values is simplified and uses tokio behind the covers. This should also be more
      efficient.
    - The server provides a basic web api which can be enabled through code. See the demo_server/ sample which
      starts a server on localhost:8585
    - Finer grained locking around some structures where only read access is required
    - Implement Method::Call() service and GetMonitoredItems. Add a callback framework to address space allowing 
      other methods to be implemented.

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

