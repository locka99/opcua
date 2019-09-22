# Design

This document will document any major design decisions.

## Modules

Rust OPC UA is split over crates to facilitate building OPC UA clients or servers. 

The main crates are:

* `opcua-types` - contains machine generated types and handwritten types
* `opcua-core` - contains functionality common to client and server. This is mostly code for encoding / decoding chunks and crypto support.
* `opcua-client` - contains the client side API
* `opcua-server` - contains the server side API. The server may optionally use `opcua-client` to register the server with a local discovery server.

## Encryption

OPC UA for Rust uses OpenSSL for encryption. This decision was basically made for me since there is no Rust crate at this time
that satisfies the requirements for OPC UA. That includes:

* Hashing algorithms
* Symmetric encryption algorithms
* Asymmetric encryption algorithms
* Signing and verification algorithms
* Random number generation

TODO

## Networking

### Sychronous I/O

Early versions of OPC UA for Rust used the standard `std::net::TcpStream` for I/O but ran into some serious issues:

* TcpStream is a high level abstraction and doesn't really suit low level stacks. For example it can block or have other undesirable
  behaviours which were hard to code around when running synchronously.
   * Making it non-blocking made it spin in a loop which wasn't good either.
   * Reading and writing really needed to happen independently, e.g. on two threads necessitating thread communication.
   * I need timers too for timeouts.
* Synchronous networking doesn't scale well at all. If I have two threads per connection, then
  it isn't going to scale to 100 connections. I had a desire to make I/O scalable if at all possible.
* A lower level "metal" I/O, [mio](https://github.com/tokio-rs/mio) does exist but it is part of [Tokio](https://github.com/tokio-rs/tokio).

### Asynchronous I/O

So I decided to rewrite OPC UA for Rust to use Tokio. Tokio is implicitly asynchronous and tasks like reading and writing
from a stream are non blocking. So also for timers and other things that need to happen but shouldn't happen to the detriment of other activities.

The penalty for this is that asynchronous programming is _hard_. It's hard even in languages like JavaScript where high level
abstractions take some of the pain away. 

Basically a session is a state machine:
 
* `New`
* `WaitingHello` - waiting for a client to send a HEL message.
* `ProcessMessages` - main processing
* `Finished(StatusCode)` - Session is finished, sockets are closed. The `StatusCode` indicates why the session finished which might be
  `Good` if a normal termination occurred or another OPC UA error otherwise.
 
The main loop for a server is this:

1. for_each socket
    1. Spawn looping task
        1. Spawn hello timeout task
        2. Spawn reading task
        3. Spawn writing task
        
Each of the tasks would terminate if the state goes to `Finished`. In addition, any of the tasks could set the session to `Finished`. 
So if the Hello task times out it sets the session to finished. Then the reading / writing tasks detect the state and terminate themselves.
Likewise if the sockets experence an error they also set the `Finished` state 