# Introduction

This is an [OPC UA](https://opcfoundation.org/about/opc-technologies/opc-ua/) server / client API implementation for Rust.

<table>
  <tr>
    <td><b>Linux</b></td>
    <td><a href="https://travis-ci.org/locka99/opcua" title="Travis Build Status"><img src="https://travis-ci.org/locka99/opcua.svg?branch=master"></img></a></td>
  </tr>
  <tr>
    <td><b>Windows</b></td>
    <td><a href="https://ci.appveyor.com/project/locka99/opcua" title="AppVeyor Build Status"><img src="https://ci.appveyor.com/api/projects/status/s4ndusio664o1349?svg=true"></img></a></td>
  </tr>
</table>

OPC UA is an industry standard for monitoring of data. It's used extensively for embedded devices, industrial control, IoT,
etc. - just about anything that has data that something else wants to monitor, control or visualize. 

Rust is a systems programming language and is therefore a natural choice for implementing OPC UA. This implementation 
supports the embedded, micro and nano profiles but may grow to support features in time.

Read the [compatibility](./docs/compatibility.md) page for how the implementation conforms with the OPC UA spec.

Read the [change log](./CHANGELOG.md) for changes per version as well as aspirational / upcoming work.

# License

The code is licenced under [MPL-2.0](https://opensource.org/licenses/MPL-2.0). Like all open source code, you use this code at your own risk. 

# Setup

Read the [setup](./docs/setup.md) for instructions on building OPCUA for Rust.

Read [cross compilation](./docs/cross-compile.md) for hints for cross compiling OPC UA for Rust to other 
platforms.

# Design

Read the [design](./docs/design.md) for more in-depth description of implementation.

# Tutorial

Tutorials / user guides are still work in progress. 

* [Client Tutorial](docs/client.md)
* [Server Tutorial](docs/server.md)

# Further Documentation

The API documentation is generated from the latest published crates. This may be some way behind current development. 

<table>
    <tr>
        <td><b>Client</b></td>
        <td><a href="https://docs.rs/opcua-client"><img src="https://docs.rs/opcua-client/badge.svg"></img></a></td>
        <td>Client side APIs to connect to an OPC UA server.</td>
    </tr>
    <tr>
        <td><b>Server</b></td>
        <td><a href="https://docs.rs/opcua-server"><img src="https://docs.rs/opcua-server/badge.svg"></img></a></td>
        <td>Server side APIs to host an OPC UA server, address space, create new nodes, subscriptions.</td>
    </tr>
    <tr>
        <td><b>Crypto</b></td>
        <td><a href="https://docs.rs/opcua-crypto"><img src="https://docs.rs/opcua-crypto/badge.svg"></img></a></td>
        <td>Security profiles, encryption, hashing, signing / verification, certificate management.</td>
    </tr>
    <tr>
        <td><b>Core</b></td>
        <td><a href="https://docs.rs/opcua-core"><img src="https://docs.rs/opcua-core/badge.svg"></img></a></td>
        <td>Core functionality shared by client and server - Secure channel, TCP encoding, TCP messages, chunking.</td>
    </tr>
    <tr>
        <td><b>Types</b></td>
        <td><a href="https://docs.rs/opcua-types"><img src="https://docs.rs/opcua-types/badge.svg"></img></a></td>
        <td>OPC UA core types and binary encoding implementations.</td>
    </tr>
</table>

# Samples

If you want to get stuck in, there are a number of samples in the samples/ folder. The `simple-client` and the `simple-server` projects are
minimal client and server programs respectively.

```bash
# In one bash
cd opcua/samples/simple-server
cargo run
# In another bash
cd opcua/samples/simple-client
cargo run
```

The full list of samples:

1. [`simple-server`](samples/simple-server) - an OPC UA server that adds 4 variables v1, v2, v3 and v4 and updates them from a timer via push and pull mechanisms.
2. [`simple-client`](samples/simple-client) - an OPC UA client that connects to a server and subscribes to the values of v1, v2, v3 and v4.
3. [`discovery-client`](samples/discovery-client) - an OPC UA client that connects to a discovery server and lists the servers registered on it.
4. [`chess-server`](samples/chess-server) - an OPC UA server that connects to a chess engine as its back end and updates variables representing the state of the game.
5. [`demo-server`](samples/demo-server) - an OPC UA server that will implements more functionality than the simple server and may become a compliance server in time.
6. [`mqtt-client`](samples/mqtt-client) - an OPC UA client that subscribes to some values and publishes them to an MQTT broker.
7. [`web-client`](samples/web-client) - an OPC UA client that subscribes to some values and streams them over a websocket.
8. [`modbus-server`](samples/modbus-server) - an OPC UA server that translates variables from MODBUS.