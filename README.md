# Introduction

This is an [OPC UA](https://opcfoundation.org/about/opc-technologies/opc-ua/) server / client API implemented in Rust.

[![Travis Build Status](https://travis-ci.org/locka99/opcua.svg?branch=master)](https://travis-ci.org/locka99/opcua)
[![AppVeyor Build Status](https://ci.appveyor.com/api/projects/status/s4ndusio664o1349?svg=true)](https://ci.appveyor.com/project/locka99/opcua)

OPC UA is an industry standard for monitoring of data. It's used extensively for embedded devices, industrial control, IoT,
etc. - just about anything that has data that something else wants to monitor, control or visualize. 

Rust is a systems programming language and is therefore a natural choice for implementing OPC UA. This implementation 
supports the embedded, micro and nano profiles but may grow to support features in time.

# License

The code is licenced under [MPL-2.0](https://opensource.org/licenses/MPL-2.0). Like all open source code, you use this code at your own risk. 

# Documentation

See the [CHANGELOG.md](./CHANGELOG.md) for changes per version as well as aspirational / upcoming work.

See the [design docs](./docs/README.md) for more in-depth thoughts on the whys and wherefores of implementing OPC UA in Rust.

The documentation is generated from the latest published crates which may be some way behind current development. 

- [![Client](https://docs.rs/opcua-client/badge.svg)](https://docs.rs/opcua-client) - the client-side API.
- [![Server](https://docs.rs/opcua-server/badge.svg)](https://docs.rs/opcua-server) - the server-side API.
- [![Core](https://docs.rs/opcua-core/badge.svg)](https://docs.rs/opcua-core) - core functionality used by client and server.
- [![Types](https://docs.rs/opcua-types/badge.svg)](https://docs.rs/opcua-types) - structures, requests, responses and enums. 

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

1. `simple-server` - an OPC UA server that adds 4 variables v1, v2, v3 and v4 and updates them from a timer via push and pull mechanisms.
2. `simple-client` - an OPC UA client that connects to a server and requests the values of v1, v2, v3 and v4. It may also subscribe to changes to these values.
3. `discovery-client` - an OPC UA client that connects to a discovery server and lists the servers registered on it.
4. `gfx-client` - an OPC UA client that displays changing values graphically.
5. `chess-server` - an OPC UA server that connects to a chess engine as its back end and updates variables representing the state of the game.
6. `demo-server` - an OPC UA server that will implements more functionality than the simple server and may become a compliance server in time.
