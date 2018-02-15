# Intro

`simple-server` demonstrates a fairly minimal, but functioning OPC UA server demonstrating how the APIs work. 

Essentially it does the following.

1. Sets up an OPC UA server, reading its endpoint configuration from ../server.conf
2. Adds variables v1, v2, v3 and v4 to the address space and hooks them up so their values change
3. Launches server, accepting connections on the configured endpoints.

Two variables v1 and v2 are updated from within a timer proc. Two variables v3 and v4 are polled from getter methods.
This demonstrates two ways you can hook up variables with values.

## Crypto

The sample server also creates a pki/ folder with a certificate and key and implements a simple trust model.

Basically when a client connects to the server and wishes to use crypto it must present its public cert. The server will
check the cert and if it does not recognize it will write it to the `pki/rejected/` folder. In order to make the cert trusted,
the administrator (i.e. you) must move the `.der` file from `pki/rejected` into `pki/trusted`. Once that is done the server
will trust the client and allow it to establish a connection. 

# Build instructions

Build and run like this:

```
cargo run
```

# Connecting

Use an OPC UA client to connect to the server, e.g. if you have NodeJS you can do this:

```
npm install -g opcua-commander
opcua-commander -e opc.tcp://127.0.0.1:4855
```

