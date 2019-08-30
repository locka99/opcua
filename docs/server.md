# Server

This is a small tutorial for using the OPC UA server library. It will assume you are familiar with OPC UA,
Rust and tools such as `cargo`.

1. A small overview of OPC UA is [here](./opc_ua_overview.md).
2. Rust OPC UA's compatibility with the standard is described [here](./compatibility.md). 

## Server API

The Rust OPC UA server API supports all of the OPC UA embedded profile services and a few of the standard profile
services. 

These are implemented for you so generally once you create a server configuration,
set up an address space and register some callbacks you are ready to run a server.

## Lifecycle

1. Create or load a configuration
2. Create a server
3. Populate additional nodes into the address space
4. Run the server
5. Server runs forever, listening for connections.

## Create a simple project

We're going to start with a blank project. 

```
cargo init --bin test-server
```

## Import the OPC UA server crate

## Import types

## Create your server

### Configure the server

The server can be configured in a number of ways:

1. A `ServerBuilder` is the easiest way to build a server programatically.
2. A configuration file described in yaml that you create a server from.

#### ServerBuilder

A `ServerBuilder` allows you to programatically construct a `Server`.

```rust
let server = ServerBuilder::new()
    .application_name("Server Name")
    .application_uri("urn:server_uri")
    .discovery_urls(vec![endpoint_url(port_offset)])
    .create_sample_keypair(true)
    .pki_dir("./pki-server")
    .discovery_server_url(None)
    .host_and_port(hostname(), 1234)
    .user_token(sample_user_id, ServerUserToken::new_user_pass("sample", "sample1"))
    .endpoints(
        [
            ("none", endpoint_path, SecurityPolicy::None, MessageSecurityMode::None, &user_token_ids),
            ("basic128rsa15_sign", endpoint_path, SecurityPolicy::Basic128Rsa15, MessageSecurityMode::Sign, &user_token_ids),
            ("basic128rsa15_sign_encrypt", endpoint_path, SecurityPolicy::Basic128Rsa15, MessageSecurityMode::SignAndEncrypt, &user_token_ids),
            ("basic256_sign", endpoint_path, SecurityPolicy::Basic256, MessageSecurityMode::Sign, &user_token_ids),
            ("basic256_sign_encrypt", endpoint_path, SecurityPolicy::Basic256, MessageSecurityMode::SignAndEncrypt, &user_token_ids),
            ("basic256sha256_sign", endpoint_path, SecurityPolicy::Basic256Sha256, MessageSecurityMode::Sign, &user_token_ids),
            ("basic256sha256_sign_encrypt", endpoint_path, SecurityPolicy::Basic256Sha256, MessageSecurityMode::SignAndEncrypt, &user_token_ids),
        ].iter().map(|v| {
            (v.0.to_string(), ServerEndpoint::from((v.1, v.2, v.3, &v.4[..])))
        }).collect())
    .server().unwrap();
```

#### From configuration file

Reading from file can be done like so.

```rust
let mut server = Server::new(ServerConfig::load(&PathBuf::from("../server.conf")).unwrap());
```

Alternatively, let's say you use a configuration file, but how do you create it when one isn't there? Well your code 
logic could test if the file can load, and if it doesn't, could create the default one with a `ServerBuilder`.

```rust
let server_config_path = "./myserver.conf";
let server_config = if let Ok(server_config) = ServerConfig::load(&PathBuf::from(server_config_path))) {
    server_config
}
else {
    let server_config = ServerBuilder::new()
        .application_name("Server Name")
        .application_uri("urn:server_uri")
        //... Lines deleted
        .config();
    server_config.save(server_config_path);
    server_config
}
let mut server = Server::new(server_config);
```

### Security

The server configuration determines what encryption it uses on its endpoints, and also what user identity tokens
it accepts.

The client and server can communicate over an insecure or a secure channel. 

1. An insecure channel is plaintext and is not encrypted in any way. This might be fine where trust is implicit and
controlled between the client and the server, e.g. when they reside on a private network, or even the same device. 
2. A secure channel. The client presents a certificate to the server, the server presents a certificate to the client.
Each must trust the other, at which point the session proceeds over an encrypted channel.

Once the client establishes a session with the server, the next thing it will do is present its identity for activating
the session. The identity is the user's credentials which can be anonymous, user / password or X509 identity token.

### Set up your address space

Your server has an address space that usually contains the default OPC UA node set. The default node set describes
all the standard types, server diagnostics variables and more besides.

To this you may wish to add your own objects and variables.

### Create a variable Getter

### Run the server

Running a server is a synchronous action:

```rust
// Run the server. This does not ordinarily exit so you must Ctrl+C to terminate
server.run();
```

If you prefer to make it asynchronous, run it on a separate thread, or use `Server::run_server`.

## Logging

OPC UA for Rust provides an extensive amount of logging at error, warn, info, debug and trace levels. All this is via
the standard [log](https://docs.rs/log/0.4.8/log/) facade so choose which logging implementation you want 
to capture information. See the link for implementations that you can use.

### Console logging

For convenience OPC UA for Rust provides a simple `opcua-console-logging` crate that wraps [env_logger](https://docs.rs/env_logger/0.6.2/env_logger/)
and writes out logging information to stdout. To use it, set an `RUST_OPCUA_LOG` environment variable (not `RUST_LOG`),
otherwise following the documentation in `env_logger`. e.g.

```shell script
export RUST_OPCUA_LOG=debug
```

In your `Cargo.toml`:

```toml
[dependencies]
opcua-console-logging = "0.7.0" # Where version == version of OPC UA for Rust
```

In your `main()`:

```rust
fn main() {
    opcua_console_logging::init();
    //...
}
```

### log4rs
 
The `demo-server` sample demonstrates more sophisticated logging using the [log4rs crate](https://github.com/sfackler/log4rs).
