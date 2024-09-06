# Server

This is a small tutorial for using the OPC UA server library. It will assume you are familiar with Rust and tools such as `cargo`. 

1. A small overview of OPC UA is [here](./opc_ua_overview.md).
2. Rust OPC UA's compatibility with the standard is described [here](./compatibility.md). 

## Server API

The Rust OPC UA server API supports all of the OPC UA embedded profile services and a few of the standard profile services. 

These are implemented for you so generally once you create a server configuration, set up an address space and register some callbacks you are ready to run a server.

## Lifecycle

1. Create or load a configuration that defines the TCP address / port server runs on, the endpoints it supports, user identities etc.
2. Create a server from the configuration
3. Populate additional nodes into the address space and callbacks / timers that change state.
4. Run the server
5. Server runs forever, listening for connections.

## Create a simple project

We're going to start with a blank project. 

```
cargo init --bin test-server
```

## Import the OPC UA server crate

To use the server crate we need to add a dependency to the `Cargo.toml`.

```
[dependencies]
opcua = { "0.12", features = ["server"] }
```

## Create your server

### Configure the server

The server can be configured in a number of ways:

1. A `ServerBuilder` is the easiest way to build a server programmatically.
2. A configuration file described in yaml or some other `serde` supported format that you read from.

#### ServerBuilder

A `ServerBuilder` allows you to programmatically construct a `Server`.

```rust
use std::sync::Arc;

use opcua::server::address_space::Variable;
use opcua::server::node_manager::memory::{
    InMemoryNodeManager, NamespaceMetadata, SimpleNodeManager, SimpleNodeManagerImpl,
};

#[tokio::main]
async fn main() {
    // First, create a simple node manager to contain any custom nodes we make.
    // The namespace should be 2 here, since there are two default namespaces, making
    // this the third.
    let ns = 2;
    let node_manager = Arc::new(SimpleNodeManager::new_simple(
        NamespaceMetadata {
            namespace_index: ns,
            namespace_uri: "urn:my_server".to_owned(),
            ..Default::default()
        },
        "simple",
    ));

    let (server, handle) = ServerBuilder::new()
        .application_name("Server Name")
        .application_uri("urn:server_uri")
        .discovery_urls(vec![endpoint_url(port_offset)])
        .create_sample_keypair(true)
        .pki_dir("./pki-server")
        .discovery_server_url(None)
        .host(hostname())
        .port(1234)
        .add_user_token(
            sample_user_id,
            ServerUserToken::new_user_pass("sample", "sample1"),
        )
        .add_endpoint(
            "none",
            (
                endpoint_path,
                SecurityPolicy::None,
                MessageSecurityMode::None,
                &user_token_ids as &[&str],
            ),
        )
        .add_endpoint(
            "basic128rsa15_sign",
            (
                endpoint_path,
                SecurityPolicy::Basic128Rsa15,
                MessageSecurityMode::Sign,
                &user_token_ids as &[&str],
            ),
        )
        .build().unwrap();

    // Add initial nodes here...

    // Run the server.
    server.run().await.unwrap();
}
```

#### From configuration file

If you prefer to construct your server from a configuration that you read from a file you can do that instead.

```rust
fn main() {
    // The namespace should be 2 here, since there are two default namespaces, making
    // this the third.
    let ns = 2;
    let node_manager = Arc::new(SimpleNodeManager::new_simple(
        NamespaceMetadata {
            namespace_index: ns,
            namespace_uri: "urn:SimpleServer".to_owned(),
            ..Default::default()
        },
        "simple",
    ));

    let (server, handle) = ServerBuilder::new()
        .with_config_from("../server.conf")
        .with_node_manager(node_manager.clone())
        .build()
        .unwrap();
    //...
}
```

Alternatively, let's say you use a configuration file, but how do you create it when one isn't there? Well your code logic could test if the file can load, and if it doesn't, could create the default one with a `ServerBuilder`.

```rust
#[tokio::main]
async fn main() {
    let server_config_path = "./myserver.conf";
    let server_config = if let Ok(server_config) = ServerConfig::load(&PathBuf::from(server_config_path)) {
        server_config
    }
    else {
        let server_config = ServerBuilder::new()
            .application_name("Server Name")
            .application_uri("urn:server_uri")
            //... Lines deleted
            .config();
        // Now we save it so its there next time
        server_config.save(server_config_path);
        server_config
    }
    let mut server = Server::new(server_config);
}
```

#### TCP Configuration

The default TCP config uses an address / port of `127.0.0.1` and `4855`. If you intend for your server
to be remotely accessible then explicitly set the address to the assigned IP address or resolvable hostname for the network adapter your server will listen on.

Also ensure that your machine has a firewall rule to allow through the port number you use. 

### Security

The server configuration determines what encryption it uses on its endpoints, and also what user identity tokens it accepts.

The client and server can communicate over an insecure or a secure channel. 

1. An insecure channel is plaintext and is not encrypted in any way. This might be fine where trust is implicit and controlled between the client and the server, e.g. when they reside on a private network, or even the same device. 
2. A secure channel. The client presents a certificate to the server, the server presents a certificate to the client. Each must trust the other, at which point the session proceeds over an encrypted channel.

Once the client establishes a session with the server, the next thing it will do is present its identity for activating the session. The identity is the user's credentials which can be anonymous, user / password or X509 identity token.

### Set up your address space

Your server has an address space that contains the default OPC UA node set. The default node set describes all the standard types, server diagnostics variables and more besides.

To this you may wish to add your own objects and variables. To make this easy, you can
create new nodes with a builder, e.g:

```rust
#[tokio::main]
async fn main() {
    //... after server is set up
    let address_space = node_manager.address_space();
    let address_space = address_space.write().unwrap();

    // This is a convenience helper
    let folder_id = NodeId::new(2, "Variables");
    address_space.add_folder(&folder_id, "Variables", "Variables", &NodeId::objects_folder_id());

    // Build a variable
    let node_id = NodeId::new(2, "MyVar");
    VariableBuilder::new(&node_id, "MyVar", "MyVar")
        .organized_by(&folder_id)
        .value(0u8)
        .insert(&mut address_space);

    // Make sure to not keep the address space locked, or nothing will be able to
    // read from the server.
    //....
}
```

The builder pattern allows you to set each property of your node and common relationships
to other nodes before inserting it into the address space.

### Variables

Clients of servers will typically read values of variables, and may do so from a subscription. A variable can reflect a value from a physical device that your server will update either as it changes, or on a timer, or when a client requests it.

* Add hoc. Your code sets the variable when you deem the value to have changed.
* Getter. The server invokes a getter in your code whenever the value is requested.
* Timer. The server invokes a call back on a timed interval allowing you the chance to update the value. OPC UA for Rust provides a timer mechanism as a convenience

In addition you may also register a setter callback which is called whenever a client attempts to write a value to the variable. Your callback could ignore the change, clamp it to some range or call the physical device with the change.

#### Setting variable values manually

For some values you may prefer to set them once when they change. How you do this is up to you - a timer, an event, a separate thread receiving messages... Basically whatever mechanism you use, from your handler you will call something like this:

```rust
    let now = DateTime::now();
    let value = 123.456f;
    let node_id = NodeId::new(2, "myvalue");
    // You can set the value directly on the address space, but prefer calling this method instead,
    // which will notify any listening clients.
    node_manager.set_value(&handle.subscriptions(), &node_id, None, DataValue::new_at(value, now));
```

In this example `now` is the current timestamp for when the value changed and the value is 123.456.

#### Create a variable Getter

Alternatively you might prefer to poll values when a client actually asks for it. In this case, you can set the getter function whenever the variable is asked for and your function will be called.

This example will `123.456f`.  

```rust
    let node_id = NodeId::new(2, "myvalue");
    node_manager.inner().add_read_callback(node_id, |_, _, _| {
        Ok(DataValue::new_now(123.456f))
    })
```

The difference with the dynamic getter is there are parameters that allow your code to conditionally decide how they return a value.

The parameters to the getter are:

* `NumericRange`
* `TimestampsToReturn`
* `f64` - the max age parameter.

This allows a getter to be broad or specific. In the example, the getter is so specific it does not require any of the parameters.

### Run the server

Running a server is asynchronous.

```rust
#[tokio::main]
async fn main() {
    //... After server and address space are created

    // Run the server. This can be terminated gracefully by calling `handle.cancel()`.
    server.run().await.unwrap();
}
```

## Logging

OPC UA for Rust provides an extensive amount of logging at error, warn, info, debug and trace levels. All this is via the standard [log](https://docs.rs/log/0.4.8/log/) facade so choose which logging implementation you want to capture information. See the link for implementations that you can use.

### Console logging

For convenience OPC UA for Rust provides a simple `opcua-console-logging` crate that wraps [env_logger](https://docs.rs/env_logger/0.6.2/env_logger/) and writes out logging information to stdout. To use it, set an `RUST_OPCUA_LOG` environment variable (not `RUST_LOG`), otherwise following the documentation in `env_logger`. e.g.

```shell script
export RUST_OPCUA_LOG=debug
```

In your `Cargo.toml`, ensure to add `console-logging` to your opcua features:

```toml
[dependencies]
opcua = { "0.12", features = ["....", "console-logging"]}
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
