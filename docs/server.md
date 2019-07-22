# Server

This is a tutorial for using the OPC UA server library. It will assume you are familiar with Rust and tools such as `cargo`.

## OPC UA Overview

OPC UA is a standardized communication protocol for industrial visualization and control systems. It
allows devices to talk with one another over a secure link. It is a client / server architecture. The 
server provides _services_ and are grouped into sets:

* Subscriptions - create / modify / delete subscriptions to data
* Monitored Items - add / modify / delete items from a subscription
* Discovery - discover other servers
* Attributes - read and write values on the server
* Methods - call methods on the server
* View - browse the server address space

Clients connect to a server and call services depending on what they want to do. For example a client subscribe to a 
particular variable so it receive notifications when the value changes.

### Server API

The Rust OPC UA server API supports all of the embedded OPC UA services and a few of the standard services. Most of
these are implemented for you. The server API can be used to configure the identity of your server, its port
number and other details, to set up an address space, set up variables that operate from setters or timers, and to 
listen for clients.

### Protocols

All communication between the client and server is via a protocol, of which there are three:

- OPC UA TCP binary - Supported
- HTTPS binary - Not supported
- HTTPS XML SOAP - Not supported

This implementation supports encrypted and unencrypted communication of traffic between client and server
as well as a certificate trust model.

### Endpoints

### Lifecycle

## Create a simple project

## Import the crate

## Import types

## Create your server

### Configure the server

The server can be configured in a number of ways:

1. A `ServerBuilder` is the easiest way to build a server programatically.
2. A configuration file described in yaml that you create a server from.

#### ServerBuilder

A `ServerBuilder` allows you to programattically construct a `Server`.

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