# Client

This is a tutorial for using the OPC UA library. It will assume you are familiar with Rust and tools such as `cargo`.

## OPC UA summary

OPC UA clients connect to OPC UA servers. 

There are 3 transport protocols for OPC UA - OPC UA TCP, HTTPS, and SOAP. This implementation currently 
only supports OPC UA TCP. 

OPC UA TCP describes an endpoint with a URL like this `opc.tcp://servername:port/endpoint/path`.
 

* `opc.tcp` is the OPC UA TCP schema
* `servername:port` is the host's name and port, e.g. "localhost:4855"
* `/endpoint/path` is the _endpoint_ you wish to connect to, e.g. "/device/metrics".

The basic lifecycle of a connection is:

1. Connect to server socket via OPC UA url, e.g. resolve "localhost" and connect to port 4855
2. Send hello
3. Open secure channel - create a secure / insecure connection to the server
4. Create session - establish a session with one of the endpoints, e.g. "/device/metrics"
5. Activate session - activate a session, i.e. provide a user identity
6. Do stuff, periodically renewing the channel. 
7. Close secure channel, server drops the socket

Once you're in step 5, the client is able to subscribe to variables, browse the address space and do other things
described by _services_.

The Rust OPC UA client API supports calling most OPC UA services, so what you do
is mainly up to you. Obviously if you call a service, then the server must implement that service otherwise it may
drop the connection. Therefore with OPC UA there is usually has to be implicit contract between
what the server supports and what the client wants to do.

Typically clients are likely to be subscribing to data and sitting in a loop listening to changes on that data. 

This tutorial will describe a very basic client that connects to a server and subscribes to some variables.

## Create a simple project

We're going to start with a blank project. 

```
cargo init --bin test-client
```

## Import the crate

The `opcua-client` is the crate containing the client side API. So first edit your `Cargo.toml` to 
add that dependency:

```toml
[dependencies]
opcua-client = "0.6"
```

## Import types

At the top of your `main.rs`, insert this:

```rust
use opcua_client::prelude::*;
```

The `prelude` module contains almost all of the structs you'll need in a client.

## Create your client

An OPC UA client needs to say who it is when it connects to the server. It may also need to present
certificates and modify other behaviours. 

A `Client` object represents a configured client but how do we configure it?

1. Externally by loading a a configuration file.
2. Via a `ClientBuilder`
3. Hybrid approach, load some defaults from a configuration file and override them from a `ClientBuilder`.

We'll use a pure `ClientBuilder` approach. A builder pattern in Rust consists of a number of configuration
calls chained together that eventually yield the object we are building.

```rust
use opcua_client::prelude::*;

fn main() {
    let client = ClientBuilder::new()
        .application_name("My First Client")
        .application_uri("urn:MyFirstClient")
        .create_sample_keypair(true)
        .trust_server_certs(false)
        .session_retry_limit(3)
        .client().unwrap();

    //...
}
```

### Name and URI

OPC UA likes to know the name and uri of the client and server. So in this example, we
will set our client to present itself to the server as "My First Client" by calling `application_name()` and
a similar uri via `application_uri()`. 

### Security

We'll set our client to generate a keypair of its own if necessary (it won't do it if finds a keypair
on disk already) with `create_sample_keypair(true)`.

When run the first time it will create a directory called `./pki` (relative to the working directory)
and create a private key and public certificate files.

```
./pki/own/cert.der
./pki/private/private.pem
```

These files are X509 (.der) and PEM files respectively. The X509 is a certifcate containing information 
about the client "My First Client" and a public key. The PEM is the private key.

For security purposes, clients are required to trust server certificates (just as servers are required to trust clients),
but for demo purposes we'll disable that setting in the client by calling `trust_server_certs(false)`. When this setting is
false, the client will automatically trust the server regardless of the key it presents.

When we connect to a server you will see some more entries under `./pki`:

```
./pki/rejected/
./pki/trusted/ServerFoo [f5baa2ed3896ef3048a148ea69a516a92a222fcc].der
```

The server's .der file will be stored in `./pki/trusted`. The name of the file depends on the server's application
name and the thumbprint (has) of the certificate.

### Retry policy

We also set a retry policy, so that if the client cannot connect to the server or is disconnected from the server, 
it will try to connect up to 3 times before giving up. Setting the limit to zero would retry continuously.
We could also change the retry interval if we wanted to.

### Create the Client   

Finally we call `client()` to produce a `Client`.

## Connect to a server

Once we have a `Client` describing who we are, we can try connecting to a server. There are a number
of ways to do this:

1. Predefined endpoints set up by the `ClientBuilder`
2. Ad hoc.

We'll go ad hoc. So in your client code you will have some code like this.

```rust
fn main() {
    //... create Client
    
    // Set up some parameters
    let opcua_url = "opc.tcp://localhost:4855/";
    let security_policy = SecurityPolicy:None;
    let message_security_mode = MessageSecurityMode::None;
    let user_token_policy = UserTokenPolicy::anonymous();
    let identity = IdentityToken::Anonymous;
    // ...
    // Create the session
    let session = client.connect_to_endpoint((opcua_url, security_policy.to_str(), message_security_mode, user_token_policy), identity).unwrap();
}
```

This command asks the API to connect to the server `opc.tcp://localhost:4855/` with a security policy / message mode
of None / None, and to connect as an anonymous user.

Assuming the connect success and returns `Ok(session)` then we now have a session to the server. Note that the client
returns a `Arc<RwLock<Session>>`. That means we need to lock it when we want to call it.

```rust
// Obtain a read-write lock to the session
let session = session.write().unwrap();
// call it.

``` 

#### Avoiding deadlock

The client exposes the session as a `Arc<RwLock<Session>>`. that is to say you must obtain a 
lock to call it and you are expected to release the lock when you are done.

You MUST release any lock before invoking `Session::run(session)` or the client will deadlock - the
run loop will be waiting for the lock that will never release.

Therefore avoid this code:

```rust
let s = session.write().unwrap();
// ... create some subscriptions, monitored items
// DANGER. Session is still locked on this thread and will deadlock.
let _ = Session::run(session);
```

Use a scope or a function to release the lock before you hit `Session::run(session):

```rust
{
    let s = session.write().unwrap();
    // ... create some subscriptions, monitored items 
}
let _ = Session::run(session);
```

## Calling the server

Once we have a session we can ask the server to do things. First a word about synchronous and asynchronous calls.

### Synchronous calls

The OPC UA for Rust client API is _mostly_ synchronous by design. i.e. when you call the a function, the message will be
sent to the server and the call will block until the response is received or the call times out. 

### Asynchronous calls

Under the covers, all calls are asynchronous, but the client API shields that detail.

The only exception to this are publish requests and responses which are asynchronous. When the API is used to create 
subscriptions, the API will automatically begin to send asynchronous `PublishRequest` messages to the server. 
When it receives a `PublishReponse` the API will automatically call the callback with any updates for monitored items. 

### Calling a service

Each kind of call to the server has a corresponding function in the `Session`, for example to create a subscription there
is a `create_subscription()` function. 

So we can call that to create a subcription. And then call `create_monitored_items()` to add items to monitor to the subscription.

```rust
let subscription_id = session.create_subscription(2000.0, 10, 30, 0, 0, true, DataChangeCallback::new(|changed_monitored_items| {
    println!("Data change from server:");
    changed_monitored_items.iter().for_each(|item| print_value(item));
}))?;

// Create some monitored items
let items_to_create: Vec<MonitoredItemCreateRequest> = ["v1", "v2", "v3", "v4"].iter()
    .map(|v| NodeId::new(2, *v).into()).collect();
let _ = session.create_monitored_items(subscription_id, TimestampsToReturn::Both, &items_to_create)?;
```

