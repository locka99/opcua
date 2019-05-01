# Client

## OPC UA summary

OPC UA clients connect to OPC UA servers. 

There are 3 transport protocols for OPC UA - OPC UA TCP, HTTPS, and SOAP. This implementation currently 
only supports OPC UA TCP. 

OPC UA TCP describes a url like this `opc.tcp://servername:port/endpoint/path`.
 
* `opc.tcp` is the OPC UA TCP schema
* `servername:port` is the host's name and port, e.g. "localhost:4855"
* `/endpoint/path` is the _endpoint_ you wish to connect to.

The basic lifecycle of a connection is:

1. Connect to server socket via OPC UA url
2. Open secure channel - create a secure / insecure connection to the server
3. Create session - establish a session with one of the endpoints
4. Activate session - activate a session, i.e. provide a user identity
5. Do stuff, periodically renewing the channel. 
6. Close secure channel, server drops the socket

Once you're in step 5, the client is able to subscribe to variables, browse the address space and do other things
described by _services_. The Rust OPC UA client API supports calls to most OPC UA services, so what you do
is mainly up to you. Most clients are likely to sit in a loop listening to changes on data.

This tutorial will describe a very basic client that connects to a server and subscribes to some variables.

## Import the crate

The `opcua-client` is the crate containing the client side API. So first edit your `Cargo.toml` to 
add that dependency:

```toml
[dependencies]
opcua-client = "0.6"
```

## Import types

At the top of your `main.rs`, or wherever you need to call OPC UA, insert this:

```rust
use opcua_client::prelude::*;
```

The `prelude` module contains almost all of the structs you'll need in a client.

## Create your client

An OPC UA client needs to say who it is when it connects to the server. It may also need to present
certificates and modify other behaviours. 

The client is represented by a `Client` object which can configured in a number of ways:

1. Externally by loading a a configuration file.
2. Via a `ClientBuilder`
3. Hybrid approach, load some defaults from a configuration file and override them from a `ClientBuilder`.

We'll use a pure `ClientBuilder`.

```rust
let client = ClientBuilder::new()
        .application_name("My First Client")
        .application_uri("urn:MyFirstClient")
        .trust_server_certs(true)
        .create_sample_keypair(true)
        .session_retry_limit(3)
        .client().unwrap();
```

So in this example, our client will present itself to the server as `My First Client`. 

For security purposes, it also says it will implicitly trust server certificates. That means that when the client
connects to the server it will automatically trust the server's certificate. In the real world, you may or may not
want to do that.

Additionally, we want our client to generate a keypair of its own if necessary.

We also set a retry policy, that if the client cannot connect to the server or is disconnected, it will 
try to connect up to 3 times before. 

Finally we call `client()` to produce a `Client`.

## Connect to a server

Once you have a client you can try connecting to a server to create a session.

So in your client code you will have some code like this.

```rust
// Set up some parameters
let opcua_url = "opc.tcp://localhost:4855/";
let security_policy = SecurityPolicy:None;
let message_security_mode = MessageSecurityMode::None;
let user_token_policy = UserTokenPolicy::anonymous();
let identity = IdentityToken::Anonymous;
// ...
// Create the session
let session = client.connect_to_endpoint((opcua_url, security_policy.to_str(), message_security_mode, user_token_policy), identity).unwrap();
```

This command asks the API to connect to the server `opc.tcp://localhost:4855/` with a security policy / message mode
of None / None, and to connect as an anonymous user.

Assuming the connect success and returns `Ok(session)` then we now have a connection to the server. 

## Call the server

# Synchronous calls

The OPC UA for Rust client API is _mostly_ synchronous by design. i.e. when you call the a function, the message will be
sent to the server and the call will block until the response is received. 

Each kind of call to the server has a corresponding function in the `Session`, for example to create a subscription there
is a `create_subscription()` function. 

```
impl Session {
    //...
    pub fn create_subscription<CB>(&mut self, publishing_interval: f64, lifetime_count: u32, max_keep_alive_count: u32,
            max_notifications_per_publish: u32, priority: u8, publishing_enabled: bool, callback: CB)
            -> Result<u32, StatusCode>
            where CB: OnDataChange + Send + Sync + 'static {
        //...
    }
    //...
}
```

Here we see that `create_subscription` returns a `Result<u32, StatusCode>`. Internally this 
constructs a `CreateSubscriptionRequest` and waits for a `CreateSubscriptionResponse`. Out of that it returns the
`subscription_id` as a `u32`. If it gets a service fault, or some kind of error instead it will return a `StatusCode`
for the error.

This particular function is also generic - it requires we supply a call back that implements the `OnDataChange` trait. 

### Asynchronous calls

Under the covers, all calls are asynchronous, but the client API shields that detail.

The only exception to this are publish requests and responses which are asynchronous. When the API is used to create 
subscriptions, the API will automatically begin to send asynchronous `PublishRequest` messages to the server. 
When it receives a `PublishReponse` the API will automatically call the callback with any updates for monitored items. 

### Thread safety

Asynchronous callbacks will happen on different threads from your synchronous calls. Since this is Rust you don't have
to care a great deal about this detail, but if you're wondering why certain objects are enclosed by `Arc<RwLock<>>` 
or `Arc<Mutex<RwLock>>` then it is to allow multiple threads access to those objects.

It is never a good idea to have any OPC UA object locked when you call the client API. This is most important to 
remember when you enter the session run loop.

```
let s = session.lock().unwrap();
// ... create some subscriptions, monitored items
// DANGER. Session is still locked on this thread and will deadlock.
let _ = Session::run(session);
```

Instead you need to scope limit your actions to release the lock:

```
{
    let s = session.lock().unwrap();
    // ... create some subscriptions, monitored items 
}
let _ = Session::run(session);
```
