# Client

Before we start, be sure to understand the basics of OPC UA.

## Small summary

OPC UA clients connect to OPC UA servers. There are 3 ways of connecting - OPC UA TCP, HTTPS, and SOAP - but this 
implementation currently only supports OPC UA TCP. This is by far and away the most common protocol although 
some servers also support connecting over https. Perhaps this implementation will some day... There is little
chance that SOAP will ever be supported though.

OPC UA TCP describes a url like this "opc.tcp://servername:4855/endpoint/path". To break it down, `opc.tcp` is 
the OPC UA TCP schema, `servername` is the host's name or IP address, `4855` is the port to connect to
(although any port is valid), and `/endpoint/path` is the _endpoint_ you wish to connect to.

When a client connects to a server, it first discovers what endpoints the server has. It then
attempts to find an endpoint that matches the one being connected to. Each endpoint also describes
what security it requires so the client may exchange certificates with the server and there may be 
trust issues to sort out.  

Once the connection is established, the client creates and activates a _session_ with the server. Activation 
involves supplying an identity token to the server to authorize access to the server. Some servers may
support anonymous access while others may require a credential. 

When the session exists, the client is able to subscribe to variables, browse the address space and do other things
described by _services_. The Rust OPC UA client API supports calls to most OPC UA services, so what you do
is mainly up to you. 

This tutorial will describe a very basic client that connects to a server and subscribes to some variables.

## Import the crate

When you're writing a client you first edit your `Cargo.toml` to depend on the `opcua-client`.

```toml
[dependencies]
opcua-client = "0.6"
```

## Bring in the types

At the top of your `main.rs`, or wherever you need to call OPC UA, insert this:

```rust
use opcua_client::prelude::*;
```

The `prelude` module contains almost all of the structs you'll need in a client.

## Create your client

Your client needs to be able to talk to a server and say who it is. This configuration can reside in an external 
configuration file, or it can be created by a builder pattern. The `ClientBuilder` is a way to programmatically construct
a `Client` which will represent your client side persona:

```rust
let client = ClientBuilder::new()
        .application_name("WebSocketClient")
        .application_uri("urn:WebSocketClient")
        .trust_server_certs(true)
        .create_sample_keypair(true)
        .session_retry_limit(3)
        .client().unwrap();
```

So in this example, our client will present itself to the server as `WebSocketClient`. It also says it implicitly trusts
server certificates, that it will generate a keypair of its own if necessary, it will try to connect up to 3 times before
failing, and finally it produces a `Client`.

The builder also allows a client to set up any user identities it supports and some other settings.   

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
// Create the session
let session = client.connect_to_endpoint((opcua_url, security_policy.to_str(), message_security_mode, user_token_policy), identity).unwrap();
```

This command asks OPC UA to connect to a server `opc.tcp://localhost:4855/` with a security policy / message mode of None / None,
and to connect as an anonymous user.

Assuming the connect success and returns `Ok(session)` then we now have a connection to the server. 

## Call the server

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

As stated, most functions are synchronous.

The only exception to this are publish requests and responses which are asynchronous and controlled internally by the API. 
When the API is used to create subscriptions, the API will automatically begin to send asynchronous 
`PublishRequest` messages to the server. When it receives a `PublishReponse` the API will automatically call the callback
with any updates for monitored items. 

### Thread safety

Asynchronous callbacks will happen on different threads from your synchronous calls. Since this is Rust you don't have to care a great deal
about this detail, but if you're wondering why certain objects are enclosed by `Arc<RwLock<>>` or `Arc<Mutex<RwLock>>` 
then that is why. 

The one thing you *do* have to know, is that if you hold a lock on the session, client or state then you may prevent
parts of Rust OPC UA from obtaining a lock itself. This is most important to remember when you enter the session run loop.

```
let s = session.lock().unwrap(); 
// DANGER. Session is locked on this thread and deadlock can happen on other threads.
let _ = Session::run(session);
```
