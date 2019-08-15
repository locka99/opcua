# Client

This is a small tutorial for using the OPC UA client library. It will assume you are familiar with OPC UA,
Rust and tools such as `cargo`.

1. A small overview of OPC UA is [here](./opc_ua_overview.md).
2. Rust OPC UA's compatibility with the standard is described [here](./compatibility.md). 

### Introducing the OPC UA Client API

The OPC UA for Rust client API supports calls for most OPC UA services. Most
of these are synchronous, i.e. you call the function and it returns when the response is received or an error
occurs.

The only exception to this are when you create monitored items changes to those items are
asynchronously received on your callback. 

When you write a client you require some knowledge of the server you are calling. You need to know its
ip address, port, endpoints, security policy and also what services it supports.

In this sample, we're going to write a simple client that connects to the 
`opcua/samples/simple-server`, subscribes to some values and prints them out as they change. 

If you want to see a finished version of this, look at `opcua/samples/simple-client`.

### Life cycle

So basic lifecycle for a client is:

1. Connect to server socket via OPC UA url, e.g. resolve "localhost" and connect to port 4855
2. Send hello
3. Open secure channel - create a secure / insecure connection to the server
4. Create session - establish a session with one of the endpoints, e.g. "/device/metrics"
5. Activate session - activate a session, i.e. provide a user identity
6. Do stuff, periodically renewing the channel. 
7. Close secure channel, server drops the socket

Most of the housekeeping and detail is handled by the API. You just need to point the client
at the server, and set things up before running a loop.
 
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

OPC UA has a *lot* of types and structures and the client has structs representing the client,
session and open connection.
 
To pull these in, add this to the top of your `main.rs`:

```rust
use opcua_client::prelude::*;
```

The `prelude` module contains almost all of the things you'll need in a client.

## Create your client

The `Client` object represents a configured client describing its identity and set of behaviours.
 
There are three ways we can create one. 

1. Externally by loading a a configuration file.
2. Via a `ClientBuilder`
3. Hybrid approach, load some defaults from a configuration file and override them from a `ClientBuilder`.

We'll use a pure `ClientBuilder` approach below because it's the simplest to understand without worrying about
filepaths or file formats.

A builder pattern in Rust consists of a number of configuration calls chained together that eventually yield the
object we are building.

```rust
use opcua_client::prelude::*;

fn main() {
    let mut client = ClientBuilder::new()
        .application_name("My First Client")
        .application_uri("urn:MyFirstClient")
        .create_sample_keypair(true)
        .trust_server_certs(false)
        .session_retry_limit(3)
        .client().unwrap();

    //...
}
```

So here we use `ClientBuilder` to construct a `Client` that will:

* Be called "My First Client" and a uri of "urn:MyFirstClient"
* Automatically create a private key and public certificate (if none already exists)
* Automatically trust the server's cert
* Retry up to 3 times to reconnect if the connection goes down.

### Security

Security is an important feature of OPC UA. Our example automatically creates a private key and public cert if
none already exists.

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

When we connect to a server you will see some more entries under `./pki` resembling this:

```
./pki/rejected/
./pki/trusted/ServerFoo [f5baa2ed3896ef3048a148ea69a516a92a222fcc].der
```

The server's .der file was automatically stored in `./pki/trusted` because we told the client to automatically
trust the server. The default behaviour is to distrust the server, in which case the cert would have appeared
under `/pki/rejected` and we would have had to manually moved it into the trust folder.

The name of the file is created from the server's application name and the thumbprint of the certificate.

### Retry policy

We also set a retry policy, so that if the client cannot connect to the server or is disconnected from the server, 
it will try to connect up to 3 times before giving up. If a connection succeeds the retry counter is reset so it's
3 tries for any one reconnection attempt, not total. Setting the limit to zero would retry continuously forever.

There are also settings to control the retry rate. It is not advisable to make retries too fast.

### Create the Client   

Finally we called `client()` to produce a `Client`. Now we have a client we can start calling it.

## Connect to a server

A `Client` can connect to any server it likes. There are a number of ways to do this:

1. Predefined endpoints set up by the `ClientBuilder`
2. Ad hoc.

We'll go ad hoc. So in your client code you will have some code like this.

```rust
fn main() {
    //... create Client
    
    // Create an endpoint. The EndpointDescription can be made from a tuple consisting of
    // the endpoint url, security policy, message security mode and user token policy.
    let endpoint: EndpointDescription = ("opc.tcp://localhost:4855/", "None", MessageSecurityMode::None, UserTokenPolicy::anonymous()).into();

    // Create the session
    let session = client.connect_to_endpoint(endpoint, IdentityToken::Anonymous).unwrap();
}
```

This command asks the API to connect to the server `opc.tcp://localhost:4855/` with a security policy / message mode
of None / None, and to connect as an anonymous user.

Assuming the connect success and returns `Ok(session)` then we now have a session to the server.

## Using the Session object
 
Note that the client returns sessions wrapped as a `Arc<RwLock<Session>>`. The `Session` is locked because we
(the client) share it with the API.

That means to use a session you must lock it to obtain read or write access to it. e.g, 
 
```rust
// Obtain a read-write lock to the session
let session = session.write().unwrap();
// call it.
``` 

#### Avoiding deadlock

You MUST release any lock before invoking `Session::run(session)` or the client will deadlock - the
run loop will be waiting for the lock that will never release.

Therefore avoid this code:

```rust
let s = session.write().unwrap();
// ... create some subscriptions, monitored items
// DANGER. Session is still locked on this thread and will deadlock.
let _ = Session::run(session);
```

Use a scope or a function to release the lock before you hit `Session::run(session)`:

```rust
{
    let mut session = session.write().unwrap();
    // ... create some subscriptions, monitored items 
}
let _ = Session::run(session);
```

## Calling the server

Once we have a session we can ask the server to do things by sending requests to it. Requests correspond to services
implemented by the server. Each request is answered by a response containing the answer, or a service fault if the 
service is in error. 

First a word about synchronous and asynchronous calls.

### Synchronous calls

The OPC UA for Rust client API is _mostly_ synchronous by design. i.e. when you call the a function, the request will be
sent to the server and the call will block until the response is received or the call times out. 

This makes the client API easy to use.

### Asynchronous calls

Under the covers, all calls are actually asynchronous. Requests are dispatched and responses are handled asynchronously
but the client waits for the response it is expecting. 

The only exception to this are publish requests and responses which are always asynchronous. These are handled
internally by the API from timers. If a publish response contains changes from a subscription, the subscription's
registered callback will be called asynchronously from another thread. 

### Calling a service

Each service call to the server has a corresponding client side function. For example to create a subscription there
is a `create_subscription()` function in the client's `Session`. When this is called, the API will fill in a
`CreateSubscriptionRequest` message, send it to the server, wait for the corresponding `CreateSubscriptionResponse`
and return from the call with the contents of the response.

Here is code that creates a subscription and adds a monitored item to the subscription.

```rust
{
    let mut session = session.write().unwrap();
    let subscription_id = session.create_subscription(2000.0, 10, 30, 0, 0, true, DataChangeCallback::new(|changed_monitored_items| {
        println!("Data change from server:");
        changed_monitored_items.iter().for_each(|item| print_value(item));
    }))?;
    
    // Create some monitored items
    let items_to_create: Vec<MonitoredItemCreateRequest> = ["v1", "v2", "v3", "v4"].iter()
        .map(|v| NodeId::new(2, *v).into()).collect();
    let _ = session.create_monitored_items(subscription_id, TimestampsToReturn::Both, &items_to_create);
}
```

Note the call to `create_subscription()` requires an implementation of a callback. There is a `DataChangeCallback`
helper for this purpose that calls your function with any changed items.

## Run a loop

Now we have created a subscription, we can put the client into a running state:

```rust
let _ = Session::run(session);
```

This loop runs forever, or until the client sets an abort flag and breaks, or the connection retry limit is exceeded.
