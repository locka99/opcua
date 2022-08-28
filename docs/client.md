# Client

_Work in progress_

This is a small tutorial for using the OPC UA client library. It will assume you are familiar with OPC UA,
Rust and tools such as `cargo`.

1. A small overview of OPC UA is [here](./opc_ua_overview.md).
2. Rust OPC UA's compatibility with the standard is described [here](./compatibility.md). 

### Introducing the OPC UA Client API

The OPC UA for Rust client API supports calls for OPC UA services. Whether the server you are calling implements them is another matter but
 you can call them.
 
 For the most part it is synchronous - you call the function and it waits for the server to respond or a timeout to happen. Each function call returns a
 `Result` either containing the response to the call, or a status code.

Data change notifications are asynchronous. When you create a subscription you supply a callback. The client
 API will automatically begin sending publish requests to the server on your behalf and will call
your callback when a publish response contains notifications. 

Clients generally require some knowledge of the server you are calling. You need to know its
ip address, port, endpoints, security policy and also what services it supports. The client API provides
different ways to connect to servers, by configuration file or ad hoc connections. 

In this sample, we're going to write a simple client that connects to the 
`opcua/samples/simple-server`, subscribes to some values and prints them out as they change. 

If you want to see a finished version of this, look at `opcua/samples/simple-client`.

### Life cycle

From a coding perspective a typical use would be this:

1. Create a `Client`. The easiest way is with a `ClientBuilder`.
2. Call the client to connect to a server endpoint and create a `Session`
3. Call functions on the session which make requests to the server, e.g. read a value, or monitor items
4. Run in a loop doing 3 repeatedly or exit

Most of the housekeeping and detail is handled by the API. You just need to point the client
at the server, and set things up before calling stuff on the session.
 
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
opcua = { "0.11", features = ["client"] }
```

## Import types

OPC UA has a *lot* of types and structures and the client has structs representing the client,
session and open connection.
 
To pull these in, add this to the top of your `main.rs`:

```rust
use opcua::client::prelude::*;
```

The `prelude` module contains all of the things a basic client needs.

## Create your client

The `Client` object represents a configured client describing its identity and set of behaviours.
 
There are three ways we can create one. 

1. Via a `ClientBuilder`
2. Externally by loading a a configuration file.
3. Hybrid approach, load some defaults from a configuration file and override them from a `ClientBuilder`.

We'll use a pure `ClientBuilder` approach below because it's the simplest to understand without worrying about
file paths or file formats.

A builder pattern in Rust consists of a number of configuration calls chained together that eventually yield the
object we are building.

```rust
use opcua::client::prelude::*;

fn main() {
    let mut client = ClientBuilder::new()
        .application_name("My First Client")
        .application_uri("urn:MyFirstClient")
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .session_retry_limit(3)
        .client().unwrap();

    //... connect to server
}
```

So here we use `ClientBuilder` to construct a `Client` that will:

* Be called "My First Client" and a uri of "urn:MyFirstClient"
* Automatically create a private key and public certificate (if none already exists)
* Automatically trust the server's cert during handshake.
* Retry up to 3 times to reconnect if the connection goes down.

### Security

Security is an important feature of OPC UA. Because the builder has called `create_sample_keypair(true)` 
it will automatically create a self-signed private key and public cert if the files do not already exist. If 
we did not set this line then something else would have to install a key & cert, e.g. an external script.

But as it is set, the first time it starts it will create a directory called `./pki` (relative to
the working directory) and create a private key and public certificate files.

```
./pki/own/cert.der
./pki/private/private.pem
```

These files are X509 (`cert.der`) and private key (`private.pem`) files respectively. The X509 is a certificate
containing information about the client "My First Client" and the
public key. The private key is just the private key.

For security purposes, clients are required to trust server certificates (and servers are 
required to trust clients), but for demo purposes we've told the client to automatically
trust the server by calling `trust_server_certs(true)`. When this setting is true, the client will
automatically trust the server regardless of the key it presents.

In production you should NOT disable the trust checks.

When we connect to a server for the first you will see some more entries added under `./pki` resembling this:

```
./pki/rejected/
./pki/trusted/ServerFoo [f5baa2ed3896ef3048a148ea69a516a92a222fcc].der
```

The server's .der file was automatically stored in `./pki/trusted` because we told the client to automatically
trust the server. The name of this file is derived from information in the certificate and its thumbprint
to make a unique file. 

If we had told the client not to trust the server, the cert would have appeared
under `/pki/rejected` and we would need to move it manually into the `/pki/trusted` folder. This
is what you should do in production.

#### Make your server trust your client

Even though we have told the client to automatically trust the server, it does not mean the server will trust the client.
Both will need to trust on another for the handshake to succeed. Therefore the next step is make the server trust the
client.

Refer to the documentation in your server to see how to do this. In many OPC UA servers this will involve moving
the client's cert from a `/rejected` to a `/trusted` folder much as you did in OPC UA for Rust. Other servers may
require you do this some other way, e.g. through a web interface or configuration.

### Retry policy

We also set a retry policy, so that if the client cannot connect to the server or is disconnected from the server, 
it will try to connect up to 3 times before giving up. If a connection succeeds the retry counter is reset so it's
3 tries for any one reconnection attempt, not total. Setting the limit to zero would retry continuously forever.

There are also settings to control the retry reconnection rate, i.e. the interval to wait from one failed
attempt to the next. It is not advisable to make retries too fast.

### Create the Client   

Finally we called `client()` to produce a `Client`. Now we have a client we can start calling it.

## Connect to a server

A `Client` can connect to any server it likes. There are a number of ways to do this:

1. Predefined endpoints set up by the `ClientBuilder`
2. Ad hoc via a url, security policy and identity token.

We'll go ad hoc. So in your client code you will have some code like this.

```rust
fn main() {
    //... create Client
    
    // Create an endpoint. The EndpointDescription can be made from a tuple consisting of
    // the endpoint url, security policy, message security mode and user token policy.
    let endpoint: EndpointDescription = (
        "opc.tcp://localhost:4855/",
        "None",
        MessageSecurityMode::None,
        UserTokenPolicy::anonymous()
    ).into();

    // Create the session
    let session = client.connect_to_endpoint(endpoint, IdentityToken::Anonymous).unwrap();
 
    //... use session
}
```

This command asks the API to connect to the server `opc.tcp://localhost:4855/` with a security policy / message mode
of None / None, and to connect as an anonymous user.

Assuming the connect success and returns `Ok(session)` then we now have a session to the server. 

Note you will always get a `session` even if activation failed, i.e. if your identity token was
invalid for the endpoint your connection will be open but every call will fail with a `StatusCode::BadSessionNotActivated`
service fault until you call `activate_session()` successfully.

## Using the Session object
 
Note that the client returns sessions wrapped as a `Arc<RwLock<Session>>`. The `Session` is locked because 
the code shares it with the OPC UA for Rust internals.

That means to use a session you must lock it to obtain read or write access to it. e.g, 
 
```rust
// Obtain a read-write lock to the session
let session = session.write().unwrap();
// call it.
``` 

Since you share the Session with the internals, you MUST relinquish the lock in a timely fashion. i.e.
you should never lock it open at the session start because OPC UA will never be able to obtain it and will
break.

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

Under the covers, all calls are asynchronous. Requests are dispatched and responses are handled asynchronously
but the client waits for the response it is expecting or for the call to timeout. 

The only exception to this are publish requests and responses which are always asynchronous. These are handled
internally by the API from timers. If a publish response contains changes from a subscription, the subscription's
registered callback will be called asynchronously from another thread. 

### Calling a service

Each service call in the server has a corresponding client side function. For example to create a subscription there
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

## Running a loop

You may want to run continuously after you've created a session. There are two ways to do this depending on what you
are trying to achieve.

## Session::run

If all you did is subscribe to some stuff and you have no further work to do then you can just call `Session::run()`. 

```rust
Session::run(session);
```

This function synchronously runs forever on the thread, blocking until the client sets an abort flag and breaks, or the connection breaks and any retry limit is exceeded.

## Session::run_async

If you intend writing your own loop then the session's loop needs to run asynchronously on another thread. In this case you call `Session::async_run()`. When you call it, a new thread is spawned to maintain the session and the calling thread
is free to do something else. So for example, you could write a polling loop of some kind. The call to `run_async()` returns an `tokio::oneshot::Sender<SessionCommand>` that allows you to send a message to stop the session running on
the other thread. You must capture that sender returned by the function in a variable or it will drop and the session will 
also drop.

```rust
let session_tx = Session::run_async(session.clone());
loop {
  // My loop 
  {
    // I want to poll a value from OPC UA
    let session = session.write().unwrap();
    let value = session.read(....);
    //... process value
  }
 
  let some_reason_to_quit() {
    // Terminate the session loop
    session_tx.send(SessionCommand.stop());
  }
 
  // Maybe I sleep in my loop because it polls
  std::thread::sleep(Duration::from_millis(2000);)
}
```

## That's it

Now you have created a simple client application. Look at the client examples under `samples`,
starting with `simple-client` for a very basic client.