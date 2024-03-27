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
2. Create a `Session` and `SessionEventLoop` from a server endpoint.
3. Begin polling the event loop, either in a tokio `Task` or in a `select!` block.
4. Wait for the event loop to connect to the server.
5. Call functions on the session which make requests to the server, e.g. read a value, or monitor items
6. Run in a loop doing 5 repeatedly or exit

Most of the housekeeping and detail is handled by the API. You just need to point the client
at the server, and set things up before calling stuff on the session.
 
## Create a simple project

We're going to start with a blank project. 

```
cargo init --bin test-client
```

## Import the crate

The `opcua` is the crate containing the client side API. So first edit your `Cargo.toml` to 
add that dependency. You will also need `tokio`:

```toml
[dependencies]
opcua = { version = "0.14", features = ["client"] }
tokio = { version = "1", features = ["full"] }
```

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
3 tries for any one reconnection attempt, not total. Setting the limit to -1 would retry continuously forever.

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
#[tokio::main]
async fn main() {
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
    let (session, event_loop) = client.new_session_from_endpoint(endpoint, IdentityToken::Anonymous).await.unwrap();

    // Spawn the event loop on a tokio task.
    let mut handle = event_loop.spawn();
    tokio::select! {
        r = &mut handle => {
            println!("Session failed to connect! {r}");
            return;
        }
        _ = session.wait_for_connection().await => {}
    }
    
 
    //... use session
}
```

This command asks the API to connect to the server `opc.tcp://localhost:4855/` with a security policy / message mode
of None / None, and to connect as an anonymous user.

Note that this does not connect to the server, only identify a server endpoint to connect to and create the necessary types to manage that connection.

The `event_loop` is responsible for maintaining the connection to the server. We run it in a background thread for convenience. In this case, if the event loop terminates, we have failed to connect to the server, even after retries.

In order to avoid waiting forever on a connection, we watch the handle in a `select!`.

Once `wait_for_connection` returns, if the event loop has not terminated, we have an open and activated session.

## Calling the server

Once we have a session we can ask the server to do things by sending requests to it. Requests correspond to services
implemented by the server. Each request is answered by a response containing the answer, or a service fault if the 
service is in error.

The API is asynchronous, and only requires a shared reference to the session. This means that you can make multiple independent requests concurrently. The session only keeps a single connection to the server, but OPC-UA supports _pipelining_ meaning that you can send several requests to the server at the same time, then receive them out of order.

### Calling a service

Each service call in the server has a corresponding client side function. For example to create a subscription there
is a `create_subscription()` function in the client's `Session`. When this is called, the API will fill in a
`CreateSubscriptionRequest` message, send it to the server, wait for the corresponding `CreateSubscriptionResponse`
and return from the call with the contents of the response.

Here is code that creates a subscription and adds a monitored item to the subscription.

```rust
{
    let subscription_id = session.create_subscription(std::time::Duration::from_millis(2000), 10, 30, 0, 0, true, DataChangeCallback::new(|changed_monitored_items| {
        println!("Data change from server:");
        changed_monitored_items.iter().for_each(|item| print_value(item));
    })).await?;
    
    // Create some monitored items
    let items_to_create: Vec<MonitoredItemCreateRequest> = ["v1", "v2", "v3", "v4"].iter()
        .map(|v| NodeId::new(2, *v).into()).collect();
    let _ = session.create_monitored_items(subscription_id, TimestampsToReturn::Both, items_to_create).await?;
}
```

Note the call to `create_subscription()` requires an implementation of a callback. There is a `DataChangeCallback`
helper for this purpose that calls your function with any changed items, but you can also implement it yourself for more complex use cases.

## Monitoring the event loop

Using `event_loop.spawn` is convenient if you do not care what the session is doing, but in general you want to know what is happening so that your code can react to it. The `event_loop` _drives_ the entire session including sending and receiving messages, monitoring subscriptions, and establishing and maintaining the connection.

You can watch these events yourself by using `event_loop.enter`, which returns a `Stream` of `SessionPollResult` items.

```rust

tokio::task::spawn(async move {
    // Using `next` requires the futures_util package.
    while let Some(evt) = event_loop.next() {
        match evt {
            Ok(SessionPollResult::ConnectionLost(status)) => { /* connection lost */ },
            Ok(SessionPollResult::Reconnected(mode)) => { /* connection established */ },
            Ok(SessionPollResult::ReconnectFailed(status)) => { /* connection attempt failed */ },
            Err(e) => { /* Exhausted connect retries, the stream will exit now */ },
            _ => { /* Other events */ }
        }
    }
})

```

## That's it

Now you have created a simple client application. Look at the client examples under `samples`,
starting with `simple-client` for a very basic client.
