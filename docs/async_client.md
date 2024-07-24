# Async Client

The client has been rewritten from a synchronous API to an asynchronous API. This came in the form of a rather large patch. This document lays out the why and what of that change.

## Why

The client was already fundamentally built upon tokio, and the core of the client was async. The rewrite started as a smaller project intended to simply change the existing implementation to allow that to bubble up. This has been attempted in the past. However, it quickly became clear that the existing implementation was hard to change in that way, and it seemed likely that a rewrite would not really produce a better quality library, but rather make it even more complex and fragile.

### Locking

In particular, the library did (and still does, to a slightly lesser degree) contain a lot synchronous locks. This has historically lead to several bugs, as documented by the extensive use of tracing macros to debug deadlocks. A PR #146 made an effort to switch from std::sync::Mutex/RwLock to parking_lot, but this may have made the problem _worse_.

In order to produce a deadlock, you _must_ hold two forms of synchronization mechanisms at the same time. The simplest way to make deadlock-free code is to forbid this, which is often easier said than done. The code as is did avoid deadlocks for the most part, but _await points are synchronization_. By allowing locks to be held accross await points, channel uses, or thread joins, there is an implicit risk of deadlocks.

This rewrite does still use locks, it is largely unavoidable. More locks could have been removed, but that would have required rewriting the server as well. It does, however, attempt to replace locks in a few ways.

 - Assign clearer ownership of components. For example, the transport layer now owns the message buffer.
 - Use more specialized synchronization mechanisms. The `Handle` implementation now uses atomics, as does the `DepthGauge`. A few types have been swapped for `ArcSwap`, which while still a form of locking, is less intrusive than an `RwLock` or `Mutex` for things that are written rarely, read from often, and never mutated except for being replaced, like channel and session IDs.

There is still a lot more to do here, but this is hopefully a decent start.

### Weight

While less obviously a goal, this rewrite had a few major requirements:

 - The API should be entirely async.
 - The client should never spawn a thread, unless explicity asked to by the user.
 - The user must be able to apply backpressure to the client.

Async rust is uniquely well suited to these requirements. Implementing this allows us to create a very light weight client, but this necessitated further changes to the API.

Everything is now driven by a set of event loops wrapped in a "poll" API. This means that it is fully possible to run the client entirely cooperatively on a single OS thread, without any tokio tasks. Alternatively, users can quite easily just spawn the event loop on a tokio task. This design is inspired by the wonderful rust MQTT library rumqttc.

This does have a few downsides.

 - There is no single method to connect to the server, though one could be written. You have to use `wait_for_connection` after spawning the event loop. Having the event loop own the connection was essential in order to avoid excessive locking and complexity in the client.
 - There is no way to have a session object with just a secure channel and no active session. This simplifies the session a bit (it now has just two real states, connected and not connected), but it makes the code for making calls to a server without a session a bit hairy, see `client.rs`.
 - The transport event loop shares a single thread with everything else the session does. If this ever becomes a problem it is very possible to make the session optionally run the transport in an internal task.

## What

### Functional changes

As mentioned the API is now entirely async. Originally the plan was to keep the existing synchronous API in place. It would be relatively trivial to write one, but at the same time it is somewhat un-rusty to create such an API. If a user wants to interface with the client from blocking code, they should have to make that decision explicitly. Writing one would just be a matter of creating a client containing the session and a tokio runtime, than calling `runtime.block_on(...)` for each service.

The old client, by accident or on purpose, did not support pipelining requests, due to `send_request` requiring a mutable reference to the session state. The new client does, by lowering the message queue to the transport layer, and by eliminating the `SessionState` entirely, instead keeping multiple independent pieces of state in the client or the event loop.

The service traits are gone. They were entirely unused, except as a way to group services, and potentially as a way for users to have mocking? Keeping them would have been possible, but it would have required a higher MSRV.

Callbacks have changed slightly, mostly due to the way notifications are received. The subscription logic is similar, but the way `MonitoredItems` queued values seemed largely meaningless, as they were always immediately dequeued (or if they weren't that would be a user error?), it seemed like a feature that was mostly unhelpful. The connect/disconnect callbacks are also gone, though they could be reimplemented. It is possible to monitor the state of the session by watching the output of the event loop `poll` method.

The client is no longer behind a lock. Any locking is internal, except for access to the subscription cache directly. This should be a strictly positive change for usability.

### Removal of the prelude

Big glob-imports are generally discouraged, and are apparently bad for compile time. In general, a user who wants to glob-import everything can do so through `types::*` and `client::*`. Being explicit about what we expose is good for semver compatibility, and `prelude` should be reserved for imports such as core traits and essential types. Ideally we would remove this from the server as well, but this patch aimed to be constrained to the client as much as possible.

### Changes outside of the client

A few changes were made outside of the client, though they are very limited in scope.

 - Use atomics in the `Handle` and `DepthGauge` implementations.
 - Use the async client in the server. This was actually quite complicated, since that code did a _lot_ of locking, taking three mutexes at the same time, which almost immediately blocked and deadlocked. The implementation now avoids that, but is perhaps a bit more clone-happy.
 - The integration tests of course had to be rewritten. They are now enabled by default, since it turns out they now run in about a second total. If the server was rewritten to async as well they could probably run in a few hundred milliseconds at most.
 - The samples needed to be rewritten as well.
 - A pair of default implementations was added for `ReadValueId` and `QualifiedName`, just for convenience. `QualifiedName` has `null` which is a very reasonable default.

### Remaining gaps

There are a few things that were deemed out of scope for the initial implementation. Implementing these need not be complicated, but they are also not strictly necessary for a fully featured async client.

 - Wrapper methods for creating session and connecting. This could be useful, and is likely fairly easy to do. We would create a session, temporarily poll the event loop, and connect to the client. These methods would have to return an `impl Stream`, or a `JoinHandle`, since we would need to start the event loop to connect.
 - A wrapper around the event loop to provide a better interface for monitoring the connection.
 - Better control over subscription transfers. Currently it is a bit magical. Calling `transfer_subscriptions` is fine, but actually recreating them is a bit agressive. Especially if the user has tens or hundreds of thousands of monitored items. This change adds chunking to that process, but this is a bit of a stopgap measure.
 - Utility methods for retries on service calls.
 - Mechanisms for handling session loss without an actual lost TCP connection. This is partially covered in the old sync client, so there is a clear gap here. It requires some careful investigation however, to determine the best way to deal with this.
 - Discovery endpoints on the session. They are currently only available on the client itself, which spins up a new connection. Technically they are available on sessions as well.

## Future projects

This is a large patch, hopefully without too many bugs, though it is hard to say for sure. While it is huge, it is constrained to the client for the most part. In the process of writing this, a few issues came up that make for nice future projects:

 - Rewrite `StatusCode` by hand. The current implementation uses `bitflags` but this works poorly (the debug output is very misleading), since `StatusCode`s in OPC-UA really aren't bit flags in that sense. A manual implementation is a moderate amount of work, but would probably be helpful.
 - Rewrite the server. This is probably an even larger project than the client, having it be async all the way through would be very helpful as well.
 - Use more sophisticated errors than just `StatusCode`. This is a problem with other OPC-UA implementations as well, it can be hard to tell whether an error comes from the server or the client, or any other details in general. The session logs when errors are encountered, but logs scale poorly and cannot be handled programatically. While every error should _have_ a status code, there is no reason why we couldn't use normal rust errors with custom `status_code` methods and the option for more debug info.
 - Look into using pure rust crypto libraries as an alternative. Rust crypto has come a long way, and avoiding external libraries can improve the portability of the code.
 - Make the transport layer generic to allow for other transports.
 - Expand on the session with more utility methods for making more sophisticated requests to OPC-UA servers. Continuation point handling, server limits, events, etc.
 - Fix all the warnings on recent rust versions. There are a few deprecated methods, and a few warnings related to glob imports mentioned above.

