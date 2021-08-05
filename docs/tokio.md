# Into

OPC UA for Rust uses Tokio for network I/O, timers and for asynchronous scheduling. Tokio
is basically a scheduler and library used in conjunction with Rust primitives `async` and `await`
for asynchronous execution of code..

Within OPC UA for Rust, async is used for.

* Listening for connections
* Making connections  
* Handshake
* Read / write portions of messaging
* Timeouts
* Side channel commands to abort connections

Despite that, the implementation is also kind of clunky in ways and future async work should 
involve fixing or mitigating that clunkiness.

# Synchronous client API

The client side API is all synchronous externally and async internally. In the future
it would be nice to offer an async and a synchronous API without massively breaking
the existing API. 

Breakage is very probable though because the current code uses read-write locks on the session
for synchronous calls which would not be conduicive to async.

1. Remove `Arc<RwLock<Session>>` if possible. e.g. perhaps Session becomes a cloneable facade with internal locks if necessary but make the struct callable from outside without obtaining any lock.
2. Clean up innards of existing sync - async bridge to make use of Tokio, i.e. replace thread::sleep code
   with async blocks using async timers.
3. ???
4. Asynchronous / Synchronous interfaces


# Synchronous server API

For the most part it doesn't matter that the server is synchronous because most servers are going
to be set-it-and-forget-it deals. Where it might have an impact is on historical read / update
activities, or setter/getters on variables. Basically there may be situations where the server
calls out to the implementor and it would nice if those call outs were asynchronous in some manner.

# Too many threads

Server and client are spawning too many threads for different aspects of their runtime

* Client spawns TWO tokio executors
  * Session has a thread::spawn for an executor
  * TcpTransport has its own thread::spawn and executor. This executor can be single or multi threaded
    depending on configuration.

In theory Client should be able to execute from a single thread assuming Tokio executor was invoked from
main and async API was used. Even in the synchronous case, then 2 threads should be possible - the
synchronous main thread and the session/transport tokio executor thread.

Server side thread use isn't quite so important but it would be nice if thread use
could be minimized.

# Clunky internal mechanics

There are quit flags, states, timers and too much polling going on. Some of this could be simplified.

Ideally it should be possible for a task to be triggered by a state change such that it can loop but not poll on a timer, but on actual change of date it is interested in.

