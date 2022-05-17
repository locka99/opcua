# Into

OPC UA for Rust is asynchronous inside. It uses Tokio in conjunction
with Rust primitives `async` and `await` and the `Future` trait for asynchronous
execution of code. Tokio provides the scheduler, IO and timers that are used 
for:

* Listening for connections
* Making connections  
* Handshake
* Read / write portions of messaging
* Timeouts
* Side channel commands to abort connections

The implementation does have some rough edges especially around excessive
locking and some shared state and future work should focus on improving
that.

# Room for improvement

## Use a supplied tokio runtime

At present tokio is setup and run internally. Perhaps the server and client should
allow the runtime to be defined by the API consumer. e.g. perhaps the thing using
OPC UA for Rust has its own tokio executor and would prefer we use that.

## Synchronous client API

The client side API is synchronous externally and async internally. That is to say, 
the client calls a function and waits for it to execute (or fail). In the future
it would be nice to also offer an async API without massively breaking
the existing API. 

Breakage is very probable though because the current code uses read-write locks
on the session for synchronous calls which would not be conduicive to async.

1. Remove `Arc<RwLock<Session>>` if possible. e.g. perhaps Session becomes a cloneable facade with internal locks if necessary but make the struct callable from outside without obtaining any lock.
2. Clean up innards of existing sync - async bridge to make use of Tokio, i.e. replace thread::sleep code
   with async blocks using async timers.
3. ???
4. Asynchronous / Synchronous interfaces

## Synchronous server message processing

All networking is asynchronous, i.e. buffers are filled and turned into requests via
tokio.

The processing of requests is currently synchronous, i.e. a request is processed and
reponse returned in a single thread. 

For the most part this doesn't matter. Where it might have an impact is on historical read / update
activities, or setter/getters on variables. These potentially could 
take some time to complete so it would be desirable that some requests / responses
became tasks that could be executed out of order to completion without delaying 
other requests & responses.

## Too many threads

Server and client are spawning too many threads for different aspects of their runtime

The client uses a minimum of 2 threads, if tokio is set to use a single threaded executor.
The main thread is the synchronous API, the other thread(s) is where asynchronous tasks
are executed. Perhaps if there was an async API to the client, then all of its functionality
could reside in a single thread, although the caller would still be running on its own
thread.

Server side thread use isn't quite so important but it would be nice if thread use
could be minimized. At present the server thread usage is controlled via a single threaded
executor flag but no effort has been made to see if there are other threads being spawned
that could be optimized away. For example if the server registers with a discovery server
then it uses a thread for that and the client side API will spawn another thread.

## Locks should be Tokio too

The codebase has locking mechanisms for shared objects such as sessions, state, address space etc. At present they
are protected with conventional `RwLock` and `Mutex` structures. The code obtains the appropriate lock before performing
actions. The problem for tokio, is that these block and degrade performance. It might be possible to
use tokio compatible locks where if the lock cannot be obtained, the thread yields and more progress can be made on other
tasks.  

If it is *not* possible to use a Lock, then it might be that some refactoring of code that uses locks can
alleviate some of the contention. 

## Clunky internal mechanics

During tokio 0.1 there are quit flags, states, timers and too much polling going on. A lot of this
mess was removed when moving tokio 1.0 and to `await` and `async` semantics.
Now state didn't have to be passed around between tasks, instead being pinned by
implementation. 

Even so, there is a lot of locking and shared references (via `Arc<RwLock>` or 
`Arc<Mutex>` encapsulated structures). Perhaps this can be reduced.
