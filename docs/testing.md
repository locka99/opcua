# Testing

Unit tests should cover at least the following

* All handwritten serializable data types and enums, e.g. NodeId, Variant etc.
* Chunking messages together, handling errors, buffer limits, multiple chunks
* Size limits validation on string, array fields in encoded messages
* OpenSecureChannel, CloseSecureChannel request and response
* Every service set call
* Sign, verify, encrypt and decrypt
* Data change filters
* Event filters
* Subscription state engine
* Bug fixes

## Integration testing

Integration tests will run a server listening on a port and a client connecting to it via
 a socket to perform tests such as: 

* Discovery service
* Connect / disconnect
* Create / Activate session
* Subscribe to values
* Encrypted communication with each security profile
* Permission based actions, e.g. read node values without session

The integration tests are slower than unit tests and cannot run concurrently so they are run manually.

## Benchmarks

Bench tests will cover potentially CPU intensive operations. Benchmarks will use [Criterion](https://bheisler.github.io/criterion.rs/book/criterion_rs.html)
benchmark framework.

At present there is only benchmark for:

* Populating the address space with the default node set (server)

Invoking benchmarks:

```
$ cd opcua/server
$ cargo bench
```

The Criterion tool runs tests and requires `gnuplot` to generate reports of performance over time. 

## OPC UA test cases

The OPC UA foundation describes tests that servers/clients must pass to implement various profiles or facets. Each is described under the test case links against the facets of each [OPC UA profile](http://opcfoundation-onlineapplications.org/ProfileReporting/index.htm).

These are not performed manually or automatically at present, however much of the functionality
they describe is covered by unit / integration tests and of course interoperability testing.

## 3rd party interoperability testing

OPC UA for Rust contains a couple of samples built with 3rd party OPC UA open source implementations for
interoperability testing.

* Node OPC UA - a NodeJS based implementation
* Open62541 - a C based implementation

These can be used in place of the `simple-client` and `simple-server` samples as appropriate:

```bash
cd opcua/node-opcua
npm install 
node server.js 
# OR 
node client.js
```

The idea is to test the Rust `simple-client` against the Node OPC UA server to ensure it works. Or
test the Rust `simple-server` by connecting to it with the Node OPC UA client.

The Open62541 only has a very basic client implementation so far. It requires a C compiler and CMake. Basic setup instructions:

```
cd opcua/open62541
cmake -G "Unix Makefiles" -B ./cmake-build -S .
cd cmake-build
make
```
