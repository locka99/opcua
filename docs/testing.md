# Testing

## Unit tests

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

Unit tests are part of a normal development cycle and you should ensure adequate coverage of new code with tests that are preferably in the same
file as the code being tested.

```bash
cd opcua
cargo test --all
```

## Integration testing

Integration tests will run a server listening on a port and a client connecting to it via a socket to perform tests such as:

* Discovery service
* Connect / disconnect
* Create / Activate session
* Subscribe to values
* Encrypted communication with each security profile
* User identity tokens - anonymous, user/pass, x509
* Permission based actions, e.g. read node values without session

The integration tests are slower than unit tests and cannot run concurrently so they are run manually.

Integration tests are under `integration/`. The tests are marked `#[ignore]` to prevent them running as a unit test. To run them use the provided
script that runs them one at a time.

```bash
cd opcua/integration
sh ./run.sh
```

## Fuzz testing

Fuzzing involves feeding deliberately junk / randomized data to the code and
seeing how it copes with it. If it panics or otherwise functions in an uncontrolled fashion then it has exposed an error in the code.

Fuzz testing requires a nightly version of Rust and is [restricted to certain platforms](https://rust-fuzz.github.io/book/cargo-fuzz/setup.html).

Read the link above setup basically involves this:

```bash
rustup install nightly
cargo install cargo-fuzz
```

To run:

```bash
cd opcua/lib
rustup default nightly
cargo fuzz list
cargo fuzz run fuzz_deserialize
cargo fuzz run fuzz_comms
```

Future candidates for fuzzing might include:

* Chunks
* Crypto / signing / verification of chunks
* ExtensionObject containing junk
* DateTime parsing
* EventFilter
* Browse Paths

We might also want to make the fuzzing "structure aware". This involves implementing or deriving an "Arbitrary" trait on types we want to be randomized. See link above for examples.

## Benchmarks

Bench tests will cover potentially CPU intensive operations. Benchmarks will use [Criterion](https://bheisler.github.io/criterion.rs/book/criterion_rs.html)
benchmark framework.

At present there is only benchmark for:

* Populating the address space with the default node set (server)

Invoking benchmarks:

```bash
cd opcua/lib
cargo bench
```

The Criterion tool runs tests and requires `gnuplot` to generate reports of performance over time.

Potential benchmarks might include:

* Handling multiple concurrent connections under load
* Performing complex pattern searches on the address space
* Memory

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

```bash
cd opcua/open62541
cmake -G "Unix Makefiles" -B ./cmake-build -S .
cd cmake-build
make
```
