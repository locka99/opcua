Integration tests must be run like this:

```
cargo test --features integration -- --test-threads=1
```

Each test runs a server against a client and tests functionality such as connecting with different encryption and
signing levels.

NOTE: Integration tests are currently broken. Some tokio tasks related to network IO are not terminating which causes 
the tokio::run on the server to never exit on demand.