Integration tests must be run like this:

```
cargo test --features integration -- --test-threads=1
```

Each test runs a server against a client and tests functionality such as connecting with different encryption and
signing levels.