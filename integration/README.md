Integration tests are to test scenarios between the client and server. 

Since tests create and listen on ports, use pki folders, they must be run one at a time, like this:

```
cargo test --features integration -- --test-threads=1
```

Or use the `run.sh` or `run-sanity.sh` script.


