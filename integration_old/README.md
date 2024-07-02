Integration tests are to test scenarios between the client and server. 

Since tests create and listen on ports, use pki folders, they must be run one at a time, like this:

```
cargo test --features integration -- --test-threads=1
```

Or use the `run.sh` or `run-sanity.sh` script.

The X509 token required for some tests is in `x509/` and generated like so:

```
openssl req -x509 -nodes -newkey rsa:4096 -keyout user_private_key.pem -outform der -out user_public_cert.der -days 10000
```