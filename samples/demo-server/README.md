Use `simple-server` as reference for a very simple OPC UA server.

Use `demo-server` (this project) for a more full-featured server that demonstrates the following.

* Exposes static and dynamically changing variables
* Variables of every supported data type including arrays
* Events
* Http access to diagnostics and other info
* More sophisticated logging and data capture
* Be used for testing / verification purposes

The demo-server enables the `http` feature in `opcua-server` so it can display metrics
from `http://localhost:8585`, however you must start it from the `demo-server` directory so it can find its html 
and other resources.

```
cd opcua/samples/demo-server
cargo run
```

## Testing configuration

If you are using the demo server for testing a client you must do a few things depending on what you're testing 
against.

1. Copy `sample.server.test.conf` to `../server.test.conf`. The `demo-server` will load this file
if it exists.
2. Edit `../server.test.conf`
3. Set `tcp_config.host` and `discovery_urls` to the IP address of the server host. Do not set it to localhost
5. Set `create_sample_keypair` to false
6. Generate a PKI keypair that is acceptable to your test environment and matches the IP address you set in the config. Copy
 this to `pki/own/cert.der` and `pki/private/private.pem`.

