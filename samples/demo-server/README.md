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

If you are using the demo server for testing a client you may have to do a few things depending on what you're testing 
against.

1. Copy `server.conf` to `server.test.conf`. The `demo-server` will use the latter if it exists, otherwise falling back
on the former. Note that the default `server.conf` is created during unit testing and is checked in whereas the modified
`server.test.conf` should not be checked in.
2. Edit `server.test.conf`
3. Set `tcp_config.host` and `discovery_urls` to the IP address of the server host. By default it will say `localhost`
which may interfere with PKI certificate policies 
4. Set `create_sample_keypair` to false
4. Generate a PKI keypair that is acceptable to your test environment and matches the IP address you set in the config. Copy
 this to `pki/own/cert.der` and `pki/private/private.pem`.
