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

# Testing configuration

If you are using for testing you may have to do a few things depending on what you're testing against.

In particular pay attention to the `server.conf` file and ensure that:

1. You set `tcp_config.host` and `discovery_urls` to the IP address of the server host. By default it will say localhost
which may interfere with PKI certificate policies 
2. Generate a PKI keypair and ensure it has this same IP address as an alt hostname. If you are testing in an environment
which uses trust you may need your keypair to be signed by a certificate that your environment likes, if it does not
support self-signed certificates.
