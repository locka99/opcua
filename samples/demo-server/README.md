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

### Troubleshooting

* It is best to try opening Project settings in test harness and browsing to server first to ensure trust is possible, and to troubleshoot any basic connection issues.
* Check logs if certs are rejected.
* If you get `BadCertificateTimeInvalid` returned to the test harness, try setting `check_time`
  to `false` in the `server.test.conf`. For some reason test harness uses certs which can be out of date.
* If the network is IPv6, use `127.0.0.1` instead of the machine name or `localhost`

## Run using Docker

If you want to build the demo server and don't have a development environment then another option is to use docker as follows:

```sh
cd opcua
docker build -t opcua-rs/demo-server:latest . -f samples/demo-server/Dockerfile
```

And then to run it:

```sh
docker run -d opcua-rs/demo-server:latest
```
