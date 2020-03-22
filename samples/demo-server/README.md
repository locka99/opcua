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
