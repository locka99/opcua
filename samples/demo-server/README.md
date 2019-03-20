This `demo-server` is a more full-featured server implemented over OPC UA. It is not
intended to be as basic as `simple-server` and will grow over time to:
 
* Expose more variables, both static and dynamically changing.
* Have variables of every supported data type including arrays
* Be used for testing / verification purposes
* Http access to diagnostics and other info
* More sophisticated logging and data capture

The demo-server enables the `http` feature in `opcua-server` so it can display metrics
from `http://localhost:8585`, however you must start it from the correct directory for the content to resolve. 

```
cd opcua/samples/demo-server
cargo run
```
