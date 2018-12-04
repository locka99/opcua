This `demo-server` is a more full-featured server implemented over OPC UA. It is not
intended to be as basic as `simple-server` and will grow over time to:
 
* Expose more variables, both static and dynamically changing.
* Have variables of every supported data type including arrays
* Be used for testing / verification purposes
* Http access to diagnostics and other info
* More sophisticated logging and data capture

There is an http server showing metrics running on localhost:8585, however `cargo run` must be issued from `opcua/samples/demo-server`
because it is serving content from a relative path `../../server/html`. 
