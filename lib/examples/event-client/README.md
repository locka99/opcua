This is a simple client that will connect to a server and subscribe to alarms / events.

Example usage

```sh
cargo run --example event-client -- --url opc.tcp://opcua.demo-this.com:62544/Quickstarts/AlarmConditionServer --event-source i=2253
```
