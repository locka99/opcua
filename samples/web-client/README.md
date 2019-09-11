`web-client` is a web server that is a client to a OPCUA server. 

Usage:

Run the `demo-server` in one console:

```
cd opcua/samples/demo-server
cargo run
```

Then in another console run the `web-client`

```
cd opcua/samples/web-client
cargo run -- --url opc.tcp://localhost:4855
```

Then open a web browser such as Firefox or Chrome and load the url `http://localhost:8686`. If all goes well you will see
a simple control page with buttons to Connect / Disconnect.

Click "Connect" and the page will establish a websocket session with `web-client` which in turn will
connect to the OPC UA server. 

The page has a section to subscribe to a comma separated list of variables by node id. It has a section to
 subscribe to events by a node id. These sections are prefilled with node ids that exist on the `demo-server`.

The `web-client` maintains a separate OPC UA client session for each browser page so each has its own OPC UA client
session and subscription state. If the "Disconnect" button is clicked, the websocket is dropped and in turn the
OPC UA session will be dropped.

Internally, the web-client consists of an `actix-web` server. There is an `OPCUASession` actor which is bound to a 
websocket context. The actor is created by opening `ws://servername:8686/ws/` which connects to the OPC UA
server when it starts. The client session sends messages to the front end over a websocket as JSON and rendered
by the browser.