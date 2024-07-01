This is a simple OPC UA client hooked up to an MQTT client. It demonstrates how you might write a bridging app 
that subscribes to variables from an OPC server and publishes them to an MQTT broker.

To run the sample:

1. Run either simple-server or 3rd-party/node-opcua/server.js in one console
2. Run mqtt-client in another

This will subscribe to some nodes on the server and publish them to a MQTT broker, (default broker.hivemq.com:1883).

e.g. when node "ns=2;s=v1" changes, it publishes it's value to the "opcua-rust/mqtt-client/2/v1" topic on the server.

You can observe happening by running another MQTT client that subscribes to this same topic. The easiest way is this:

1. Open http://www.hivemq.com/demos/websocket-client/
2. Click "Connect" to the broker with the pre-filled values
3. Click "Add New Topic Subscription", enter "opcua-rust/mqtt-client/#" as the topic and click "Subscribe" 
4. You should see messages arrive that were published