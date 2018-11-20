This is a simple OPC UA client hooked up to an MQTT client. It demonstrates a simple bridging app 
that subscribes to variables from an OPC server and publishes them to an MQTT broker.

The default MQTT server broker.hivemq.com:1883 which you can observe from the client:

1. Open http://www.hivemq.com/demos/websocket-client/
2. Connect with the default values
3. Subscribe to opcua-rust/# 
