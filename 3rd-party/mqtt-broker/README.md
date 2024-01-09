# Mosquitto MQTT Broker

This is for testing pubsub. It's not configured to be secure, but convenient, so do not use in a production setting.

## Installation

```bash
cd opcua/3rd-party/mqtt-broker
docker build -t opcua-mqtt-broker .
```

## Run

To run the broker:

```bash
docker run -it -p 1883:1883 -p 9001:9001 -v /mosquitto/data -v /mosquitto/log opcua-mqtt-broker
```
