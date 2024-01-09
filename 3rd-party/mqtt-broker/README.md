This is prepackaged MQTT broker for use with pubsub examples. The broker is a Docker image based on Eclipse Mosquitto.

It's not configured to be secure, but convenient, so do not use in a production setting.

```bash
cd opcua/3rd-party/mqtt-broker
docker build -t opcua-mqtt-broker .
```

To run the broker:

```bash
docker run -it -p 1883:1883 -p 9001:9001 -v /mosquitto/data -v /mosquitto/log opcua-mqtt-broker
```
