# Mosquitto MQTT Broker

This MQTT broker is for testing pubsub. It's not configured to be secure, but convenient, so do not use in a production setting.

## Run

Run with `docker-compose`:

```bash
docker-compose up -d
```

And to stop

```bash
docker-compose down
```

## Sanity test

Using a Python 3 installation (or your equivalent command):

```bash
pip install paho-mqtt
python3 test.py
```

