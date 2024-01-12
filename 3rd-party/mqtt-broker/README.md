# Mosquitto MQTT Broker

This MQTT broker is for testing pubsub. It's not configured to be secure, but convenient, so do not use in a production setting.

Note: if you run this from Windows you might see complaints in `mosquitto/log/mosquitto.log` about incorrect file permissions for the files it puts under `mosquitto/`. These are warning for time being but if they become hard errors you can comment out the volume points in the `docker-compose.yml`.

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

