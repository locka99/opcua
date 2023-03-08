This is a basic MQTT server for testing pubsub functionality.

## Create certificates

Generate certificates for https access using rumqtt's own tool requires installation of Golang

```
git clone https://github.com/bytebeamio/provision.git
cd provision
go build provision.go
provision ca
provision server --ca ca.cert.pem --cakey ca.key.pem --domain localhost
```

Then copy these .pem files to the `tls` subfolder.

```
capath = "/etc/tls/ca.cert.pem"
certpath = "/etc/tls/server.cert.pem"
keypath = "/etc/tls/server.key.pem"
```

## Usage

Usage:

```
cargo run
```

## Testing basic usage

Use an MQTT client to connect to the server and monitor topic, e.g. https://mqttx.app/