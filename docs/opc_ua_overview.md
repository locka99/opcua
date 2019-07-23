# OPC UA Overview

[OPC UA](https://opcfoundation.org/) is a standardized communication protocol for industrial visualization and control systems. It
allows devices to talk with one another over an encrypted or unencrypted channel. 

The protocol is a client / server architecture so the client must connect to a server, and the server may be
providing information to more than one client.

## Services

The server provides _services_ and are grouped into sets. Clients connect to a server and call services 
depending on what they want to do. For example a client could subscribe to a particular variable and receive 
notifications when the value changes.

Services include:

* Subscriptions - create / modify / delete subscriptions to data
* Monitored Items - add / modify / delete items from a subscription
* Discovery - discover other servers
* Attributes - read and write values on the server
* Methods - call methods on the server
* View - browse the server address space

Not all servers (or the APIs they're built with) support all services, or they may have limitations that 
affect what the service supports. 

## Protocols

All communication between the client and server is via a protocol, of which there are three:

- OPC UA TCP binary
- HTTPS binary
- HTTPS XML SOAP

Not all implementations support all 3 protocols. For example Rust OPC UA only supports OPC UA TCP binary.

## Encryption

Connections may be unencrypted or encrypted. Servers may support a trust model so that only trusted clients
and servers may communicate with each other.

## User identities

Sessions are created when the client presents an identity token to the server to identify itself. The identity
may be anonymous, username / password, or a security token. The server can use identity to affect what the
session is capable of doing.

## Profiles

OPA UA classifies servers into profiles by what services they support

## Endpoints

A client connects to a server using an "endpoint". An endpoint resembles a standard URL, for example `opc.tcp://servername:port/endpoint/path`.

* `opc.tcp` is the OPC UA TCP schema
* `servername:port` is the host's name and port, e.g. "localhost:4855"
* `/endpoint/path` is the _endpoint_ you wish to connect to, e.g. "/device/metrics".

Endpoints may or may not be protected by security. If an endpoint is secured, communication with it will be encrypted. 
OPC UA uses asymmetric encryption and certificates to secure communication between a client and server. By default
a secure server will not trust a client it does not recognize, so there is a trust model.

In addition, a server may require the client to supply an identity token - either a password or a certificate to prove 
who is using it for the duration of the active session. The current identity may be used by the server to limit
access to certain services.

## More information

* [Official website](https://opcfoundation.org/)

