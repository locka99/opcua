# OPC UA Overview

[OPC UA](https://opcfoundation.org/) is a communication protocol for industrial visualization and control systems. It allows a client to connect to a server over a secure/insecure channel and call services on the server in order to monitor variables, call methods and other activities.

A server listens for connections on a port. A client first connects to that port. It then queries what _endpoints_ the server supports. Endpoints describe different ways of interacting with the server including their security policy. The client will then connect to an endpoint, handshake and establish and activate a session with an identity token. Once activated the client can call services on the server.

OPC UA is very complex to implement (spanning 14 volumes of specification) so it is broken down into a series of profiles that build on each other and describe what features a server should implement.

There are a large number of implementations of the OPC UA protocol both open source and proprietary. All should be interoperable with each other subject to their support for profiles and services.

## OPC UA for Rust

OPC UA for Rust describes its compatibility [here](./compatibility.md).

## Services

An OPC UA server provides _services_ and are grouped into sets. The client calls services depending on what it wants to do. For example a client could subscribe to a particular variable and receive notifications when the value changes.

Services include:

* Subscriptions - create / modify / delete subscriptions to data
* Monitored Items - add / modify / delete items from a subscription
* Discovery - discover other servers
* Attributes - read and write values on the server
* Methods - call methods on the server
* View - browse the server address space

Not all servers support all services, and servers may enforce different limits on what they can do, e.g. maximum number of subscriptions.

A client is expected to know what it can call and what the limits are. A server may drop a connection if an unsupported service is called.

## Protocols

All communication between the client and server are via a transport, of which there are three:

- OPC UA TCP binary
- HTTPS binary
- HTTPS XML SOAP

Not all implementations support all 3 protocols. For example Rust OPC UA only supports OPC UA TCP binary.

## User identities

Sessions are created when the client presents an identity token to the server to identify itself. The identity may be anonymous, username / password, or a security token. The server can use identity to affect what the session is capable of doing.

## Profiles

OPA UA classifies servers into profiles which are bundles of _facets_ that define the services and minimum capabilities that a server should support. Each profile implements everything preceding it. 

* Nano - 1 session, no encryption, user/pass tokens, OPC UA TCP, read attributes
* Micro - 2+ sessions, monitor items
* Embedded - 2+ subscriptions, GetMonitoredItems / ResendData methods, 10+ monitored items, deadband filter
* Standard - 50+ sessions, 5+ subscriptions, diagnostics, register with discovery server, X509 user tokens

These are the _basic_ characteristics of each profile, but the full requirements are described [here](https://apps.opcfoundation.org/profilereporting/).

Servers may implement further facets in addition to these that offer other functionality.

## Endpoints

A client connects to a server using an "endpoint". An endpoint resembles
a standard URL, for example `opc.tcp://servername:port/endpoint/path`.

* `opc.tcp` is the OPC UA TCP schema
* `servername:port` is the host's name and port, e.g. "localhost:4855"
* `/endpoint/path` is the _endpoint_ you wish to connect to, e.g. "/device/metrics".

Endpoints describe a security policy which may be none, or may describe encryption and hash algorithms. If an endpoint is secure, communication with it will be encrypted.

## Security

Endpoints may be secure or insecure. Security is established when the client connects to an endpoint. The endpoint describes the security policy it must use which can be none for no encryption. For a security policy other none and the client / server will present each other with their respective X509 certificates to establish trust.

Once each side trusts the other they will create an encrypted channel with security policy's encryption algorithms to communicate with each other. The client / server can also choose to sign / verify packets in addition to just encrypting them.

## Sessions

After a client has connected to an endpoint, it now presents an identity token to the server to identify itself and activate a session.

Identity tokens may be one of the following:

* Anonymous - an anonymous user.
* User/pass - a username and password.
* X509 - a certificate associated with the user.

A server uses the identity in any way it chooses, e.g. allowing only authorized users to write values while allowing anonymous users to read values.

## More information

* [OPC Foundation](https://opcfoundation.org/)

