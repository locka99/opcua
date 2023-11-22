# OPC UA Feature Support

## OPC UA Binary Transport Protocol

This implementation supports the `opc.tcp://` binary protocol. Binary over `https://` is not supported although it is conceivable that it could be supported.

The implement will **never** implement OPC UA over XML. XML hasn't see much adoption so this is no great impediment.

## Server

The server shall implement the OPC UA capabilities:

* http://opcfoundation.org/UA-Profile/Server/Behaviour - base server profile
* http://opcfoundation.org/UA-Profile/Server/EmbeddedUA - embedded UA profile

### Services

The following services are supported in the server:

* Discovery service set
  * GetEndpoints
  * FindServers - stub that returns BadNotSupported
  * RegisterServer - stub that returns BadNotSupported
  * RegisterServer2 - stub that returns BadNotSupported

* Attribute service set
  * Read
  * Write
  * History Read - 0.8+. The server-side functionality is delegated to callbacks that must be implemented.
  * History Update - 0.8+. The server-side functionality is delegated to callbacks that must be implemented.

* Session service set
  * CreateSession
  * ActivateSession
  * CloseSession
  * Cancel - stub implementation

* Node Management service set
  * AddNodes
  * AddReferences
  * DeleteNodes
  * DeleteReferences

* Query service set
  * QueryFirst - stub that returns BadNotSupported
  * QueryNext - stub that returns BadNotSupported

* View service set
  * Browse
  * BrowseNext
  * TranslateBrowsePathsToNodeIds

* MonitoredItem service set
  * CreateMonitoredItems
    - Data change filter including dead band filtering.
    - Event filter
  * ModifyMonitoredItems
  * SetMonitoringMode
  * SetTriggering
  * DeleteMonitoredItems

* Subscription service set
  * CreateSubscription
  * ModifySubscription
  * DeleteSubscriptions
  * TransferSubscriptions - stub implementation fails on any request
  * Publish
  * Republish
  * SetPublishingMode

* Method service set
  * Call

### Address Space / Nodeset

The standard OPC UA address space is exposed. OPC UA for Rust uses a script to generate code to create and populate the standard address space. This functionality is controlled by a server build feature
`generated-address-space` that defaults to on but can be disabled if the full address space is not required. When disabled, the address space will be empty apart from some root objects.

### Current limitations

Currently the following are not supported

* Diagnostic info. OPC UA allows for you to ask for diagnostics with any request. None is supplied at this time
* Session resumption. If your client disconnects, all information is discarded.
* Default node set is mostly static. Certain fields of server information will contain their default values unless explicitly set.
* Access control is limited to setting read/write permissions on nodes that apply to all sessions.
* Multiple created sessions in a single transport.

## Client

The client API API is synchronous - i.e. you call a function that makes a request and it returns
when the response is received or a timeout occurs. Under the surface it is asynchronous so that functionality may be exposed at some point.

The client exposes functions that correspond to the current server supported profile, i.e. look above at the server services and there will be client-side functions that are analogous to those services.

In addition to the server services above, the following are also supported.

* FindServers - when connected to a discovery server, to find other servers
* RegisterServer - when connected to a discovery server, to register a server

Potentially the client could have functions to call other services so it could be used to call other
OPC UA implementation.

## Configuration

Server and client can be configured programmatically via a builder or by configuration file. See
the `examples/` folder for examples of client and server side configuration.

The config files are specified in YAML but this is controlled via serde so the format is not hard-coded.

## Encryption modes

Server and client support endpoints with the standard message security modes:

* None
* Sign
* SignAndEncrypt

The following security policies are supported:

* None
* Basic128Rsa15
* Basic256
* Basic256Rsa256
* Aes128-Sha256-RsaOaep
* Aes256-Sha256-RsaPss

## User identities

The server and client support the following user identity tokens

1. Anonymous - i.e. no identity
2. UserName - encrypted and plaintext. User/pass identities are defined by configuration.
3. X509 certificates

## Crypto

OPC UA for Rust uses cryptographic algorithms for signing, verifying, encrypting and decrypting data. In addition it creates, loads and saves certificates and keys.

OpenSSL is used for encryption although it would be nice to go to a pure Rust implementation assuming a crate delivers everything required. The crypto+OpenSSL code is isolated in an `opcua-crypto` crate.

You must read the [setup](./setup.md) to configure OpenSSL for your environment.

### Certificate pki structure

The server / client uses the following directory structure to manage trusted/rejected certificates:

```
pki/
  own/
    cert.der - your server/client's public certificate
  private/
    key.pem  - your server/client's private key
  trusted/
    ...      - contains certs from client/servers you've connected with and you trust
  rejected/
    ...      - contains certs from client/servers you've connected with and you don't trust
```

For encrypted connections the following applies:

* The server will reject the first connection from an unrecognized client. It will create a file representing the cert in its the `pki/rejected/` folder and you, the administrator must move the cert to the `trusted/` folder to permit connections from that client in future.
    * NOTE: Signed certificates are not supported at this time. Potentially a cert signed with a trusted CA could be automatically moved to the `trusted/` folder.
* Likewise, the client shall reject unrecognized servers in the same fashion, and the cert must be moved from the `rejected/` to `trusted/` folder for connection to succeed.
* Servers that register with a discovery server may find the discovery server rejects their registration attempts if the cert is unrecognized. In that case you must move your server's cert from discovery server's  `rejected` to its ``trusted` folder, wherever that may be. e.g. on Windows it is under `C:\ProgramData\OPC Foundation\UA\Discovery\pki`

There are switches in config that can be used to change the folder that certs are stored and to modify
the trust model.

### Certificate creator tool

The `tools/certificate-creator` tool will create a demo public self-signed cert and private key.
It can be built from source, or the crate:

```bash
$ cargo install --force opcua-certificate-creator
```

A minimal usage might be something like this inside examples/simple-client and/or examples/simple-server:

```bash
$ opcua-certificate-creator --pkipath ./pki
```

A full list of arguments can be obtained by ```--help``` and you are advised to set fields such
as expiration length, description, country code etc to your requirements.
