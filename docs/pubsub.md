# OPC PubSub

Support for PubSub is experimental.

PubSub allows a client to listen to a subject over some transport
mechanism (UDP, or MQTT) to which a server publishes
information without establishing a direct connection or session with the server.

The benefit of PubSub is potentially allows things like aggregation,
multiple clients, to efficiently receive change notifications.

## Example Server

```rust


```

## Example Client

```rust

```