# Migration from earlier versions

Any version breaking changes are described below.

## Migration from 0.10 and below

### New synchronization classes

0.11+ uses synchronization `RwLock` and `Mutex` from the [parking_lot](https://crates.io/crates/parking_lot) crate instead of `std`. So if you have compiler errors, replace your imports with:

```rust
use opcua::sync::*;
```

They haven't been added to the `opcua::client::prelude` or `opcua::server::prelude` in case
your code uses `std::sync` types for other reasons that you need to resolve manually.

## Migrating from 0.9 and below

### Unified crate

OPC UA for Rust is now a single crate instead of many crates as it used to be. This makes it simpler to use, and also maintain and publish. If you are using 0.9 or below, you will have to make some minor adjustments to use the new
layout.

In your Cargo.toml, reference the `opcua` crate instead of either `opcua-server` or `opcua-client` and specify `client` and/or `server` in the features, e.g.

```toml
[dependencies]
opcua = { version = "0.10", features = ["client"] }
```

And in your source code, use `opcua::client::` or `opcua::server::` instead of `opcua_client::` or `opcua_server::`, e.g.

```rust
use opcua::client::prelude::*;
```
