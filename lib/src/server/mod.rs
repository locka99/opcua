// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! The OPC UA Server module contains the server side functionality - address space, services,
//! server security, session management, local discovery server registration and subscriptions.
//!
//! # Usage
//!
//! An implementation will usually start by building a [`ServerConfig`], either
//! from a configuration file, or through code. Then it will construct a [`Server`], initialise
//! its address space, and then run it.
//!
//! [`Server`]: ./server/struct.Server.html
//! [`ServerConfig`]: ./config/struct.ServerConfig.html
//!
//! # Example
//!
//! This is a very simple server which runs with the default address space on the default port.
//!
//!  ```ignore
//!  use opcua::server::prelude::*;
//!
//!  fn main() {
//!      let server: Server = ServerBuilder::new_sample().server().unwrap();
//!      server.run();
//!  }
//!  ```

#[cfg(feature = "discovery-server-registration")]
mod discovery;

#[cfg(feature = "http")]
pub mod http;

pub(crate) mod address_space {
    pub(crate) mod types {
        pub use crate::async_server::address_space::{
            user_access_level, AccessLevel, AddressSpace, DataType, Method, NodeBase, Object,
            ObjectType, ReferenceDirection, ReferenceType, Variable, VariableType,
        };
    }
    pub use crate::async_server::address_space::EventNotifier;
}

pub mod prelude {
    //! Provides a way to use most types and functions commonly used by server implementations from a
    //! single use statement.
    pub use crate::core::prelude::*;
    pub use crate::crypto::*;
    pub use crate::types::service_types::*;
    pub use crate::types::status_code::StatusCode;
}

//#[cfg(test)]
//mod tests;
