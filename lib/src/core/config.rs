// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::result::Result;

use serde;
use serde_yaml;

use crate::types::{
    service_types::{ApplicationDescription, ApplicationType},
    LocalizedText, UAString,
};

/// A trait that handles the loading / saving and validity of configuration information for a
/// client and/or server.
pub trait Config: serde::Serialize {
    fn save(&self, path: &Path) -> Result<(), ConfigSaveError> {
        let _ = self.is_valid()?;
        let s = serde_yaml::to_string(&self).unwrap();
        let mut f = File::create(path)?;
        f.write_all(s.as_bytes())?;
        Ok(())
    }

    fn load<A>(path: &Path) -> Result<A, ConfigLoadError>
    where
        for<'de> A: Config + serde::Deserialize<'de>,
    {
        let s = std::fs::read_to_string(path)?;
        serde_yaml::from_str(&s).map_err(ConfigLoadError::from)
    }

    fn is_valid(&self) -> Result<(), ConfigError>;

    fn application_name(&self) -> UAString;

    fn application_uri(&self) -> UAString;

    fn product_uri(&self) -> UAString;

    fn application_type(&self) -> ApplicationType;

    fn discovery_urls(&self) -> Option<Vec<UAString>> {
        None
    }

    fn application_description(&self) -> ApplicationDescription {
        ApplicationDescription {
            application_uri: self.application_uri(),
            application_name: LocalizedText::new("", self.application_name().as_ref()),
            application_type: self.application_type(),
            product_uri: self.product_uri(),
            gateway_server_uri: UAString::null(),
            discovery_profile_uri: UAString::null(),
            discovery_urls: self.discovery_urls(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Application Name is empty")]
    AppNameEmpty,

    #[error("Application URI not set")]
    UriEmpty,

    #[error("User tokens contains the reserved \"{}\" id", .0)]
    UserTokenReserved(String),

    #[error("User tokens contains an endpoint with an empty id")]
    UserTokenEndpointEmptyId,

    #[error("No Endpoints defined")]
    NoEndpointDefined,

    #[error("Endpoints contains an endpoint with an empty id")]
    EndpointEmptyId,

    #[error("Default endpoint id {} does not exist in list of endpoints", .0)]
    DefaultEndpointIdNotInEndpoints(String),

    #[error("Max array length is zero, which is invalid")]
    MaxArrayLengthIsZero,

    #[error("Max string length is zero, which is invalid")]
    MaxStringLengthIsZero,

    #[error("Max byte string length is zero, which is invalid")]
    MaxByteStringLengthIsZero,

    #[error("Discovery urls not set")]
    DiscoveryUrlMissing,

    #[error("Cannot find user token with id {}", .0)]
    UnknownUserToken(String),

    #[error("User token cannot be empty")]
    UserTokenEmpty,

    #[error("User token {} holds a password and certificate info - it cannot be both", .0)]
    UserTokenBothPasswordAndCert(String),

    #[error("User token {} fails to provide a password or certificate info", .0)]
    UserTokenNoPassOrCert(String),

    #[error("User token {} fails to provide both a certificate path and a private key path.", .0)]
    UserTokenNoCertNoPrivKey(String),

    #[error("User token {} is invalid because id is a reserved value, use another value.", .0)]
    UserTokenReservedValue(String),

    #[error("Specified security policy \"{}\" is not recognized", .0)]
    UnknownSecurityPolicy(String),

    #[error("Endpoint {} is invalid. Security mode \"{}\" is invalid. Valid values are None, Sign, SignAndEncrypt", .id, .security_mode)]
    SecurityModeInvalid {
        id: String,
        security_mode: String,
    },

    #[error("Endpoint {} is invalid. Security policy and security mode must both contain None or neither of them should.", .0)]
    SecurityPolicyEitherBothOrNeitherNone(String),

    #[error("Session retry limit of {} is invalid - must be -1 (infinite), 0 (never) or a positive value", .0)]
    SessionRetryLimitInvalid(i32),
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigSaveError {
    #[error(transparent)]
    ConfigError(#[from] ConfigError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigLoadError {
    #[error(transparent)]
    ConfigError(#[from] ConfigError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    SerdeYaml(#[from] serde_yaml::Error),

}

