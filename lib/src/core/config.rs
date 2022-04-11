// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::fs::File;
use std::io::{Read, Write};
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
    fn save(&self, path: &Path) -> Result<(), ()> {
        if self.is_valid() {
            let s = serde_yaml::to_string(&self).unwrap();
            if let Ok(mut f) = File::create(path) {
                let result = f.write_all(s.as_bytes());
                if result.is_ok() {
                    return Ok(());
                } else {
                    error!("Could not save config - error = {:?}", result.unwrap_err())
                }
            } else {
                error!("Cannot create the path to save the config");
            }
        } else {
            error!("Config isn't valid and won't be saved");
        }
        Err(())
    }

    fn load<A>(path: &Path) -> Result<A, ()>
    where
        for<'de> A: Config + serde::Deserialize<'de>,
    {
        if let Ok(mut f) = File::open(path) {
            let mut s = String::new();
            if f.read_to_string(&mut s).is_ok() {
                serde_yaml::from_str(&s).map_err(|err| {
                    error!(
                        "Cannot deserialize configuration from {}, error reason: {}",
                        path.to_string_lossy(),
                        err.to_string()
                    );
                })
            } else {
                error!(
                    "Cannot read configuration file {} to string",
                    path.to_string_lossy()
                );
                Err(())
            }
        } else {
            error!("Cannot open configuration file {}", path.to_string_lossy());
            Err(())
        }
    }

    fn is_valid(&self) -> bool;

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
