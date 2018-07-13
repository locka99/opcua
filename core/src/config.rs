use std::result::Result;
use std::path::Path;
use std::fs::File;
use std::io::{Read, Write};

use serde;
use serde_yaml;

use opcua_types::{UAString, LocalizedText};
use opcua_types::service_types::{ApplicationDescription, ApplicationType};

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

    fn load<A>(path: &Path) -> Result<A, ()> where for<'de> A: Config + serde::Deserialize<'de> + Sized {
        if let Ok(mut f) = File::open(path) {
            let mut s = String::new();
            if f.read_to_string(&mut s).is_ok() {
                let config = serde_yaml::from_str(&s);
                if let Ok(config) = config {
                    Ok(config)
                } else {
                    error!("Cannot deserialize configuration from {}", path.to_string_lossy());
                    Err(())
                }
            } else {
                error!("Cannot read configuration file {} to string", path.to_string_lossy());
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

    fn application_description(&self) -> ApplicationDescription {
        ApplicationDescription {
            application_uri: self.application_uri(),
            application_name: LocalizedText::new("", self.application_name().as_ref()),
            application_type: ApplicationType::Client,
            product_uri: self.product_uri(),
            gateway_server_uri: UAString::null(),
            discovery_profile_uri: UAString::null(),
            discovery_urls: None,
        }
    }
}
