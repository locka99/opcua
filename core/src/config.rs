use std::result::Result;
use std::path::Path;
use std::fs::File;
use std::io::{Read, Write};

use serde;
use serde_yaml;

/// A trait that handles the loading / saving and validity of configuration information for a
/// client and/or server.
pub trait Config {
    fn save(&self, path: &Path) -> Result<(), ()> where Self: serde::Serialize {
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

    fn load<A>(path: &Path) -> Result<A, ()> where A: Config + serde::Deserialize + Sized {
        if let Ok(mut f) = File::open(path) {
            let mut s = String::new();
            if f.read_to_string(&mut s).is_ok() {
                if let Ok(config) = serde_yaml::from_str(&s) {
                    return Ok(config);
                }
            }
        }
        Err(())
    }

    fn is_valid(&self) -> bool;
}
