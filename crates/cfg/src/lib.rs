pub mod args;

pub mod v1;

use std::path::{Path, PathBuf};

use daemonbase::config::ConfigPath;
use serde::{Deserialize, Serialize};

// Re-export daemonbase so users can get to the inner types used below.
pub use daemonbase;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", tag = "version")]
pub enum Config {
    V1(v1::Config),
}

impl Config {
    /// Creates a configuration from a bytes slice with TOML data.
    pub fn from_toml(
        slice: &str,
        base_dir: Option<impl AsRef<Path>>,
    ) -> Result<Self, toml::de::Error> {
        if let Some(ref base_dir) = base_dir {
            ConfigPath::set_base_path(base_dir.as_ref().into())
        }
        let res = toml::de::from_str(slice);
        ConfigPath::clear_base_path();
        res
    }

    /// Creates a configuration from a configuration file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let toml_str = std::fs::read_to_string(path).unwrap();
        Self::from_toml(&toml_str, None::<PathBuf>).map_err(|err| err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v1() {
        let _config: Config = toml::from_str(
            r#"
            version = 'v1'

            [pkcs11]
            lib-path = '/some/path'
        "#,
        )
        .unwrap();
    }
}
