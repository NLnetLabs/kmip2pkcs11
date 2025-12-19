pub mod args;

pub mod v1;

use serde::{Deserialize, Serialize};

// Re-export daemonbase so users can get to the inner types used below.
pub use daemonbase;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", tag = "version")]
pub enum Config {
    V1(v1::Config),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v1() {
        let config: Config = toml::from_str(r#"
            version = 'v1'
            lib_path = '/some/path'
        "#).unwrap();
    }
}
