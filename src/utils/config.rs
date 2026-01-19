use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Rule {
    pub id: String,
    pub pattern: String,
    // Optional explanation or description
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub rules: Vec<Rule>,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn from_yaml(content: &str) -> Result<Self> {
        let config: Config = serde_yaml::from_str(content)?;
        Ok(config)
    }

    /// Returns the default embedded configuration
    pub fn default_rules() -> Self {
        let yaml = include_str!("../../rules.yaml");
        Self::from_yaml(yaml).expect("Failed to load default rules")
    }
}
