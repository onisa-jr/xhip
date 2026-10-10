use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub account_id: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub bucket: String,
    pub default_project_dir: Option<String>,
}

impl Config {
    pub fn config_path() -> Result<PathBuf, String> {
        let home = std::env::var("HOME").map_err(|_| "HOME environment variable not set".to_string())?;
        let config_dir = Path::new(&home).join(".config").join("xhip");
        Ok(config_dir.join("config.toml"))
    }

    pub fn load() -> Result<Self, String> {
        let path = Self::config_path()?;
        if !path.exists() {
            return Err(format!(
                "Configuration file not found at {}. Please run 'xhip setup' first.",
                path.display()
            ));
        }

        // Security check: verify file permissions on unix
        if let Ok(metadata) = fs::metadata(&path) {
            let permissions = metadata.permissions();
            let mode = permissions.mode() & 0o777;
            if mode & 0o077 != 0 {
                eprintln!(
                    "Warning: config file permissions {:o} are too open. Recommended is 600.",
                    mode
                );
            }
        }

        let contents = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read config file {}: {}", path.display(), e))?;

        let config: Config = toml::from_str(&contents)
            .map_err(|e| format!("Failed to parse config file: {}", e))?;

        Ok(config)
    }

    pub fn save(&self) -> Result<PathBuf, String> {
        let path = Self::config_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create directory {}: {}", parent.display(), e))?;
            // Ensure directory has restrictive permissions (700)
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }

        let toml_str = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;

        fs::write(&path, toml_str)
            .map_err(|e| format!("Failed to write config to {}: {}", path.display(), e))?;

        // Restrict file permissions to 600 (read/write only by owner)
        let mut perms = fs::metadata(&path)
            .map_err(|e| format!("Failed to get metadata: {}", e))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms)
            .map_err(|e| format!("Failed to set permissions (0600) on config: {}", e))?;

        Ok(path)
    }

    pub fn masked_access_key(&self) -> String {
        if self.access_key_id.len() <= 6 {
            "***".to_string()
        } else {
            let prefix = &self.access_key_id[..3];
            let suffix = &self.access_key_id[self.access_key_id.len() - 3..];
            format!("{}...{}", prefix, suffix)
        }
    }
}
