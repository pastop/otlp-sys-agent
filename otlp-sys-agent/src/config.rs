use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

pub type IptablesCollectorConfig = IptablesConfig;
pub type TemperatureCollectorConfig = TemperatureConfig;
pub type ProcessCollectorConfig = ProcessConfig;

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub agent: AgentConfig,

    #[serde(default)]
    pub otlp: OtlpConfig,

    #[serde(default)]
    pub collectors: CollectorsConfig,
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let config_path = std::env::var("CONFIG_PATH")
            .unwrap_or_else(|_| "/etc/otlp-sys-agent/config.yaml".to_string());

        if Path::new(&config_path).exists() {
            let content = fs::read_to_string(&config_path)
                .with_context(|| format!("Не удалось прочитать конфиг из {}", config_path))?;
            let config: AppConfig = serde_yaml::from_str(&content)
                .with_context(|| format!("Ошибка парсинга YAML конфига из {}", config_path))?;
            Ok(config)
        } else if Path::new("config.yaml").exists() {
            let content = fs::read_to_string("config.yaml")
                .context("Не удалось прочитать локальный config.yaml")?;
            let config: AppConfig = serde_yaml::from_str(&content)
                .context("Ошибка парсинга локального config.yaml")?;
            Ok(config)
        } else if Path::new("otlp-sys-agent/config.yaml").exists() {
            let content = fs::read_to_string("otlp-sys-agent/config.yaml")
                .context("Не удалось прочитать otlp-sys-agent/config.yaml")?;
            let config: AppConfig = serde_yaml::from_str(&content)
                .context("Ошибка парсинга otlp-sys-agent/config.yaml")?;
            Ok(config)
        } else {
            // Если файл конфига не найден — используем дефолтные параметры
            Ok(AppConfig::default())
        }
    }

    pub fn get_hostname(&self) -> String {
        if !self.agent.host_name.is_empty() {
            self.agent.host_name.clone()
        } else {
            gethostname::gethostname().to_string_lossy().into_owned()
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct AgentConfig {
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,

    #[serde(default = "default_log_level")]
    pub log_level: String,

    #[serde(default)]
    pub host_name: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_interval_secs(),
            log_level: default_log_level(),
            host_name: String::new(),
        }
    }
}

fn default_interval_secs() -> u64 {
    10
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct OtlpConfig {
    #[serde(default = "default_endpoint")]
    pub endpoint: String,

    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            endpoint: default_endpoint(),
            timeout_secs: default_timeout_secs(),
        }
    }
}

fn default_endpoint() -> String {
    "http://127.0.0.1:4317".to_string()
}

fn default_timeout_secs() -> u64 {
    5
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct CollectorsConfig {
    #[serde(default)]
    pub temperature: TemperatureConfig,

    #[serde(default)]
    pub iptables: IptablesConfig,

    #[serde(default)]
    pub process: ProcessConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TemperatureConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for TemperatureConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct IptablesConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_iptables_command")]
    pub command: String,

    #[serde(default = "default_true")]
    pub collect_chain_totals: bool,

    #[serde(default)]
    pub only_with_metadata: bool,

    #[serde(default)]
    pub ignore_chains: Vec<String>,

    #[serde(default)]
    pub target_filter: Vec<String>,
}

impl Default for IptablesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            command: default_iptables_command(),
            collect_chain_totals: true,
            only_with_metadata: false,
            ignore_chains: Vec::new(),
            target_filter: Vec::new(),
        }
    }
}

fn default_iptables_command() -> String {
    "iptables-save -c".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProcessConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

fn default_true() -> bool {
    true
}
