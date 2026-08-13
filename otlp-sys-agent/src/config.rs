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

    #[serde(default)]
    pub filesystem: FilesystemConfig,

    #[serde(default)]
    pub disk: DiskConfig,
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

#[derive(Debug, Deserialize, Clone)]
pub struct DiskConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Игнорировать device-mapper устройства (dm-0, dm-1 — LVM)
    #[serde(default = "default_true")]
    pub ignore_device_mapper: bool,
    /// Список устройств для игнорирования
    #[serde(default)]
    pub ignore_devices: Vec<String>,
    /// Собирать I/O статистику (read/write counters)
    #[serde(default = "default_true")]
    pub collect_io: bool,
}

impl Default for DiskConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ignore_device_mapper: true,
            ignore_devices: Vec::new(),
            collect_io: true,
        }
    }
}

// После ProcessConfig:

#[derive(Debug, Deserialize, Clone)]
pub struct FilesystemConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_ignore_mount_points")]
    pub ignore_mount_points: Vec<String>,
    #[serde(default = "default_ignore_fs_types")]
    pub ignore_fs_types: Vec<String>,
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ignore_mount_points: default_ignore_mount_points(),
            ignore_fs_types: default_ignore_fs_types(),
        }
    }
}

fn default_ignore_mount_points() -> Vec<String> {
    vec![
        "/proc".to_string(),
        "/sys".to_string(),
        "/dev".to_string(),
        "/run".to_string(),
        "/snap".to_string(),
    ]
}

fn default_ignore_fs_types() -> Vec<String> {
    vec![
        "tmpfs".to_string(),
        "devtmpfs".to_string(),
        "squashfs".to_string(),
        "overlay".to_string(),
        "proc".to_string(),
        "sysfs".to_string(),
        "cgroup".to_string(),
        "cgroup2".to_string(),
        "devpts".to_string(),
        "mqueue".to_string(),
        "hugetlbfs".to_string(),
        "debugfs".to_string(),
        "tracefs".to_string(),
        "securityfs".to_string(),
        "pstore".to_string(),
        "bpf".to_string(),
        "autofs".to_string(),
        "binfmt_misc".to_string(),
        "rpc_pipefs".to_string(),
        "nsfs".to_string(),
        "ramfs".to_string(),
        "fuse.lxcfs".to_string(),
    ]
}

fn default_true() -> bool {
    true
}
