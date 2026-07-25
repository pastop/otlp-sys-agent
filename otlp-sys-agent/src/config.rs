use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub agent: AgentConfig,
    pub otlp: OtlpConfig,
    pub collectors: CollectorsConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AgentConfig {
    pub interval_secs: u64,
    pub log_level: String,
    pub host_name: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct IptablesCollectorConfig {
    pub enabled: bool,
    #[serde(default = "default_iptables_command")]
    pub command: String,
    #[serde(default = "default_true")]
    pub collect_chain_totals: bool,
    #[serde(default)]
    pub target_filter: Vec<String>,
    #[serde(default)]
    pub only_with_metadata: bool,
    #[serde(default)]
    pub ignore_chains: Vec<String>,
}

fn default_iptables_command() -> String {
    "iptables-save -c".to_string()
}

fn default_true() -> bool {
    true
}

impl AppConfig {
    /// Получение имени хоста: из конфига, либо из системного /proc/sys/kernel/hostname
    pub fn get_hostname(&self) -> String {
        if let Some(ref h) = self.agent.host_name {
            if !h.trim().is_empty() {
                return h.clone();
            }
        }

        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown-host".to_string())
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct OtlpConfig {
    pub endpoint: String,
    pub timeout_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CollectorsConfig {
    pub temperature: TemperatureCollectorConfig,
    pub iptables: IptablesCollectorConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TemperatureCollectorConfig {
    pub enabled: bool,
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        // Подгружаем .env если есть
        let _ = dotenvy::dotenv();

        let cfg = config::Config::builder()
            // Значения по умолчанию
            .set_default("agent.interval_secs", 10)?
            .set_default("agent.log_level", "info")?
            .set_default("otlp.endpoint", "http://127.0.0.1:4317")?
            .set_default("otlp.timeout_secs", 5)?
            .set_default("collectors.temperature.enabled", true)?
            .set_default("collectors.iptables.enabled", false)?
            // Чтение YAML конфигурации (если нет файла — игнорируем)
            .add_source(config::File::with_name("config.yaml").required(false))
            // Переопределение через ENV (пример: OTLP_AGENT__OTLP__ENDPOINT=http://...)
            .add_source(
                config::Environment::with_prefix("OTLP_AGENT")
                    .separator("__")
                    .ignore_empty(true),
            )
            .build()?;

        let app_config: AppConfig = cfg.try_deserialize()?;
        Ok(app_config)
    }
}
