This file is a merged representation of a subset of the codebase, containing files not matching ignore patterns, combined into a single document by Repomix.

<file_summary>
This section contains a summary of this file.

<purpose>
This file contains a packed representation of a subset of the repository's contents that is considered the most important context.
It is designed to be easily consumable by AI systems for analysis, code review,
or other automated processes.
</purpose>

<file_format>
The content is organized as follows:
1. This summary section
2. Repository information
3. Directory structure
4. Repository files (if enabled)
5. Multiple file entries, each consisting of:
  - File path as an attribute
  - Full contents of the file
</file_format>

<usage_guidelines>
- This file should be treated as read-only. Any changes should be made to the
  original repository files, not this packed version.
- When processing this file, use the file path to distinguish
  between different files in the repository.
- Be aware that this file may contain sensitive information. Handle it with
  the same level of security as you would the original repository.
</usage_guidelines>

<notes>
- Some files may have been excluded based on .gitignore rules and Repomix's configuration
- Binary files are not included in this packed representation. Please refer to the Repository Structure section for a complete list of file paths, including binary files
- Files matching these patterns are excluded: **/static*, **/__pycache__*
- Files matching patterns in .gitignore are excluded
- Files matching default ignore patterns are excluded
- Files are sorted by Git change count (files with more changes are at the bottom)
</notes>

</file_summary>

<directory_structure>
otlp-sys-agent/
  src/
    collectors/
      process/
        collector.rs
        mod.rs
        procfs.rs
      filesystem.rs
      iptables.rs
      mod.rs
      temperature.rs
    collector.rs
    config.rs
    lib.rs
    main.rs
    telemetry.rs
  tests/
    iptables_test.rs
    procfs_test.rs
  .env.example
  .gitignore
  Cargo.toml
  config.yaml
.gitignore
GrafanaCPUTempDashBoardExample.json
GrafanaCPUTempDashBoardExample.png
GrafanaIPTablesDashboard.png
GrafanaIPTablesDashBoardExample.json
README.md
Taskfile.yml
</directory_structure>

<files>
This section contains the contents of the repository's files.

<file path="otlp-sys-agent/src/collectors/filesystem.rs">
use nix::sys::statvfs::{statvfs, FsFlags};
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub struct FsMetrics {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub reserved_bytes: u64,
    pub inodes_total: u64,
    pub inodes_free: u64,
    pub is_read_only: bool,
}

pub fn collect_fs_metrics() -> Vec<FsMetrics> {
    let mut metrics = Vec::new();
    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();

    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 { continue; }

        let device = parts[0];
        let mount_point = parts[1];
        let fs_type = parts[2];

        if !device.starts_with("/dev/") {
            continue;
        }

        let stat = match statvfs(Path::new(mount_point)) {
            Ok(s) => s,
            Err(_) => continue, // В рабочем коде здесь стоит писать в log::warn!
        };

        let block_size = stat.fragment_size() as u64;
        let total_bytes = stat.blocks() as u64 * block_size;
        let free_root_bytes = stat.blocks_free() as u64 * block_size;
        let free_user_bytes = stat.blocks_available() as u64 * block_size;

        let used_bytes = total_bytes - free_root_bytes;
        let reserved_bytes = free_root_bytes.saturating_sub(free_user_bytes);
        let is_read_only = stat.flags().contains(FsFlags::ST_RDONLY);

        metrics.push(FsMetrics {
            device: device.to_string(),
            mount_point: mount_point.to_string(),
            fs_type: fs_type.to_string(),
            total_bytes,
            used_bytes,
            reserved_bytes,
            inodes_total: stat.files() as u64,
            inodes_free: stat.files_free() as u64,
            is_read_only,
        });
    }

    metrics
}
</file>

<file path="otlp-sys-agent/src/collectors/process/mod.rs">
pub mod collector;
pub mod procfs;

pub use collector::ProcessCollector;
</file>

<file path="otlp-sys-agent/src/collectors/process/procfs.rs">
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Метрики ввода-вывода (I/O) процесса из /proc/[pid]/io
#[derive(Debug, Clone, Default)]
pub struct ProcessIoInfo {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub syscr: u64, // Количество системных вызовов чтения (read syscalls)
    pub syscw: u64, // Количество системных вызовов записи (write syscalls)
}

/// Структура базовой информации о процессе из /proc
#[derive(Debug, Clone)]
pub struct ProcessProcInfo {
    pub pid: u32,
    pub comm: String,
    pub cmdline: String,
    pub uid: u32,
    pub username: String,
    pub state: String,
    pub systemd_unit: Option<String>,
    pub utime_ticks: u64,
    pub stime_ticks: u64,
    pub vsize_bytes: u64,
    pub rss_bytes: u64,
    pub num_threads: u64,
    pub io: Option<ProcessIoInfo>, // I/O статистика
    pub open_fds: Option<u64>,     // Кол-во открытых дескрипторов
}

/// Чтец файловой системы /proc
pub struct ProcFsReader {
    user_map: HashMap<u32, String>,
    page_size: u64,
}

impl ProcFsReader {
    pub fn new() -> Self {
        Self {
            user_map: Self::load_user_map(),
            page_size: 4096, // Стандартный размер страницы памяти Linux (4 KiB)
        }
    }

    /// Быстрая загрузка пользователей из /etc/passwd для маппинга UID -> Имя пользователя
    fn load_user_map() -> HashMap<u32, String> {
        let mut map = HashMap::new();
        if let Ok(content) = fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 {
                    if let Ok(uid) = parts[2].parse::<u32>() {
                        map.insert(uid, parts[0].to_string());
                    }
                }
            }
        }
        map
    }

    /// Обход всех директорий PID в /proc
    pub fn collect_processes(&self) -> Vec<ProcessProcInfo> {
        let proc_path = Path::new("/proc");
        let mut processes = Vec::new();

        let entries = match fs::read_dir(proc_path) {
            Ok(e) => e,
            Err(_) => return processes,
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();

            // Если имя папки состоит только из цифр — это PID
            if let Ok(pid) = name_str.parse::<u32>() {
                if let Some(info) = self.read_process_info(pid) {
                    processes.push(info);
                }
            }
        }

        processes
    }

    /// Парсинг /proc/[pid]/stat, /proc/[pid]/status и /proc/[pid]/cmdline
    fn read_process_info(&self, pid: u32) -> Option<ProcessProcInfo> {
        let pid_dir = Path::new("/proc").join(pid.to_string());

        // 1. Чтение /proc/[pid]/stat
        let stat_content = fs::read_to_string(pid_dir.join("stat")).ok()?;
        let (comm, rest) = parse_stat_comm(&stat_content)?;
        let fields: Vec<&str> = rest.split_whitespace().collect();

        // Поля после comm (вырезан comm в скобках, поэтому сдвиг):
        // fields[0]  -> state (R, S, D, Z, T и др.)
        // fields[11] -> utime (14-е поле в оригинале)
        // fields[12] -> stime (15-е поле в оригинале)
        // fields[17] -> num_threads (20-е поле в оригинале)
        // fields[20] -> vsize (23-е поле в оригинале)
        // fields[21] -> rss в страницах (24-е поле в оригинале)
        if fields.len() < 22 {
            return None;
        }

        let state = fields[0].to_string();
        let utime_ticks = fields[11].parse::<u64>().unwrap_or(0);
        let stime_ticks = fields[12].parse::<u64>().unwrap_or(0);
        let num_threads = fields[17].parse::<u64>().unwrap_or(1);
        let vsize_bytes = fields[20].parse::<u64>().unwrap_or(0);
        let rss_pages = fields[21].parse::<u64>().unwrap_or(0);
        let rss_bytes = rss_pages * self.page_size;

        // 2. Чтение /proc/[pid]/status для UID
        let uid = read_proc_uid(&pid_dir.join("status")).unwrap_or(0);
        let username = self
            .user_map
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| uid.to_string());

        // 3. Чтение /proc/[pid]/cmdline
        let cmdline = match fs::read(pid_dir.join("cmdline")) {
            Ok(bytes) => {
                let raw = String::from_utf8_lossy(&bytes);
                let clean = raw.replace('\0', " ").trim().to_string();
                if clean.is_empty() {
                    comm.clone()
                } else {
                    clean
                }
            }
            Err(_) => comm.clone(),
        };

        // 4. Определение systemd_unit из /proc/[pid]/cgroup
        let systemd_unit = read_process_systemd_unit(&pid_dir.join("cgroup"));

        // 5. Чтение I/O статистики из /proc/[pid]/io
        let io = read_process_io(&pid_dir.join("io"));

        // 6. Подсчет открытых файловых дескрипторов из /proc/[pid]/fd
        let open_fds = count_open_fds(&pid_dir.join("fd"));

        Some(ProcessProcInfo {
            pid,
            comm,
            cmdline,
            uid,
            username,
            state,
            systemd_unit,
            utime_ticks,
            stime_ticks,
            vsize_bytes,
            rss_bytes,
            num_threads,
            io,
            open_fds,
        })
    }
}

/// Парсинг файла /proc/[pid]/io
pub fn read_process_io(io_path: &Path) -> Option<ProcessIoInfo> {
    let content = fs::read_to_string(io_path).ok()?;
    let mut io = ProcessIoInfo::default();

    for line in content.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(key), Some(val)) = (parts.next(), parts.next()) {
            if let Ok(value) = val.parse::<u64>() {
                match key {
                    "read_bytes:" => io.read_bytes = value,
                    "write_bytes:" => io.write_bytes = value,
                    "syscr:" => io.syscr = value,
                    "syscw:" => io.syscw = value,
                    _ => {}
                }
            }
        }
    }

    Some(io)
}

/// Подсчет открытых файлов/сокетов в директории /proc/[pid]/fd
pub fn count_open_fds(fd_dir: &Path) -> Option<u64> {
    let entries = fs::read_dir(fd_dir).ok()?;
    let count = entries.filter_map(|e| e.ok()).count() as u64;
    Some(count)
}

/// Извлечение названия systemd unit из /proc/[pid]/cgroup
pub fn read_process_systemd_unit(cgroup_path: &Path) -> Option<String> {
    let content = fs::read_to_string(cgroup_path).ok()?;

    for line in content.lines() {
        // Формат cgroup v2: 0::/system.slice/nginx.service
        // Формат cgroup v1: 5:name=systemd:/system.slice/docker.service
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            let path_str = parts[2];
            if let Some(unit) = extract_unit_from_cgroup_path(path_str) {
                return Some(unit);
            }
        }
    }

    None
}

/// Вычленение имени юнита (.service, .socket, .scope) из пути cgroup
pub fn extract_unit_from_cgroup_path(path: &str) -> Option<String> {
    let segments: Vec<&str> = path.split('/').collect();

    for seg in segments.iter().rev() {
        if seg.ends_with(".service") {
            return Some(seg.to_string());
        }
    }

    for seg in segments.iter().rev() {
        if seg.ends_with(".socket") || seg.ends_with(".scope") {
            return Some(seg.to_string());
        }
    }

    for seg in segments.iter().rev() {
        if seg.ends_with(".slice") && !seg.is_empty() {
            return Some(seg.to_string());
        }
    }

    None
}

/// Вырезает имя процесса comm из скобок `(...)`, так как имя может содержать пробелы и скобки
pub fn parse_stat_comm(stat_str: &str) -> Option<(String, &str)> {
    let open_bracket = stat_str.find('(')?;
    let close_bracket = stat_str.rfind(')')?;

    if open_bracket >= close_bracket {
        return None;
    }

    let comm = stat_str[open_bracket + 1..close_bracket].to_string();
    let rest = stat_str[close_bracket + 1..].trim();

    Some((comm, rest))
}

/// Извлечение Real UID из строки Uid:\t1000\t1000...
fn read_proc_uid(path: &Path) -> Option<u32> {
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        if line.starts_with("Uid:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse::<u32>().ok();
            }
        }
    }
    None
}
</file>

<file path="otlp-sys-agent/src/collectors/temperature.rs">
use crate::collector::Collector;
use anyhow::Result;
use async_trait::async_trait;
use opentelemetry::metrics::Meter;
use opentelemetry::KeyValue;
use std::fs;
use std::path::Path;
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct TempReadout {
    pub chip: String,
    pub label: String,
    pub celsius: f64,
}

pub struct SysfsTempCollector {
    hostname: String,
}

impl SysfsTempCollector {

    pub fn new(hostname: String) -> Self {
        Self { hostname }
    }

    pub fn read_temperatures() -> Vec<TempReadout> {
        let mut readouts = Vec::new();
        let hwmon_path = Path::new("/sys/class/hwmon");

        if !hwmon_path.exists() {
            warn!("Директория /sys/class/hwmon не найдена");
            return readouts;
        }

        let entries = match fs::read_dir(hwmon_path) {
            Ok(e) => e,
            Err(err) => {
                warn!("Ошибка чтения /sys/class/hwmon: {}", err);
                return readouts;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let chip_name = fs::read_to_string(path.join("name"))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string());

            if let Ok(sensor_entries) = fs::read_dir(&path) {
                for sensor in sensor_entries.flatten() {
                    let file_name = sensor.file_name();
                    let name_str = file_name.to_string_lossy();

                    if name_str.starts_with("temp") && name_str.ends_with("_input") {
                        let prefix = name_str.trim_end_matches("_input");

                        let label = fs::read_to_string(path.join(format!("{}_label", prefix)))
                            .map(|s| s.trim().to_string())
                            .unwrap_or_else(|_| prefix.to_string());

                        if let Ok(content) = fs::read_to_string(sensor.path()) {
                            if let Ok(milli_celsius) = content.trim().parse::<f64>() {
                                readouts.push(TempReadout {
                                    chip: chip_name.clone(),
                                    label,
                                    celsius: milli_celsius / 1000.0,
                                });
                            }
                        }
                    }
                }
            }
        }

        readouts
    }
}

#[async_trait]
impl Collector for SysfsTempCollector {
    fn name(&self) -> &'static str {
        "temperature"
    }

    async fn collect(&self, meter: &Meter) -> Result<()> {
        // Создаем метрику типа Gauge
        let gauge = meter
            .f64_gauge("system.hardware.temperature.celsius")
            .with_description("Temperature readout from system hardware sensors")
            .with_unit("Cel")
            .build();

        let temps = Self::read_temperatures();
        for temp in temps {
            debug!(
                chip = %temp.chip,
                label = %temp.label,
                celsius = %temp.celsius,
                "Отправка показаний температуры"
            );

            // Фиксируем значение с метками чипа и сенсора
            gauge.record(
                temp.celsius,
                &[
                    KeyValue::new("host_name", self.hostname.clone()),
                    KeyValue::new("chip", temp.chip),
                    KeyValue::new("label", temp.label),
                ],
            );
        }

        Ok(())
    }
}
</file>

<file path="otlp-sys-agent/src/collector.rs">
use anyhow::Result;
use async_trait::async_trait;
use opentelemetry::metrics::Meter;
use tracing::{error, info};

/// Базовый асинхронный трейт для всех сборщиков метрик.
/// Каждый новый источник метрик (температура, iptables) должен имплементировать этот трейт.
#[async_trait]
pub trait Collector: Send + Sync {
    /// Уникальное имя коллектора (используется для логов и фильтрации в конфиге)
    fn name(&self) -> &'static str;

    /// Основной метод сбора метрик и отправки их в OpenTelemetry Meter
    async fn collect(&self, meter: &Meter) -> Result<()>;
}

/// Реестр всех активных коллекторов системы
#[derive(Default)]
pub struct CollectorRegistry {
    collectors: Vec<Box<dyn Collector>>,
}

impl CollectorRegistry {
    pub fn new() -> Self {
        Self {
            collectors: Vec::new(),
        }
    }

    /// Регистрация нового коллектора
    pub fn register<C: Collector + 'static>(&mut self, collector: C) {
        info!("Зарегистрирован коллектор: {}", collector.name());
        self.collectors.push(Box::new(collector));
    }

    /// Последовательный или параллельный запуск сбора со всех зарегистрированных коллекторов
    pub async fn collect_all(&self, meter: &Meter) {
        for collector in &self.collectors {
            if let Err(err) = collector.collect(meter).await {
                error!(
                    collector = collector.name(),
                    error = %err,
                    "Ошибка при сборе метрик"
                );
            }
        }
    }

    /// Количество активных коллекторов
    pub fn len(&self) -> usize {
        self.collectors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.collectors.is_empty()
    }
}
</file>

<file path="otlp-sys-agent/src/lib.rs">
pub mod collector;
pub mod collectors;
pub mod config;
pub mod telemetry;
</file>

<file path="otlp-sys-agent/src/telemetry.rs">
use crate::config::AppConfig;
use anyhow::Result;
use opentelemetry::KeyValue;
use opentelemetry_otlp::{MetricExporter, WithExportConfig};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::Resource;
use std::time::Duration;

pub fn init_meter_provider(config: &AppConfig) -> Result<SdkMeterProvider> {
    let hostname = config.get_hostname();

    // Переключаем экспортер на OTLP over HTTP
    let exporter = MetricExporter::builder()
        .with_http()
        .with_endpoint(&config.otlp.endpoint)
        .with_timeout(Duration::from_secs(config.otlp.timeout_secs))
        .build()?;

    let reader = PeriodicReader::builder(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_interval(Duration::from_secs(config.agent.interval_secs))
        .build();

    let resource = Resource::new(vec![
        KeyValue::new("service.name", "otlp-sys-agent"),
        KeyValue::new("host.name", hostname),
    ]);

    let provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .build();

    Ok(provider)
}
</file>

<file path="otlp-sys-agent/tests/iptables_test.rs">
use otlp_sys_agent::collectors::iptables::parse_iptables_save;
use otlp_sys_agent::config::IptablesCollectorConfig;

fn mock_iptables_output() -> &'static str {
    r#"# Generated by iptables-save v1.8.10
*filter
:INPUT ACCEPT [10500:8450120]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [500:30000]
:DOCKER-USER - [0:0]
:DOCKER-ISOLATION-STAGE-1 - [0:0]
[150:12000] -A INPUT -p tcp -m tcp --dport 22 -m set --match-set crowdsec-blacklists src -m comment --comment "block bad ips" -j DROP
[42:2400] -A DOCKER-USER -m comment --comment "allow web traffic" -j ACCEPT
[10:500] -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
[5:250] -A DOCKER-ISOLATION-STAGE-1 -j DROP
COMMIT
*nat
:PREROUTING ACCEPT [100:5000]
COMMIT
"#
}

#[test]
fn test_parse_chain_totals() {
    let config = IptablesCollectorConfig {
        enabled: true,
        command: "sudo iptables-save -c".to_string(),
        collect_chain_totals: true,
        target_filter: vec![],
        only_with_metadata: false,
        ignore_chains: vec![],
    };

    let dump = parse_iptables_save(mock_iptables_output(), &config);

    assert_eq!(dump.chain_totals.len(), 6);
    assert_eq!(dump.chain_totals[0].chain, "INPUT");
    assert_eq!(dump.chain_totals[0].policy, "ACCEPT");
    assert_eq!(dump.chain_totals[0].packets, 10500);
    assert_eq!(dump.chain_totals[0].bytes, 8450120);
}

#[test]
fn test_parse_rules_with_metadata() {
    let config = IptablesCollectorConfig {
        enabled: true,
        command: "sudo iptables-save -c".to_string(),
        collect_chain_totals: false,
        target_filter: vec![],
        only_with_metadata: false,
        ignore_chains: vec![],
    };

    let dump = parse_iptables_save(mock_iptables_output(), &config);

    assert_eq!(dump.rules.len(), 4);

    let r0 = &dump.rules[0];
    assert_eq!(r0.table, "filter");
    assert_eq!(r0.chain, "INPUT");
    assert_eq!(r0.packets, 150);
    assert_eq!(r0.bytes, 12000);
    assert_eq!(r0.target.as_deref(), Some("DROP"));
    assert_eq!(r0.match_set.as_deref(), Some("crowdsec-blacklists"));
    assert_eq!(r0.match_comment.as_deref(), Some("block bad ips"));
    assert_eq!(r0.proto.as_deref(), Some("tcp"));
    assert_eq!(r0.dport.as_deref(), Some("22"));

    let r1 = &dump.rules[1];
    assert_eq!(r1.chain, "DOCKER-USER");
    assert_eq!(r1.match_comment.as_deref(), Some("allow web traffic"));
}

#[test]
fn test_filtering_options() {
    let config = IptablesCollectorConfig {
        enabled: true,
        command: "sudo iptables-save -c".to_string(),
        collect_chain_totals: true,
        target_filter: vec!["DROP".to_string()],
        only_with_metadata: true,
        ignore_chains: vec!["DOCKER-ISOLATION-STAGE-1".to_string()],
    };

    let dump = parse_iptables_save(mock_iptables_output(), &config);

    assert!(dump
        .chain_totals
        .iter()
        .all(|c| c.chain != "DOCKER-ISOLATION-STAGE-1"));
    assert_eq!(dump.rules.len(), 1);
    assert_eq!(dump.rules[0].chain, "INPUT");
    assert_eq!(dump.rules[0].target.as_deref(), Some("DROP"));
}
</file>

<file path="otlp-sys-agent/tests/procfs_test.rs">
use otlp_sys_agent::collectors::process::procfs::{
    extract_unit_from_cgroup_path, parse_stat_comm, read_process_io,
};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_parse_stat_comm_standard() {
    let raw_stat = "1234 (nginx) S 1 1234 1234 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 4 0 1000 1000000 500";
    let (comm, rest) = parse_stat_comm(raw_stat).expect("Не удалось распарсить stat");
    assert_eq!(comm, "nginx");
    assert!(rest.starts_with("S 1 1234"));
}

#[test]
fn test_parse_stat_comm_with_spaces_and_brackets() {
    // Важно: имя процесса может содержать пробелы и скобки (например: "(sd-pam worker)")
    let raw_stat = "5678 (sd-pam (worker)) S 1 5678 5678 0 -1";
    let (comm, rest) = parse_stat_comm(raw_stat).expect("Не удалось распарсить stat со скобками");
    assert_eq!(comm, "sd-pam (worker)");
    assert_eq!(rest, "S 1 5678 5678 0 -1");
}

#[test]
fn test_extract_unit_from_cgroup_path() {
    // cgroup v2
    assert_eq!(
        extract_unit_from_cgroup_path("/system.slice/nginx.service"),
        Some("nginx.service".to_string())
    );

    // cgroup v1 с вложенным scope
    assert_eq!(
        extract_unit_from_cgroup_path("/system.slice/docker.service/docker-1234.scope"),
        Some("docker.service".to_string())
    );

    // Пользовательские сессии
    assert_eq!(
        extract_unit_from_cgroup_path("/user.slice/user-1000.slice/session-2.scope"),
        Some("session-2.scope".to_string())
    );

    // Пустой/коренной cgroup
    assert_eq!(extract_unit_from_cgroup_path("/"), None);
}

#[test]
fn test_read_process_io_parsing() {
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(
        temp_file,
        "rchar: 1000\nwchar: 2000\nsyscr: 15\nsyscw: 25\nread_bytes: 1048576\nwrite_bytes: 2097152"
    )
    .unwrap();

    let io_info = read_process_io(temp_file.path()).expect("Ошибка чтения файла io");

    assert_eq!(io_info.read_bytes, 1048576);
    assert_eq!(io_info.write_bytes, 2097152);
    assert_eq!(io_info.syscr, 15);
    assert_eq!(io_info.syscw, 25);
}
</file>

<file path="otlp-sys-agent/.env.example">
# Переопределение параметров агента (имеет высший приоритет над config.yaml)
OTLP_AGENT__AGENT__LOG_LEVEL=<type>
OTLP_AGENT__AGENT__HOST_NAME=<hostname>
OTLP_AGENT__OTLP__ENDPOINT=<url>
</file>

<file path="otlp-sys-agent/.gitignore">
# Rust / Cargo build artifacts
/target/
**/target/
Cargo.lock
.env
</file>

<file path=".gitignore">
# Rust / Cargo build artifacts
/target/
**/target/
Cargo.lock

# Taskfile output & Release Archives
/dist/
*.tar.gz
*.zip

# Local environment variables and secrets
.env
!.env.example

# IDEs & Editors
.vscode/
.idea/
*.swp
*.swo
*~
.zed/

# System files
.DS_Store
otlp-sys-agent/.tree.txt
</file>

<file path="GrafanaCPUTempDashBoardExample.json">
{
  "apiVersion": "dashboard.grafana.app/v2",
  "kind": "Dashboard",
  "metadata": {
    "name": "adkqw5l",
    "generation": 7,
    "creationTimestamp": "2026-07-25T09:02:05Z",
    "labels": {},
    "annotations": {}
  },
  "spec": {
    "annotations": [
      {
        "kind": "AnnotationQuery",
        "spec": {
          "query": {
            "kind": "DataQuery",
            "group": "grafana",
            "version": "v0",
            "spec": {},
            "labels": {
              "grafana.app/export-label": "grafana-1"
            }
          },
          "enable": true,
          "hide": true,
          "iconColor": "rgba(0, 211, 255, 1)",
          "name": "Annotations & Alerts",
          "builtIn": true
        }
      }
    ],
    "cursorSync": "Off",
    "editable": true,
    "elements": {
      "panel-1": {
        "kind": "Panel",
        "spec": {
          "id": 1,
          "title": "Максимальная температура CPU (Package):",
          "description": "",
          "links": [],
          "data": {
            "kind": "QueryGroup",
            "spec": {
              "queries": [
                {
                  "kind": "PanelQuery",
                  "spec": {
                    "query": {
                      "kind": "DataQuery",
                      "group": "prometheus",
                      "version": "v0",
                      "spec": {
                        "editorMode": "code",
                        "expr": "system_hardware_temperature_celsius{chip=\"coretemp\", label=\"Package id 0\"}",
                        "legendFormat": "Temp",
                        "range": true
                      },
                      "labels": {
                        "grafana.app/export-label": "prometheus-1",
                        "grafana.app/export-datasource-name": "prometheus"
                      }
                    },
                    "refId": "A",
                    "hidden": false
                  }
                }
              ],
              "transformations": [],
              "queryOptions": {}
            }
          },
          "vizConfig": {
            "kind": "VizConfig",
            "group": "timeseries",
            "version": "13.1.0",
            "spec": {
              "options": {
                "annotations": {
                  "clustering": -1,
                  "multiLane": false
                },
                "legend": {
                  "calcs": [],
                  "displayMode": "list",
                  "enableFacetedFilter": false,
                  "overflow": "ellipsis",
                  "placement": "bottom",
                  "showLegend": true
                },
                "tooltip": {
                  "hideZeros": false,
                  "mode": "single",
                  "sort": "none"
                }
              },
              "fieldConfig": {
                "defaults": {
                  "thresholds": {
                    "mode": "absolute",
                    "steps": [
                      {
                        "value": 0,
                        "color": "green"
                      },
                      {
                        "value": 80,
                        "color": "red"
                      }
                    ]
                  },
                  "color": {
                    "mode": "palette-classic"
                  },
                  "custom": {
                    "axisBorderShow": false,
                    "axisCenteredZero": false,
                    "axisColorMode": "text",
                    "axisLabel": "",
                    "axisPlacement": "auto",
                    "barAlignment": 0,
                    "barWidthFactor": 0.6,
                    "drawStyle": "line",
                    "fillOpacity": 0,
                    "gradientMode": "none",
                    "hideFrom": {
                      "legend": false,
                      "tooltip": false,
                      "viz": false
                    },
                    "insertNulls": false,
                    "lineInterpolation": "linear",
                    "lineWidth": 1,
                    "pointSize": 5,
                    "scaleDistribution": {
                      "type": "linear"
                    },
                    "showPoints": "auto",
                    "showValues": false,
                    "spanNulls": false,
                    "stacking": {
                      "group": "A",
                      "mode": "none"
                    },
                    "thresholdsStyle": {
                      "mode": "off"
                    }
                  }
                },
                "overrides": []
              }
            }
          }
        }
      },
      "panel-2": {
        "kind": "Panel",
        "spec": {
          "id": 2,
          "title": "Средняя температура по всем ядрам:",
          "description": "",
          "links": [],
          "data": {
            "kind": "QueryGroup",
            "spec": {
              "queries": [
                {
                  "kind": "PanelQuery",
                  "spec": {
                    "query": {
                      "kind": "DataQuery",
                      "group": "prometheus",
                      "version": "v0",
                      "spec": {
                        "editorMode": "code",
                        "expr": "avg(system_hardware_temperature_celsius{chip=\"coretemp\", label=~\"Core.*\"})",
                        "legendFormat": "Temp",
                        "range": true
                      },
                      "labels": {
                        "grafana.app/export-label": "prometheus-1",
                        "grafana.app/export-datasource-name": "prometheus"
                      }
                    },
                    "refId": "A",
                    "hidden": false
                  }
                }
              ],
              "transformations": [],
              "queryOptions": {}
            }
          },
          "vizConfig": {
            "kind": "VizConfig",
            "group": "timeseries",
            "version": "13.1.0",
            "spec": {
              "options": {
                "annotations": {
                  "clustering": -1,
                  "multiLane": false
                },
                "legend": {
                  "calcs": [],
                  "displayMode": "list",
                  "enableFacetedFilter": false,
                  "overflow": "ellipsis",
                  "placement": "bottom",
                  "showLegend": true
                },
                "tooltip": {
                  "hideZeros": false,
                  "mode": "single",
                  "sort": "none"
                }
              },
              "fieldConfig": {
                "defaults": {
                  "thresholds": {
                    "mode": "absolute",
                    "steps": [
                      {
                        "value": 0,
                        "color": "green"
                      },
                      {
                        "value": 80,
                        "color": "red"
                      }
                    ]
                  },
                  "color": {
                    "mode": "palette-classic"
                  },
                  "custom": {
                    "axisBorderShow": false,
                    "axisCenteredZero": false,
                    "axisColorMode": "text",
                    "axisLabel": "",
                    "axisPlacement": "auto",
                    "barAlignment": 0,
                    "barWidthFactor": 0.6,
                    "drawStyle": "line",
                    "fillOpacity": 0,
                    "gradientMode": "none",
                    "hideFrom": {
                      "legend": false,
                      "tooltip": false,
                      "viz": false
                    },
                    "insertNulls": false,
                    "lineInterpolation": "linear",
                    "lineWidth": 1,
                    "pointSize": 5,
                    "scaleDistribution": {
                      "type": "linear"
                    },
                    "showPoints": "auto",
                    "showValues": false,
                    "spanNulls": false,
                    "stacking": {
                      "group": "A",
                      "mode": "none"
                    },
                    "thresholdsStyle": {
                      "mode": "off"
                    }
                  }
                },
                "overrides": []
              }
            }
          }
        }
      },
      "panel-3": {
        "kind": "Panel",
        "spec": {
          "id": 3,
          "title": "Максимальная температура среди вообще всех датчиков системы:",
          "description": "",
          "links": [],
          "data": {
            "kind": "QueryGroup",
            "spec": {
              "queries": [
                {
                  "kind": "PanelQuery",
                  "spec": {
                    "query": {
                      "kind": "DataQuery",
                      "group": "prometheus",
                      "version": "v0",
                      "spec": {
                        "editorMode": "code",
                        "expr": "max(system_hardware_temperature_celsius{job=\"otlp-sys-agent\"})",
                        "legendFormat": "Temp",
                        "range": true
                      },
                      "labels": {
                        "grafana.app/export-label": "prometheus-1",
                        "grafana.app/export-datasource-name": "prometheus"
                      }
                    },
                    "refId": "A",
                    "hidden": false
                  }
                }
              ],
              "transformations": [],
              "queryOptions": {}
            }
          },
          "vizConfig": {
            "kind": "VizConfig",
            "group": "timeseries",
            "version": "13.1.0",
            "spec": {
              "options": {
                "annotations": {
                  "clustering": -1,
                  "multiLane": false
                },
                "legend": {
                  "calcs": [],
                  "displayMode": "list",
                  "enableFacetedFilter": false,
                  "overflow": "ellipsis",
                  "placement": "bottom",
                  "showLegend": true
                },
                "tooltip": {
                  "hideZeros": false,
                  "mode": "single",
                  "sort": "none"
                }
              },
              "fieldConfig": {
                "defaults": {
                  "thresholds": {
                    "mode": "absolute",
                    "steps": [
                      {
                        "value": 0,
                        "color": "green"
                      },
                      {
                        "value": 80,
                        "color": "red"
                      }
                    ]
                  },
                  "color": {
                    "mode": "palette-classic"
                  },
                  "custom": {
                    "axisBorderShow": false,
                    "axisCenteredZero": false,
                    "axisColorMode": "text",
                    "axisLabel": "",
                    "axisPlacement": "auto",
                    "barAlignment": 0,
                    "barWidthFactor": 0.6,
                    "drawStyle": "line",
                    "fillOpacity": 0,
                    "gradientMode": "none",
                    "hideFrom": {
                      "legend": false,
                      "tooltip": false,
                      "viz": false
                    },
                    "insertNulls": false,
                    "lineInterpolation": "linear",
                    "lineWidth": 1,
                    "pointSize": 5,
                    "scaleDistribution": {
                      "type": "linear"
                    },
                    "showPoints": "auto",
                    "showValues": false,
                    "spanNulls": false,
                    "stacking": {
                      "group": "A",
                      "mode": "none"
                    },
                    "thresholdsStyle": {
                      "mode": "off"
                    }
                  }
                },
                "overrides": []
              }
            }
          }
        }
      }
    },
    "layout": {
      "kind": "GridLayout",
      "spec": {
        "items": [
          {
            "kind": "GridLayoutItem",
            "spec": {
              "x": 0,
              "y": 0,
              "width": 7,
              "height": 8,
              "element": {
                "kind": "ElementReference",
                "name": "panel-1"
              }
            }
          },
          {
            "kind": "GridLayoutItem",
            "spec": {
              "x": 7,
              "y": 0,
              "width": 7,
              "height": 8,
              "element": {
                "kind": "ElementReference",
                "name": "panel-2"
              }
            }
          },
          {
            "kind": "GridLayoutItem",
            "spec": {
              "x": 14,
              "y": 0,
              "width": 7,
              "height": 8,
              "element": {
                "kind": "ElementReference",
                "name": "panel-3"
              }
            }
          }
        ]
      }
    },
    "links": [],
    "liveNow": false,
    "preload": false,
    "tags": [],
    "timeSettings": {
      "timezone": "browser",
      "from": "now-6h",
      "to": "now",
      "autoRefresh": "1m",
      "autoRefreshIntervals": [
        "5s",
        "10s",
        "30s",
        "1m",
        "5m",
        "15m",
        "30m",
        "1h",
        "2h",
        "1d"
      ],
      "hideTimepicker": false,
      "fiscalYearStartMonth": 0
    },
    "title": "Pastop_PC",
    "variables": [],
    "preferences": {
      "layout": {
        "kind": "GridLayout",
        "spec": {
          "items": []
        }
      }
    }
  }
}
</file>

<file path="GrafanaIPTablesDashBoardExample.json">
{
  "apiVersion": "dashboard.grafana.app/v2",
  "kind": "Dashboard",
  "metadata": {
    "name": "354wq34yeqrt",
    "generation": 2,
    "creationTimestamp": "2026-07-25T11:52:42Z",
    "labels": {},
    "annotations": {}
  },
  "spec": {
    "annotations": [
      {
        "kind": "AnnotationQuery",
        "spec": {
          "query": {
            "kind": "DataQuery",
            "group": "grafana",
            "version": "v0",
            "spec": {},
            "labels": {
              "grafana.app/export-label": "grafana-1"
            }
          },
          "enable": true,
          "hide": true,
          "iconColor": "rgba(0, 211, 255, 1)",
          "name": "Annotations & Alerts",
          "builtIn": true
        }
      }
    ],
    "cursorSync": "Off",
    "editable": true,
    "elements": {
      "panel-1": {
        "kind": "Panel",
        "spec": {
          "id": 1,
          "title": "Правила IPTables",
          "description": "",
          "links": [],
          "data": {
            "kind": "QueryGroup",
            "spec": {
              "queries": [
                {
                  "kind": "PanelQuery",
                  "spec": {
                    "query": {
                      "kind": "DataQuery",
                      "group": "prometheus",
                      "version": "v0",
                      "spec": {
                        "editorMode": "code",
                        "expr": "system_iptables_rule_bytes_total or system_iptables_rule_bytes {job=\"otlp-sys-agent\",host_name=\"${host_name}\"}",
                        "format": "table",
                        "instant": true,
                        "legendFormat": "Bytes"
                      },
                      "labels": {
                        "grafana.app/export-label": "prometheus-1",
                        "grafana.app/export-datasource-name": "prometheus"
                      }
                    },
                    "refId": "A",
                    "hidden": false
                  }
                },
                {
                  "kind": "PanelQuery",
                  "spec": {
                    "query": {
                      "kind": "DataQuery",
                      "group": "prometheus",
                      "version": "v0",
                      "spec": {
                        "editorMode": "code",
                        "expr": "system_iptables_rule_packets_total or system_iptables_rule_packets {job=\"otlp-sys-agent\",host_name=\"${host_name}\"}",
                        "format": "table",
                        "instant": true,
                        "legendFormat": "Packets"
                      },
                      "labels": {
                        "grafana.app/export-label": "prometheus-1",
                        "grafana.app/export-datasource-name": "prometheus"
                      }
                    },
                    "refId": "B",
                    "hidden": false
                  }
                }
              ],
              "transformations": [
                {
                  "kind": "Transformation",
                  "group": "seriesToRows",
                  "spec": {
                    "options": {}
                  }
                },
                {
                  "kind": "Transformation",
                  "group": "organize",
                  "spec": {
                    "options": {
                      "excludeByName": {
                        "Time": true,
                        "__name__": true,
                        "instance": true,
                        "job": true
                      },
                      "indexByName": {
                        "Value #A": 9,
                        "Value #B": 8,
                        "chain": 2,
                        "comment": 7,
                        "dport": 5,
                        "host_name": 0,
                        "match_set": 6,
                        "proto": 4,
                        "table": 1,
                        "target": 3
                      },
                      "renameByName": {
                        "Value #A": "Bytes Total",
                        "Value #B": "Packets Total",
                        "chain": "Chain",
                        "comment": "Comment",
                        "dport": "Port",
                        "host_name": "Host",
                        "match_set": "IPSet",
                        "proto": "Proto",
                        "table": "Table",
                        "target": "Target"
                      }
                    }
                  }
                }
              ],
              "queryOptions": {}
            }
          },
          "vizConfig": {
            "kind": "VizConfig",
            "group": "table",
            "version": "13.1.0",
            "spec": {
              "options": {
                "cellHeight": "sm",
                "showHeader": true
              },
              "fieldConfig": {
                "defaults": {
                  "thresholds": {
                    "mode": "absolute",
                    "steps": [
                      {
                        "value": 0,
                        "color": "green"
                      },
                      {
                        "value": 80,
                        "color": "red"
                      }
                    ]
                  },
                  "custom": {
                    "align": "auto",
                    "cellOptions": {
                      "type": "auto"
                    },
                    "footer": {
                      "reducers": []
                    },
                    "inspect": false
                  }
                },
                "overrides": [
                  {
                    "matcher": {
                      "id": "byName",
                      "options": "Bytes Total"
                    },
                    "properties": [
                      {
                        "id": "unit",
                        "value": "decbytes"
                      }
                    ]
                  },
                  {
                    "matcher": {
                      "id": "byName",
                      "options": "Packets Total"
                    },
                    "properties": [
                      {
                        "id": "unit",
                        "value": "short"
                      }
                    ]
                  },
                  {
                    "matcher": {
                      "id": "byName",
                      "options": "Target"
                    },
                    "properties": [
                      {
                        "id": "custom.cellOptions",
                        "value": {
                          "type": "color-background"
                        }
                      },
                      {
                        "id": "mappings",
                        "value": [
                          {
                            "options": {
                              "ACCEPT": {
                                "color": "green",
                                "text": "ACCEPT"
                              },
                              "DROP": {
                                "color": "red",
                                "text": "DROP"
                              },
                              "REJECT": {
                                "color": "orange",
                                "text": "REJECT"
                              }
                            },
                            "type": "value"
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            }
          }
        }
      }
    },
    "layout": {
      "kind": "GridLayout",
      "spec": {
        "items": [
          {
            "kind": "GridLayoutItem",
            "spec": {
              "x": 0,
              "y": 0,
              "width": 24,
              "height": 16,
              "element": {
                "kind": "ElementReference",
                "name": "panel-1"
              }
            }
          }
        ]
      }
    },
    "links": [],
    "liveNow": false,
    "preload": false,
    "tags": [
      "iptables",
      "otlp-sys-agent"
    ],
    "timeSettings": {
      "timezone": "browser",
      "from": "now-6h",
      "to": "now",
      "autoRefresh": "",
      "autoRefreshIntervals": [
        "5s",
        "10s",
        "30s",
        "1m",
        "5m",
        "15m",
        "30m",
        "1h",
        "2h",
        "1d"
      ],
      "hideTimepicker": false,
      "fiscalYearStartMonth": 0
    },
    "title": "IPTables Metrics (OTLP Sys Agent)",
    "variables": []
  }
}
</file>

<file path="otlp-sys-agent/src/collectors/process/collector.rs">
use crate::collector::Collector;
use crate::collectors::process::procfs::ProcFsReader;
use anyhow::Result;
use async_trait::async_trait;
use opentelemetry::metrics::Meter;
use opentelemetry::KeyValue;
use std::collections::HashMap;
use std::sync::Mutex;

/// Структурное хранение предыдущего состояния накопительных счётчиков процесса
#[derive(Default, Clone, Copy)]
struct ProcessLastState {
    utime_ticks: u64,
    stime_ticks: u64,
    read_bytes: u64,
    write_bytes: u64,
    syscr: u64,
    syscw: u64,
}

pub struct ProcessCollector {
    reader: ProcFsReader,
    hostname: String,
    // Хранение истории между итерациями сбора (PID -> State)
    last_state: Mutex<HashMap<u32, ProcessLastState>>,
}

impl ProcessCollector {
    pub fn new(hostname: String) -> Self {
        Self {
            reader: ProcFsReader::new(),
            hostname,
            last_state: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl Collector for ProcessCollector {
    fn name(&self) -> &'static str {
        "process"
    }

    async fn collect(&self, meter: &Meter) -> Result<()> {
        let processes = self.reader.collect_processes();

        // 1. Инициализация инструментов метрик OpenTelemetry
        let rss_gauge = meter
            .u64_gauge("process.memory.rss")
            .with_description("Process resident memory size in bytes")
            .with_unit("By")
            .build();

        let vsize_gauge = meter
            .u64_gauge("process.memory.vsize")
            .with_description("Process virtual memory size in bytes")
            .with_unit("By")
            .build();

        let user_cpu_counter = meter
            .u64_counter("process.cpu.ticks.user")
            .with_description("User CPU time in ticks")
            .build();

        let sys_cpu_counter = meter
            .u64_counter("process.cpu.ticks.system")
            .with_description("System CPU time in ticks")
            .build();

        let threads_gauge = meter
            .u64_gauge("process.threads")
            .with_description("Number of threads")
            .build();

        let fds_gauge = meter
            .u64_gauge("process.open_file_descriptors")
            .with_description("Number of open file descriptors")
            .build();

        let io_read_counter = meter
            .u64_counter("process.disk.io.read_bytes")
            .with_description("Bytes read from disk")
            .with_unit("By")
            .build();

        let io_write_counter = meter
            .u64_counter("process.disk.io.write_bytes")
            .with_description("Bytes written to disk")
            .with_unit("By")
            .build();

        let io_syscr_counter = meter
            .u64_counter("process.disk.io.syscr")
            .with_description("Read syscall count")
            .build();

        let io_syscw_counter = meter
            .u64_counter("process.disk.io.syscw")
            .with_description("Write syscall count")
            .build();

        // Получаем блокировку предыдущего состояния
        let mut prev_state_map = self.last_state.lock().unwrap();
        let mut next_state_map = HashMap::new();

        // 2. Обход процессов и запись значений
        for proc in processes {
            let mut attrs = vec![
                KeyValue::new("host_name", self.hostname.clone()),
                KeyValue::new("process.pid", proc.pid as i64),
                KeyValue::new("process.executable.name", proc.comm),
                KeyValue::new("process.command_line", proc.cmdline),
                KeyValue::new("user.name", proc.username),
                KeyValue::new("process.state", proc.state),
            ];

            if let Some(unit) = proc.systemd_unit {
                attrs.push(KeyValue::new("systemd.unit", unit));
            }

            // Получаем прошлые данные по этому PID (если процесс уже отслеживался)
            let prev = prev_state_map.get(&proc.pid).copied().unwrap_or_default();
            let has_prev = prev_state_map.contains_key(&proc.pid);

            // Считаем дельту для CPU (saturating_sub защищает от переполнений при сбросе)
            let delta_utime = if has_prev { proc.utime_ticks.saturating_sub(prev.utime_ticks) } else { 0 };
            let delta_stime = if has_prev { proc.stime_ticks.saturating_sub(prev.stime_ticks) } else { 0 };

            // Запись мгновенных метрик (Gauges)
            rss_gauge.record(proc.rss_bytes, &attrs);
            vsize_gauge.record(proc.vsize_bytes, &attrs);
            threads_gauge.record(proc.num_threads, &attrs);

            // Запись счетчиков CPU (передаем только прирост delta)
            user_cpu_counter.add(delta_utime, &attrs);
            sys_cpu_counter.add(delta_stime, &attrs);

            if let Some(fds) = proc.open_fds {
                fds_gauge.record(fds, &attrs);
            }

            // Обработка I/O метрик (тоже считаются через дельту)
            let mut current_io = (0, 0, 0, 0);
            if let Some(io) = proc.io {
                current_io = (io.read_bytes, io.write_bytes, io.syscr, io.syscw);

                let delta_read = if has_prev { io.read_bytes.saturating_sub(prev.read_bytes) } else { 0 };
                let delta_write = if has_prev { io.write_bytes.saturating_sub(prev.write_bytes) } else { 0 };
                let delta_syscr = if has_prev { io.syscr.saturating_sub(prev.syscr) } else { 0 };
                let delta_syscw = if has_prev { io.syscw.saturating_sub(prev.syscw) } else { 0 };

                io_read_counter.add(delta_read, &attrs);
                io_write_counter.add(delta_write, &attrs);
                io_syscr_counter.add(delta_syscr, &attrs);
                io_syscw_counter.add(delta_syscw, &attrs);
            }

            // Сохраняем текущие показания для следующего шага
            next_state_map.insert(
                proc.pid,
                ProcessLastState {
                    utime_ticks: proc.utime_ticks,
                    stime_ticks: proc.stime_ticks,
                    read_bytes: current_io.0,
                    write_bytes: current_io.1,
                    syscr: current_io.2,
                    syscw: current_io.3,
                },
            );
        }

        // Обновляем состояние (завершённые PID автоматически удаляются)
        *prev_state_map = next_state_map;

        Ok(())
    }
}
</file>

<file path="otlp-sys-agent/src/collectors/iptables.rs">
use anyhow::{Context, Result};
use async_trait::async_trait;
use opentelemetry::metrics::Meter;
use opentelemetry::KeyValue;
use std::process::Stdio;
use tokio::process::Command;

use crate::collector::Collector;
use crate::config::IptablesCollectorConfig;

/// Структура итоговой статистики цепочки
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ChainTotal {
    pub table: String,
    pub chain: String,
    pub policy: String,
    pub packets: u64,
    pub bytes: u64,
}

/// Структура распарсенного правила
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct ParsedRule {
    pub table: String,
    pub chain: String,
    pub packets: u64,
    pub bytes: u64,
    pub target: Option<String>,
    pub match_set: Option<String>,
    pub match_comment: Option<String>,
    pub proto: Option<String>,
    pub dport: Option<String>,
    pub src: Option<String>,
    pub dst: Option<String>,
}

#[derive(Debug, Default)]
pub struct IptablesDump {
    pub chain_totals: Vec<ChainTotal>,
    pub rules: Vec<ParsedRule>,
}

/// Асинхронно вызывает команду iptables-save и парсит её вывод
pub async fn collect_iptables_data(config: &IptablesCollectorConfig) -> Result<IptablesDump> {
    let raw_output = execute_iptables_command(&config.command).await?;
    Ok(parse_iptables_save(&raw_output, config))
}

/// Выполнение команды (например: `sudo iptables-save -c`)
async fn execute_iptables_command(cmd_str: &str) -> Result<String> {
    let parts: Vec<&str> = cmd_str.split_whitespace().collect();
    if parts.is_empty() {
        anyhow::bail!("Команда iptables_save не может быть пустой");
    }

    let program = parts[0];
    let args = &parts[1..];

    let output = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| format!("Не удалось выполнить команду: {}", cmd_str))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Команда '{}' завершилась с ошибкой: {}", cmd_str, stderr);
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Чистая функция парсинга вывода `iptables-save -c`
pub fn parse_iptables_save(input: &str, config: &IptablesCollectorConfig) -> IptablesDump {
    let mut dump = IptablesDump::default();
    let mut current_table = "filter".to_string();

    for line in input.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // 1. Определение текущей таблицы (*filter, *nat, *raw, etc.)
        if let Some(table_name) = line.strip_prefix('*') {
            current_table = table_name.trim().to_string();
            continue;
        }

        // 2. Парсинг итоговых счетчиков цепочки (:INPUT ACCEPT [123:456])
        if line.starts_with(':') && config.collect_chain_totals {
            if let Some(total) = parse_chain_total(line, &current_table) {
                if !config.ignore_chains.contains(&total.chain) {
                    dump.chain_totals.push(total);
                }
            }
            continue;
        }

        // 3. Парсинг правил ([150:12000] -A INPUT ...)
        if line.starts_with('[') {
            if let Some(rule) = parse_rule_line(line, &current_table) {
                // Фильтрация по цепочкам
                if config.ignore_chains.contains(&rule.chain) {
                    continue;
                }

                // Фильтрация по таргету (если задан target_filter)
                if !config.target_filter.is_empty() {
                    if let Some(ref t) = rule.target {
                        if !config.target_filter.contains(t) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }

                // Режим only_with_metadata
                if config.only_with_metadata
                    && rule.match_set.is_none()
                    && rule.match_comment.is_none()
                {
                    continue;
                }

                dump.rules.push(rule);
            }
        }
    }

    dump
}

/// Парсинг строки итогов цепочки: `:INPUT ACCEPT [100:2000]`
fn parse_chain_total(line: &str, table: &str) -> Option<ChainTotal> {
    let line = line.strip_prefix(':')?;
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let chain = parts[0].to_string();
    let policy = parts[1].to_string();
    let counters_str = parts[2];

    let (packets, bytes) = parse_counters(counters_str)?;

    Some(ChainTotal {
        table: table.to_string(),
        chain,
        policy,
        packets,
        bytes,
    })
}

/// Парсинг строки правила: `[150:12000] -A INPUT -p tcp -m set --match-set crowdsec-blacklists src -j DROP`
fn parse_rule_line(line: &str, table: &str) -> Option<ParsedRule> {
    let mut rule = ParsedRule {
        table: table.to_string(),
        ..Default::default()
    };

    let mut tokens = tokenize(line);
    if tokens.is_empty() {
        return None;
    }

    let counters_str = tokens.remove(0);
    let (packets, bytes) = parse_counters(&counters_str)?;
    rule.packets = packets;
    rule.bytes = bytes;

    let mut i = 0;
    while i < tokens.len() {
        match tokens[i].as_str() {
            "-A" | "--append" => {
                if i + 1 < tokens.len() {
                    rule.chain = tokens[i + 1].clone();
                    i += 1;
                }
            }
            "-j" | "--jump" => {
                if i + 1 < tokens.len() {
                    rule.target = Some(tokens[i + 1].clone());
                    i += 1;
                }
            }
            "--match-set" => {
                if i + 1 < tokens.len() {
                    rule.match_set = Some(tokens[i + 1].clone());
                    i += 1;
                }
            }
            "--comment" => {
                if i + 1 < tokens.len() {
                    rule.match_comment = Some(tokens[i + 1].clone());
                    i += 1;
                }
            }
            "-p" | "--protocol" => {
                if i + 1 < tokens.len() {
                    rule.proto = Some(tokens[i + 1].clone());
                    i += 1;
                }
            }
            "--dport" | "--destination-port" => {
                if i + 1 < tokens.len() {
                    rule.dport = Some(tokens[i + 1].clone());
                    i += 1;
                }
            }
            "-s" | "--source" => {
                if i + 1 < tokens.len() {
                    rule.src = Some(tokens[i + 1].clone());
                    i += 1;
                }
            }
            "-d" | "--destination" => {
                if i + 1 < tokens.len() {
                    rule.dst = Some(tokens[i + 1].clone());
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    if rule.chain.is_empty() {
        return None;
    }

    Some(rule)
}

/// Извлечение числа пакетов и байт из скобок `[123:4567]`
fn parse_counters(s: &str) -> Option<(u64, u64)> {
    let s = s.strip_prefix('[')?.strip_suffix(']')?;
    let mut parts = s.split(':');
    let pkts = parts.next()?.parse::<u64>().ok()?;
    let bytes = parts.next()?.parse::<u64>().ok()?;
    Some((pkts, bytes))
}

/// Простой токенизатор, учитывающий кавычки для `--comment "some text"`
fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in line.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
            }
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(ch);
            }
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

// ========================
// COLLECTOR IMPLEMENTATION
// ========================

pub struct IptablesCollector {
    config: IptablesCollectorConfig,
    hostname: String,
}

impl IptablesCollector {
    pub fn new(config: IptablesCollectorConfig, hostname: String) -> Self {
        Self { config, hostname }
    }
}

#[async_trait]
impl Collector for IptablesCollector {
    fn name(&self) -> &'static str {
        "iptables"
    }

    async fn collect(&self, meter: &Meter) -> Result<()> {
        let dump = collect_iptables_data(&self.config).await?;

        let chain_packets = meter
            .u64_counter("system.iptables.chain.packets")
            .with_description("Total packets evaluated by iptables chain policy")
            .build();

        let chain_bytes = meter
            .u64_counter("system.iptables.chain.bytes")
            .with_description("Total bytes evaluated by iptables chain policy")
            .build();

        let rule_packets = meter
            .u64_counter("system.iptables.rule.packets")
            .with_description("Total packets matched by specific iptables rule")
            .build();

        let rule_bytes = meter
            .u64_counter("system.iptables.rule.bytes")
            .with_description("Total bytes matched by specific iptables rule")
            .build();

        // 1. Экспорт итоговых счетчиков цепочек
        for chain in dump.chain_totals {
            let attrs = [
                KeyValue::new("host_name", self.hostname.clone()),
                KeyValue::new("table", chain.table),
                KeyValue::new("chain", chain.chain),
                KeyValue::new("policy", chain.policy),
            ];
            chain_packets.add(chain.packets, &attrs);
            chain_bytes.add(chain.bytes, &attrs);
        }

        // 2. Экспорт счетчиков отдельных правил
        for rule in dump.rules {
            let mut attrs = vec![
                KeyValue::new("host_name", self.hostname.clone()),
                KeyValue::new("table", rule.table),
                KeyValue::new("chain", rule.chain),
            ];

            if let Some(target) = rule.target {
                attrs.push(KeyValue::new("target", target));
            }
            if let Some(set) = rule.match_set {
                attrs.push(KeyValue::new("match_set", set));
            }
            if let Some(comment) = rule.match_comment {
                attrs.push(KeyValue::new("comment", comment));
            }
            if let Some(proto) = rule.proto {
                attrs.push(KeyValue::new("proto", proto));
            }
            if let Some(dport) = rule.dport {
                attrs.push(KeyValue::new("dport", dport));
            }
            if let Some(src) = rule.src {
                attrs.push(KeyValue::new("src", src));
            }
            if let Some(dst) = rule.dst {
                attrs.push(KeyValue::new("dst", dst));
            }

            rule_packets.add(rule.packets, &attrs);
            rule_bytes.add(rule.bytes, &attrs);
        }

        Ok(())
    }
}
</file>

<file path="otlp-sys-agent/src/collectors/mod.rs">
pub mod iptables;
pub mod temperature;
pub mod process;
pub mod filesystem;
</file>

<file path="otlp-sys-agent/src/config.rs">
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
</file>

<file path="otlp-sys-agent/src/main.rs">
use anyhow::Result;
use opentelemetry::metrics::MeterProvider;
use otlp_sys_agent::collector::CollectorRegistry;
use otlp_sys_agent::collectors::iptables::IptablesCollector;
use otlp_sys_agent::collectors::process::ProcessCollector;
use otlp_sys_agent::collectors::temperature::SysfsTempCollector;
use otlp_sys_agent::config::AppConfig;
use otlp_sys_agent::telemetry;
use std::time::Duration;
use tokio::signal;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Загрузка конфигурации
    let cfg = AppConfig::load()?;

    // 2. Инициализация логирования
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&cfg.agent.log_level)),
        )
        .init();

    info!(
        hostname = %cfg.get_hostname(),
        endpoint = %cfg.otlp.endpoint,
        interval = cfg.agent.interval_secs,
        "Запуск OTLP System Agent"
    );

    // 3. Инициализация OpenTelemetry
    let meter_provider = telemetry::init_meter_provider(&cfg)?;
    let meter = meter_provider.meter("otlp-sys-agent");

    // 4. Регистрация активных коллекторов
    let hostname = cfg.get_hostname();
    let mut registry = CollectorRegistry::new();

    if cfg.collectors.temperature.enabled {
        registry.register(SysfsTempCollector::new(hostname.clone()));
    }

    // Регистрация iptables коллектора
    if cfg.collectors.iptables.enabled {
        registry.register(IptablesCollector::new(
            cfg.collectors.iptables.clone(),
            hostname.clone(),
        ));
    }

    // Регистрация process коллектора
    if cfg.collectors.process.enabled {
        registry.register(ProcessCollector::new(hostname.clone()));
    }

    if registry.is_empty() {
        warn!("Нет активных коллекторов в конфигурации! Завершение работы.");
        return Ok(());
    }

    // 5. Главный асинхронный цикл сбора
    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.agent.interval_secs));

    info!("Агент успешно запущен. Для остановки нажмите Ctrl+C.");

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                registry.collect_all(&meter).await;
            }
            _ = shutdown_signal() => {
                info!("Получен сигнал остановки. Сброс метрик и выключение...");
                break;
            }
        }
    }

    // 6. Graceful shutdown: принудительный флаш (flush) невыгруженных метрик
    if let Err(e) = meter_provider.shutdown() {
        tracing::error!(error = %e, "Ошибка при закрытии OTLP MeterProvider");
    } else {
        info!("OpenTelemetry MeterProvider корректно завершил работу.");
    }

    info!("Агент остановлен.");
    Ok(())
}

/// Асинхронный перехват сигналов SIGINT (Ctrl+C) и SIGTERM (systemctl stop)
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Не удалось установить обработчик Ctrl+C");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Не удалось установить обработчик SIGTERM")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
</file>

<file path="otlp-sys-agent/config.yaml">
agent:
  interval_secs: 10
  log_level: "info"
  host_name: "<hostname>"

otlp:
  endpoint: "<url>"
  timeout_secs: 5

collectors:
  temperature:
    enabled: true
  iptables:
    enabled: true
    command: "iptables-save -c"
    # 1. Собирать ли итоговую статистику по цепочкам (policy counters)
    collect_chain_totals: true

    # 2. Фильтрация правил (все поля опциональны, по умолчанию собирается ВСЁ)
    # Если оставить пустым [], будут собираться вообще все действия (ACCEPT, DROP, REJECT и т.д.)
    target_filter: [] # Пример: ["DROP", "REJECT"] — если нужны только блокировки

    # Жёсткий режим: собирать только с комментариями/сетами (по умолчанию false!)
    only_with_metadata: false

    # Игнорировать служебные цепочки Docker, если они создают слишком много шума
    ignore_chains: ["DOCKER-ISOLATION-STAGE-1", "DOCKER-ISOLATION-STAGE-2"]
  process:
    enabled: true
    # 1. Фильтры процессов (если include_processes пуст — собираются все)
    include_processes: []
    exclude_processes: ["kworker/*"]

    # 2. Фильтр по systemd units (если пуст — определяются автоматически для всех процессов)
    track_systemd_units: []

    # 3. Дополнительные метрики
    collect_io: true
    collect_fds: true

    # 4. Пороги отсечения "шумных" мелких процессов
    min_cpu_percent: 0.0
    min_memory_mb: 0
</file>

<file path="README.md">
# OTLP System Agent

Легковесный агент на Rust для сбора системных метрик (`iptables`, `hwmon temperature`) и их отправки по протоколу OTLP (OpenTelemetry) в Prometheus / VictoriaMetrics / OpenTelemetry Collector.

---

## Быстрый старт на сервере (Prod)

Для установки на целевой сервер **не требуется** компилятор Rust, `git` или исходный код. Нужны только готовность принять OTLP-метрики на вашем коллекторе и права `root` для установки службы.

### Пошаговый цикл установки:

#### 1. Скачивание релизного архива
Скачайте актуальную версию архива со страницы **Releases** :

```bash
wget https://github.com/pastop/otlp-sys-agent/releases/download/0.1.1/otlp-sys-agent-release.tar.gz
```
(Или используйте curl -O ...)

2. Распаковка архива
Распакуйте архив во временную директорию и перейдите в неё:

```Bash
mkdir -p /tmp/agent-install && tar -xvf otlp-sys-agent-release.tar.gz -C /tmp/agent-install
cd /tmp/agent-install
```
3. Запуск автоматической установки
Выполните инсталляционный скрипт с правами root:

```Bash
sudo ./install.sh
```
Что делает `install.sh` под капотом:

Автоматически определяет архитектуру процессора (x86_64 или aarch64) и выбирает нужный статический бинарник.

Создает изолированного системного пользователя otlp-agent.

Копирует бинарник в `/usr/local/bin/otlp-sys-agent`

Создает директорию `/etc/otlp-sys-agent/` и копирует дефолтный `config.yaml` (если его там еще нет).

Регистрирует unit-файл `otlp-sys-agent.service` в systemd, перезагружает демон, включает автозапуск и сразу запускает сервис.

!!! ВАЖНОЕ ПРЕДУПРЕЖДЕНИЕ ПРО sudo !!!
Скрипт установки `install.sh` обязателен к запуску через `sudo`, так как он регистрирует службу `systemd` и создает системного пользователя.

Внутри файла конфигурации `/etc/otlp-sys-agent/config.yaml` использовать `sudo` КАТЕГОРИЧЕСКИ НЕЛЬЗЯ!

Неверно: `command: "sudo iptables-save -c"` - (Приведёт к ошибке sudoers_audit / Operation not permitted)

Правильно: `command: "iptables-save -c"`

Почему так? Сервис запускается от непривилегированного пользователя otlp-agent, но systemd при старте выдает процессу точечные Linux Capabilities (CAP_NET_ADMIN и CAP_NET_RAW). Агент может читать правила iptables напрямую без вызова sudo.

4. Настройка конфигурации
Отредактируйте конфигурационный файл, указав адрес вашего OTLP-приёмника:

```Bash
sudo nano /etc/otlp-sys-agent/config.yaml
```
Пример рабочей конфигурации:

```YAML
agent:
  interval_secs: 10
  log_level: "info"
  # Если оставить пустым "", имя хоста подтянется автоматически из системы
  host_name: "" 

otlp:
  endpoint: "http://10.0.0.5:4317" # Адрес вашего OTel Collector / VictoriaMetrics
  timeout_secs: 5

collectors:
  temperature:
    enabled: true

  iptables:
    enabled: true
    command: "iptables-save -c" # БЕЗ sudo!
    collect_chain_totals: true
    only_with_metadata: false
    ignore_chains: []
    target_filter: []
```
5. Перезапуск и проверка статуса
После внесения изменений в конфиг перезапустите сервис:

```Bash
sudo systemctl restart otlp-sys-agent
```
Проверьте статус и логи работы:

```Bash
# Проверка статуса службы
sudo systemctl status otlp-sys-agent

# Чтение логов в реальном времени
sudo journalctl -u otlp-sys-agent -f
```
Успешный запуск сопровождается логом:

```Plaintext
INFO otlp_sys_agent: Агент успешно запущен. hostname=pastop-pc endpoint=http://10.0.0.5:4317
```
🛠 Разработка и сборка (Dev)
Инструкция для разработчиков, желающих внести изменения в код или собрать релизный архив самостоятельно.

Требования
Rust (rustup default stable)

Task (Taskfile runner)

Zig и cargo-zigbuild (для кросс-компиляции под aarch64 и x86_64 с musl)

Подготовка окружения:
```Bash
# Установка зависимости в Arch Linux
sudo pacman -S zig
cargo install cargo-zigbuild
```
Команды разработки:
Локальный запуск агента в dev-режиме:

```Bash
task dev
```
Запуск юнит-тестов:

```Bash
task test
```
Сборка релизного архива (Full Cycle Build):

```Bash
task release
```
(Скомпилирует бинарники под x86_64 и ARM64 через Zig, сгенерирует `install.sh`, `systemd.service` и упакует всё в `dist/otlp-sys-agent-release.tar.gz`).

## Пример дашборда представлен в `GrafanaDashBoardExample.json` и `GrafanaCPUTempDashBoardExample.json`
</file>

<file path="otlp-sys-agent/Cargo.toml">
[package]
name = "otlp-sys-agent"
version = "0.1.3"
edition = "2021"
authors = ["Pastorov Nikita <pastopnik@gmail.com>","Google Gemini 3.5 Flash"]
description = "Lightweight modular OTLP system metrics collector"

[dependencies]
# Async Runtime
tokio = { version = "1.40", features = ["full"] }
async-trait = "0.1"

# OpenTelemetry & OTLP Exporter
opentelemetry = { version = "0.32.0", features = ["metrics"] }
opentelemetry_sdk = { version = "0.32.1", features = ["metrics", "rt-tokio"] }
opentelemetry-otlp = { version = " 0.32.0", features = ["http-proto", "reqwest-client", "reqwest-rustls", "metrics"] }
# opentelemetry-otlp = { version = "0.27", features = ["grpc-tonic", "metrics"] }

# Configuration & Environment
config = "0.15.25"
dotenvy = "0.15"
serde = { version = "1.0", features = ["derive"] }

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Error handling
anyhow = "1.0"
thiserror = "2.0.20"

gethostname = "1.1.0"
serde_yaml = "0.9.34"

nix = { version = "0.31.3", features = ["fs"] }

[profile.release]
opt-level = "z"     # Оптимизация по размеру бинарника
lto = true          # Link-Time Optimization для максимальной производительности
codegen-units = 1   # Максимальная оптимизация при сборке
panic = "abort"     # Убирает стэктрейсы из бинарника (уменьшает размер)
strip = true        # Автоматически вырезает отладочные символы

[dev-dependencies]
tempfile = "3.10"
</file>

<file path="Taskfile.yml">
version: '3'

vars:
  APP_NAME: otlp-sys-agent
  APP_USER: otlp-agent
  PROJECT_DIR: otlp-sys-agent
  DIST_DIR: dist
  RELEASE_DIR: '{{.DIST_DIR}}/release'
  TARGET_X86: x86_64-unknown-linux-musl
  TARGET_ARM: aarch64-unknown-linux-musl

tasks:
  default:
    desc: Полный цикл сборки релиза (тесты -> кросс-компиляция -> генерация скриптов -> архив)
    deps: [release]

  # --- СЕКЦИЯ РАЗРАБОТКИ (DEV) ---

  dev:
    desc: Запуск агента в режиме разработки (можно передать CONFIG=/path/to/config.yaml)
    vars:
      CFG: '{{.CONFIG | default (printf "%s/config.yaml" .PROJECT_DIR)}}'
    cmds:
      - CONFIG_PATH="{{.CFG}}" cargo run --manifest-path {{.PROJECT_DIR}}/Cargo.toml

  test:
    desc: Запуск юнит и интеграционных тестов Rust
    cmds:
      - cargo test --manifest-path {{.PROJECT_DIR}}/Cargo.toml --all-targets

  clean:
    desc: Очистка директории сборки dist и target
    cmds:
      - rm -rf {{.DIST_DIR}}
      - cargo clean --manifest-path {{.PROJECT_DIR}}/Cargo.toml

  # --- СЕКЦИЯ СБОРКИ (BUILD) ---

  build:x86_64:
    desc: Сборка статического бинарника для Linux x86_64 (musl)
    cmds:
      - mkdir -p {{.RELEASE_DIR}}/bin
      - cargo zigbuild --manifest-path {{.PROJECT_DIR}}/Cargo.toml --release --target {{.TARGET_X86}}
      - cp {{.PROJECT_DIR}}/target/{{.TARGET_X86}}/release/{{.APP_NAME}} {{.RELEASE_DIR}}/bin/{{.APP_NAME}}-x86_64

  build:aarch64:
    desc: Сборка статического бинарника для Linux ARM64 (musl)
    cmds:
      - mkdir -p {{.RELEASE_DIR}}/bin
      - cargo zigbuild --manifest-path {{.PROJECT_DIR}}/Cargo.toml --release --target {{.TARGET_ARM}}
      - cp {{.PROJECT_DIR}}/target/{{.TARGET_ARM}}/release/{{.APP_NAME}} {{.RELEASE_DIR}}/bin/{{.APP_NAME}}-aarch64

  build:all:
    desc: Сборка бинарников под все целевые архитектуры
    deps: [build:x86_64, build:aarch64]

  # --- СЕКЦИЯ ГЕНЕРАЦИИ РЕЛИЗНОГО ОКРУЖЕНИЯ ---

  gen:install-script:
    desc: Генерация инсталляционного bash-скрипта install.sh
    cmds:
      - mkdir -p {{.RELEASE_DIR}}
      - |
        cat << 'EOF' > {{.RELEASE_DIR}}/install.sh
        #!/usr/bin/env bash
        set -euo pipefail

        APP_NAME="{{.APP_NAME}}"
        USERNAME="{{.APP_USER}}"
        CONFIG_DIR="/etc/${APP_NAME}"
        BIN_TARGET="/usr/local/bin/${APP_NAME}"
        SERVICE_TARGET="/etc/systemd/system/${APP_NAME}.service"

        if [ "$EUID" -ne 0 ]; then
            echo "[ERROR] Запустите скрипт установки с правами root (sudo ./install.sh)"
            exit 1
        fi

        echo "=== Установка ${APP_NAME} ==="

        ARCH=$(uname -m)
        case "${ARCH}" in
            x86_64)
                BIN_SRC="./bin/${APP_NAME}-x86_64"
                ;;
            aarch64|arm64)
                BIN_SRC="./bin/${APP_NAME}-aarch64"
                ;;
            *)
                echo "[ERROR] Неподдерживаемая архитектура: ${ARCH}"
                exit 1
                ;;
        esac

        if [ ! -f "${BIN_SRC}" ]; then
            echo "[ERROR] Бинарный файл ${BIN_SRC} не найден в текущей директории!"
            exit 1
        fi

        if id "$USERNAME" &>/dev/null; then
            echo "[INFO] Пользователь '$USERNAME' уже существует."
        else
            echo "[INFO] Создание системного пользователя и группы '$USERNAME'..."
            useradd --system \
                    --user-group \
                    --no-create-home \
                    --shell /usr/bin/nologin \
                    --comment "${APP_NAME} service user" \
                    "$USERNAME"
            echo "[OK] Пользователь и группа созданы."
        fi

        echo "[INFO] Копирование бинарника в ${BIN_TARGET}..."
        cp "${BIN_SRC}" "${BIN_TARGET}"
        chmod 755 "${BIN_TARGET}"

        echo "[INFO] Настройка конфигурации в ${CONFIG_DIR}..."
        mkdir -p "${CONFIG_DIR}"
        if [ -f "${CONFIG_DIR}/config.yaml" ]; then
            echo "[WARN] Конфигурация ${CONFIG_DIR}/config.yaml уже существует. Пропускаем копирование."
        else
            cp ./config.yaml "${CONFIG_DIR}/config.yaml"
            echo "[OK] Скопирован дефолтный config.yaml"
        fi
        chown -R root:"${USERNAME}" "${CONFIG_DIR}"
        chmod 750 "${CONFIG_DIR}"
        chmod 640 "${CONFIG_DIR}/config.yaml" 2>/dev/null || true

        echo "[INFO] Установка unit-файла systemd..."
        cp "./${APP_NAME}.service" "${SERVICE_TARGET}"
        chmod 644 "${SERVICE_TARGET}"

        echo "[INFO] Перезагрузка systemd и запуск сервиса..."
        systemctl daemon-reload
        systemctl enable --now "${APP_NAME}.service"

        echo "=== Установка успешно завершена! ==="
        systemctl status "${APP_NAME}.service" --no-pager
        EOF
      - chmod +x {{.RELEASE_DIR}}/install.sh

  gen:systemd:
    desc: Генерация unit-файла systemd
    cmds:
      - mkdir -p {{.RELEASE_DIR}}
      - |
        cat << 'EOF' > {{.RELEASE_DIR}}/{{.APP_NAME}}.service
        [Unit]
        Description=OTLP System Metrics Collector Agent
        After=network.target

        [Service]
        Type=simple
        User={{.APP_USER}}
        Group={{.APP_USER}}
        WorkingDirectory=/etc/{{.APP_NAME}}
        ExecStart=/usr/local/bin/{{.APP_NAME}}
        Restart=always
        RestartSec=5s
        LimitNOFILE=65536

        # Права для чтения iptables, сетевых счетчиков и статусов /proc без root
        CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH
        AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH

        [Install]
        WantedBy=multi-user.target
        EOF

  gen:config:
    desc: Копирование config.yaml в релиз
    cmds:
      - mkdir -p {{.RELEASE_DIR}}
      - cp {{.PROJECT_DIR}}/config.yaml {{.RELEASE_DIR}}/config.yaml

  gen:scripts:
    deps: [gen:install-script, gen:systemd, gen:config]

  # --- СЕКЦИЯ РЕЛИЗА И ПУБЛИКАЦИИ (PROD / GIT) ---

  release:
    desc: Сборка релизного архива (Строго после успешного прохождения тестов)
    deps:
      - test
      - 'build:all'
      - gen:scripts
    cmds:
      - 'tar -czvf {{.DIST_DIR}}/{{.APP_NAME}}-release.tar.gz -C {{.RELEASE_DIR}} .'
      - 'echo "Релиз собран: {{.DIST_DIR}}/{{.APP_NAME}}-release.tar.gz"'

  git:push:
    desc: Безопасный коммит и пуш исходного кода в Git (блокируется при падении тестов)
    deps: [test]
    vars:
      COMMIT_MSG: '{{.MSG | default "chore: update agent codebase"}}'
    cmds:
      - git add .
      - git commit -m "{{.COMMIT_MSG}}"
      - git push origin main

  git:release:
    desc: Автоматическое поднятие версии, сборка и публикация релиза в GitHub Releases
    vars:
      RAW_TAG: '{{.TAG | default "v0.1.2"}}'
      VER: '{{.RAW_TAG | trimPrefix "v"}}'
    cmds:
      # 1. Обновляем версию строго в секции [package] Cargo.toml
      - sed -i '0,/^version = .*/s//version = "{{.VER}}"/' {{.PROJECT_DIR}}/Cargo.toml
      # 2. Фиксируем изменение версии в git
      - git add {{.PROJECT_DIR}}/Cargo.toml
      - 'git commit -m "chore: bump version to {{.VER}}" || true'
      - git push origin main
      # 3. Пересобираем релизные бинарники под обновленную версию
      - task: release
      # 4. Проставляем тег и публикуем в GitHub
      - git tag -f -a {{.RAW_TAG}} -m "Release {{.RAW_TAG}}"
      - git push origin {{.RAW_TAG}} --force
      - gh release create {{.RAW_TAG}} {{.DIST_DIR}}/{{.APP_NAME}}-release.tar.gz --title "Release {{.RAW_TAG}}" --notes "Автоматический релиз {{.RAW_TAG}}" --clobber
</file>

</files>
