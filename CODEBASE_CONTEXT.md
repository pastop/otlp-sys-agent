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
      disk.rs
      filesystem.rs
      iptables.rs
      mod.rs
      network.rs
      system.rs
      temperature.rs
    collector.rs
    config.rs
    lib.rs
    main.rs
    telemetry.rs
  tests/
    disk_test.rs
    filesystem_test.rs
    iptables_test.rs
    network_test.rs
    procfs_test.rs
    system_test.rs
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

<file path="otlp-sys-agent/src/collectors/disk.rs">
// src/collectors/disk.rs

use crate::collector::Collector;
use crate::config::DiskConfig;
use anyhow::Result;
use async_trait::async_trait;
use opentelemetry::metrics::Meter;
use opentelemetry::KeyValue;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use tracing::{debug, warn};

/// Информация о физическом диске и его разделах
#[derive(Debug, Clone)]
pub struct DiskInfo {
    /// Имя устройства: sda, nvme0n1, vda
    pub device: String,
    /// Модель диска из /sys/block/<dev>/device/model
    pub model: String,
    /// Общий размер диска в байтах
    pub total_bytes: u64,
    /// SSD (false) или HDD (true)
    pub rotational: bool,
    /// Съёмное устройство (USB-флешки и т.п.)
    pub removable: bool,
    /// Список разделов: (имя, размер в байтах)
    pub partitions: Vec<(String, u64)>,
    /// Неразмеченное пространство (разница между размером диска и суммой разделов)
    pub unallocated_bytes: u64,
}

/// I/O статистика диска из /sys/block/<dev>/stat
#[derive(Debug, Clone, Default, Copy)]
pub struct DiskIoStats {
    pub reads_completed: u64,
    pub read_bytes: u64,
    pub writes_completed: u64,
    pub write_bytes: u64,
    pub io_time_ms: u64,
    pub io_in_progress: u64,
}

/// Предыдущее состояние I/O для расчёта дельт
#[derive(Debug, Clone, Default, Copy)]
struct DiskIoPrevState {
    reads_completed: u64,
    read_sectors: u64,
    writes_completed: u64,
    write_sectors: u64,
    io_time_ms: u64,
}

// ==============================
// ЧИСТЫЕ ФУНКЦИИ ПАРСИНГА (для юнит-тестов)
// ==============================

/// Чистая функция парсинга содержимого /proc/partitions.
/// Возвращает map {имя_устройства -> размер в байтах}.
///
/// Формат /proc/partitions:
/// ```text
///  major minor  #blocks  name
///    8        0  976762584 sda
///    8        1  974761984 sda1
/// ```
/// Размер указан в блоках по 1024 байта.
pub fn parse_proc_partitions(content: &str) -> HashMap<String, u64> {
    let mut map = HashMap::new();

    for line in content.lines().skip(2) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let blocks_1024: u64 = parts[2].parse().unwrap_or(0);
            let name = parts[3].to_string();
            map.insert(name, blocks_1024 * 1024);
        }
    }

    map
}

/// Находит все разделы, принадлежащие конкретному диску.
/// Для sda: ищет sda1, sda2, ...
/// Для nvme0n1: ищет nvme0n1p1, nvme0n1p2, ...
pub fn find_partitions(
    disk_name: &str,
    partitions_map: &HashMap<String, u64>,
) -> Vec<(String, u64)> {
    let mut result = Vec::new();

    let prefix = if disk_name.starts_with("nvme") || disk_name.starts_with("mmcblk") {
        format!("{}p", disk_name)
    } else {
        disk_name.to_string()
    };

    for (name, size) in partitions_map {
        if name.starts_with(&prefix) && name.len() > prefix.len() {
            let suffix = &name[prefix.len()..];
            if suffix.chars().all(|c| c.is_ascii_digit()) {
                result.push((name.clone(), *size));
            }
        }
    }

    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

/// Расчёт неразмеченного пространства:
/// unallocated = total_bytes - сумма размеров всех разделов
pub fn calculate_unallocated(total_bytes: u64, partitions: &[(String, u64)]) -> u64 {
    let allocated: u64 = partitions.iter().map(|(_, size)| size).sum();
    total_bytes.saturating_sub(allocated)
}

/// Фильтр устройств для игнорирования
pub fn should_skip_device(device_name: &str, config: &DiskConfig) -> bool {
    if device_name.starts_with("loop")
        || device_name.starts_with("ram")
        || device_name.starts_with("zram")
        || device_name.starts_with("fd")
    {
        return true;
    }

    if config.ignore_device_mapper && device_name.starts_with("dm-") {
        return true;
    }

    if config.ignore_devices.contains(&device_name.to_string()) {
        return true;
    }

    false
}

// ==============================
// ФУНКЦИИ ЧТЕНИЯ СИСТЕМНЫХ ДАННЫХ
// ==============================

/// Читает /proc/partitions и возвращает map {имя -> размер в байтах}
fn read_proc_partitions() -> HashMap<String, u64> {
    match fs::read_to_string("/proc/partitions") {
        Ok(content) => parse_proc_partitions(&content),
        Err(_) => HashMap::new(),
    }
}

/// Утилита: чтение u64 из sysfs-файла
fn read_sys_u64(path: &Path) -> Option<u64> {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
}

// ==============================
// СБОР ИНФОРМАЦИИ О ДИСКАХ
// ==============================

/// Основная функция: собирает информацию о всех физических дисках
pub fn collect_disk_info(config: &DiskConfig) -> Vec<DiskInfo> {
    let partitions_map = read_proc_partitions();
    let mut disks = Vec::new();

    let sys_block_path = Path::new("/sys/block");
    let entries = match fs::read_dir(sys_block_path) {
        Ok(e) => e,
        Err(err) => {
            warn!("Не удалось прочитать /sys/block: {}", err);
            return disks;
        }
    };

    for entry in entries.flatten() {
        let device_name = entry.file_name().to_string_lossy().to_string();

        if should_skip_device(&device_name, config) {
            continue;
        }

        let dev_path = entry.path();

        // 1. Размер диска в секторах (по 512 байт)
        let total_bytes = match read_sys_u64(&dev_path.join("size")) {
            Some(sectors) => sectors * 512,
            None => continue,
        };

        if total_bytes == 0 {
            continue;
        }

        // 2. Модель диска
        let model = fs::read_to_string(dev_path.join("device/model"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| {
                fs::read_to_string(dev_path.join("model"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "unknown".to_string())
            });

        // 3. SSD или HDD
        let rotational = read_sys_u64(&dev_path.join("queue/rotational"))
            .map(|v| v == 1)
            .unwrap_or(false);

        // 4. Съёмное устройство
        let removable = read_sys_u64(&dev_path.join("removable"))
            .map(|v| v == 1)
            .unwrap_or(false);

        // 5. Найти все разделы этого диска
        let disk_partitions = find_partitions(&device_name, &partitions_map);

        // 6. Рассчитать неразмеченное пространство
        let unallocated_bytes = calculate_unallocated(total_bytes, &disk_partitions);

        disks.push(DiskInfo {
            device: device_name,
            model,
            total_bytes,
            rotational,
            removable,
            partitions: disk_partitions,
            unallocated_bytes,
        });
    }

    disks
}

/// Чтение I/O статистики из /sys/block/<dev>/stat
/// Формат (11+ полей):
/// reads_completed reads_merged sectors_read read_time_ms
/// writes_completed writes_merged sectors_written write_time_ms
/// io_in_progress io_time_ms weighted_io_time_ms ...
pub fn collect_disk_io_stats(config: &DiskConfig) -> HashMap<String, DiskIoStats> {
    let mut stats = HashMap::new();
    let sys_block_path = Path::new("/sys/block");

    let entries = match fs::read_dir(sys_block_path) {
        Ok(e) => e,
        Err(_) => return stats,
    };

    for entry in entries.flatten() {
        let device_name = entry.file_name().to_string_lossy().to_string();

        // Фильтруем устройства сразу при сборе
        if should_skip_device(&device_name, config) {
            continue;
        }

        let stat_path = entry.path().join("stat");
        let content = match fs::read_to_string(&stat_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let fields: Vec<&str> = content.split_whitespace().collect();
        if fields.len() < 11 {
            continue;
        }

        let reads_completed = fields[0].parse::<u64>().unwrap_or(0);
        let sectors_read = fields[2].parse::<u64>().unwrap_or(0);
        let writes_completed = fields[4].parse::<u64>().unwrap_or(0);
        let sectors_written = fields[6].parse::<u64>().unwrap_or(0);
        let io_in_progress = fields[8].parse::<u64>().unwrap_or(0);
        let io_time_ms = fields[9].parse::<u64>().unwrap_or(0);

        stats.insert(
            device_name,
            DiskIoStats {
                reads_completed,
                read_bytes: sectors_read * 512,
                writes_completed,
                write_bytes: sectors_written * 512,
                io_time_ms,
                io_in_progress,
            },
        );
    }

    stats
}

// ==============================
// COLLECTOR IMPLEMENTATION
// ==============================

pub struct DiskCollector {
    hostname: String,
    config: DiskConfig,
    prev_io: Mutex<HashMap<String, DiskIoPrevState>>,
}

impl DiskCollector {
    pub fn new(config: DiskConfig, hostname: String) -> Self {
        Self {
            config,
            hostname,
            prev_io: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl Collector for DiskCollector {
    fn name(&self) -> &'static str {
        "disk"
    }

    async fn collect(&self, meter: &Meter) -> Result<()> {
        // ── 1. Информация о дисках ──
        let disks = collect_disk_info(&self.config);

        let total_gauge = meter
            .u64_gauge("system.disk.total_bytes")
            .with_description("Total size of physical disk in bytes")
            .with_unit("By")
            .build();

        let unallocated_gauge = meter
            .u64_gauge("system.disk.unallocated_bytes")
            .with_description("Unallocated (free) space on physical disk")
            .with_unit("By")
            .build();

        let partition_gauge = meter
            .u64_gauge("system.disk.partition_size_bytes")
            .with_description("Size of disk partition in bytes")
            .with_unit("By")
            .build();

        for disk in &disks {
            let base_attrs = [
                KeyValue::new("host_name", self.hostname.clone()),
                KeyValue::new("device", disk.device.clone()),
                KeyValue::new("model", disk.model.clone()),
                KeyValue::new("rotational", disk.rotational),
                KeyValue::new("removable", disk.removable),
            ];

            total_gauge.record(disk.total_bytes, &base_attrs);
            unallocated_gauge.record(disk.unallocated_bytes, &base_attrs);

            for (part_name, part_size) in &disk.partitions {
                let part_attrs = [
                    KeyValue::new("host_name", self.hostname.clone()),
                    KeyValue::new("device", disk.device.clone()),
                    KeyValue::new("partition", part_name.clone()),
                ];
                partition_gauge.record(*part_size, &part_attrs);
            }

            debug!(
                device = %disk.device,
                model = %disk.model,
                total_gb = disk.total_bytes / 1024 / 1024 / 1024,
                unallocated_gb = disk.unallocated_bytes / 1024 / 1024 / 1024,
                partitions = disk.partitions.len(),
                "Метрики диска отправлены"
            );
        }

        // ── 2. I/O статистика дисков ──
        if !self.config.collect_io {
            return Ok(());
        }

        let io_stats = collect_disk_io_stats(&self.config);

        let read_counter = meter
            .u64_counter("system.disk.io.read_bytes")
            .with_description("Bytes read from disk")
            .with_unit("By")
            .build();

        let write_counter = meter
            .u64_counter("system.disk.io.write_bytes")
            .with_description("Bytes written to disk")
            .with_unit("By")
            .build();

        let reads_counter = meter
            .u64_counter("system.disk.io.reads_completed")
            .with_description("Number of completed read operations")
            .build();

        let writes_counter = meter
            .u64_counter("system.disk.io.writes_completed")
            .with_description("Number of completed write operations")
            .build();

        let io_time_counter = meter
            .u64_counter("system.disk.io.io_time_ms")
            .with_description("Time spent doing I/Os in milliseconds")
            .with_unit("ms")
            .build();

        let io_in_progress_gauge = meter
            .u64_gauge("system.disk.io.in_progress")
            .with_description("Number of I/Os currently in progress")
            .build();

        let mut prev_map = self.prev_io.lock().unwrap();
        let mut next_map = HashMap::new();

        for (device, io) in &io_stats {
            let attrs = [
                KeyValue::new("host_name", self.hostname.clone()),
                KeyValue::new("device", device.clone()),
            ];

            let cur_read_sectors = io.read_bytes / 512;
            let cur_write_sectors = io.write_bytes / 512;

            let has_prev = prev_map.contains_key(device);

            if has_prev {
                let prev = prev_map[device];

                let delta_read_bytes =
                    cur_read_sectors.saturating_sub(prev.read_sectors) * 512;
                let delta_write_bytes =
                    cur_write_sectors.saturating_sub(prev.write_sectors) * 512;
                let delta_reads =
                    io.reads_completed.saturating_sub(prev.reads_completed);
                let delta_writes =
                    io.writes_completed.saturating_sub(prev.writes_completed);
                let delta_io_time =
                    io.io_time_ms.saturating_sub(prev.io_time_ms);

                read_counter.add(delta_read_bytes, &attrs);
                write_counter.add(delta_write_bytes, &attrs);
                reads_counter.add(delta_reads, &attrs);
                writes_counter.add(delta_writes, &attrs);
                io_time_counter.add(delta_io_time, &attrs);
            }

            io_in_progress_gauge.record(io.io_in_progress, &attrs);

            next_map.insert(
                device.clone(),
                DiskIoPrevState {
                    reads_completed: io.reads_completed,
                    read_sectors: cur_read_sectors,
                    writes_completed: io.writes_completed,
                    write_sectors: cur_write_sectors,
                    io_time_ms: io.io_time_ms,
                },
            );
        }

        *prev_map = next_map;

        Ok(())
    }
}
</file>

<file path="otlp-sys-agent/src/collectors/filesystem.rs">
// src/collectors/filesystem.rs

use crate::collector::Collector;
use crate::config::FilesystemConfig;
use anyhow::Result;
use async_trait::async_trait;
use nix::sys::statvfs::{statvfs, FsFlags};
use opentelemetry::metrics::Meter;
use opentelemetry::KeyValue;
use std::fs;
use std::path::Path;
use tracing::{debug, warn};

#[derive(Debug)]
pub struct FsMetrics {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub reserved_bytes: u64,
    pub inodes_total: u64,
    pub inodes_free: u64,
    pub is_read_only: bool,
}

/// Запись из /proc/mounts
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
}

/// Чистая функция парсинга содержимого /proc/mounts.
/// Фильтрует ТОЛЬКО по префиксу /dev/ (базовая фильтрация).
/// НЕ применяет фильтры из конфига — это задача collect_fs_metrics.
pub fn parse_proc_mounts(content: &str) -> Vec<MountEntry> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let device = parts[0];
        let mount_point = parts[1];
        let fs_type = parts[2];

        // Только реальные блочные устройства
        if !device.starts_with("/dev/") {
            continue;
        }

        entries.push(MountEntry {
            device: device.to_string(),
            mount_point: mount_point.to_string(),
            fs_type: fs_type.to_string(),
        });
    }

    entries
}

/// Полный сбор метрик: парсинг + фильтрация по config + statvfs
pub fn collect_fs_metrics(config: &FilesystemConfig) -> Vec<FsMetrics> {
    let mut metrics = Vec::new();
    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
    let entries = parse_proc_mounts(&mounts);

    for entry in entries {
        // Фильтр: игнорировать определённые типы ФС (из конфига)
        if config.ignore_fs_types.iter().any(|t| t == &entry.fs_type) {
            continue;
        }

        // Фильтр: игнорировать определённые точки монтирования (из конфига)
        if config
            .ignore_mount_points
            .iter()
            .any(|mp| entry.mount_point.starts_with(mp.as_str()))
        {
            continue;
        }

        let stat = match statvfs(Path::new(&entry.mount_point)) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    mountpoint = %entry.mount_point,
                    error = %e,
                    "Ошибка statvfs"
                );
                continue;
            }
        };

        let block_size = stat.fragment_size() as u64;
        let total_bytes = stat.blocks() as u64 * block_size;
        let free_root_bytes = stat.blocks_free() as u64 * block_size;
        let free_user_bytes = stat.blocks_available() as u64 * block_size;
        let used_bytes = total_bytes.saturating_sub(free_root_bytes);
        let reserved_bytes = free_root_bytes.saturating_sub(free_user_bytes);
        let is_read_only = stat.flags().contains(FsFlags::ST_RDONLY);

        metrics.push(FsMetrics {
            device: entry.device,
            mount_point: entry.mount_point,
            fs_type: entry.fs_type,
            total_bytes,
            used_bytes,
            free_bytes: free_user_bytes,
            reserved_bytes,
            inodes_total: stat.files() as u64,
            inodes_free: stat.files_free() as u64,
            is_read_only,
        });
    }

    metrics
}

// ========================
// COLLECTOR IMPLEMENTATION
// ========================

pub struct FilesystemCollector {
    hostname: String,
    config: FilesystemConfig,
}

impl FilesystemCollector {
    pub fn new(config: FilesystemConfig, hostname: String) -> Self {
        Self { config, hostname }
    }
}

#[async_trait]
impl Collector for FilesystemCollector {
    fn name(&self) -> &'static str {
        "filesystem"
    }

    async fn collect(&self, meter: &Meter) -> Result<()> {
        let fs_metrics = collect_fs_metrics(&self.config);

        let total_gauge = meter
            .u64_gauge("system.filesystem.total_bytes")
            .with_description("Total filesystem size in bytes")
            .with_unit("By")
            .build();

        let used_gauge = meter
            .u64_gauge("system.filesystem.used_bytes")
            .with_description("Used filesystem space in bytes")
            .with_unit("By")
            .build();

        let free_gauge = meter
            .u64_gauge("system.filesystem.free_bytes")
            .with_description("Free filesystem space available to non-root users")
            .with_unit("By")
            .build();

        let reserved_gauge = meter
            .u64_gauge("system.filesystem.reserved_bytes")
            .with_description("Reserved filesystem space (root-only blocks)")
            .with_unit("By")
            .build();

        let inodes_total_gauge = meter
            .u64_gauge("system.filesystem.inodes_total")
            .with_description("Total number of filesystem inodes")
            .build();

        let inodes_free_gauge = meter
            .u64_gauge("system.filesystem.inodes_free")
            .with_description("Number of free filesystem inodes")
            .build();

        for fs in &fs_metrics {
            let attrs = [
                KeyValue::new("host_name", self.hostname.clone()),
                KeyValue::new("device", fs.device.clone()),
                KeyValue::new("mountpoint", fs.mount_point.clone()),
                KeyValue::new("fstype", fs.fs_type.clone()),
            ];

            total_gauge.record(fs.total_bytes, &attrs);
            used_gauge.record(fs.used_bytes, &attrs);
            free_gauge.record(fs.free_bytes, &attrs);
            reserved_gauge.record(fs.reserved_bytes, &attrs);
            inodes_total_gauge.record(fs.inodes_total, &attrs);
            inodes_free_gauge.record(fs.inodes_free, &attrs);

            debug!(
                device = %fs.device,
                mountpoint = %fs.mount_point,
                total = fs.total_bytes,
                used = fs.used_bytes,
                free = fs.free_bytes,
                reserved = fs.reserved_bytes,
                "Метрики файловой системы отправлены"
            );
        }

        Ok(())
    }
}
</file>

<file path="otlp-sys-agent/src/collectors/system.rs">
// src/collectors/system.rs

use crate::collector::Collector;
use anyhow::Result;
use async_trait::async_trait;
use opentelemetry::metrics::Meter;
use opentelemetry::KeyValue;
use std::collections::HashMap;
use std::fs;
use std::sync::Mutex;
// ❌ УБРАНО: use tracing::warn;   (не используется)

/// Информация о CPU из /proc/cpuinfo
#[derive(Debug, Clone)]
pub struct CpuInfo {
    pub model: String,
    pub cores: u64,
    pub threads: u64,
}

/// Состояние CPU из /proc/stat (для расчёта загрузки)
/// ✅ СДЕЛАНО pub + поля pub для доступа из тестов
#[derive(Debug, Clone, Default, Copy)]
pub struct CpuStatState {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl CpuStatState {
    /// Суммарное время всех состояний CPU
    pub fn total(&self) -> u64 {
        self.user + self.nice + self.system + self.idle
            + self.iowait + self.irq + self.softirq + self.steal
    }

    /// Время, когда CPU был занят (всё кроме idle и iowait)
    pub fn busy(&self) -> u64 {
        self.user + self.nice + self.system + self.irq + self.softirq + self.steal
    }
}

/// Информация о памяти из /proc/meminfo
#[derive(Debug, Clone)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub buffers_bytes: u64,
    pub cached_bytes: u64,
}

// ==============================
// ЧИСТЫЕ ФУНКЦИИ ПАРСИНГА
// ==============================

pub fn parse_cpuinfo(content: &str) -> CpuInfo {
    let mut model = String::from("unknown");
    let mut physical_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut threads: u64 = 0;

    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }
        let key = parts[0].trim();
        let value = parts[1].trim();

        match key {
            "model name" => {
                if model == "unknown" {
                    model = value.to_string();
                }
            }
            "physical id" => {
                physical_ids.insert(value.to_string());
            }
            "processor" => {
                threads += 1;
            }
            _ => {}
        }
    }

    let cores = if physical_ids.is_empty() { threads } else { threads };

    CpuInfo { model, cores, threads }
}

pub fn parse_proc_stat(content: &str) -> CpuStatState {
    for line in content.lines() {
        if line.starts_with("cpu ") {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 8 {
                return CpuStatState {
                    user: fields[1].parse().unwrap_or(0),
                    nice: fields[2].parse().unwrap_or(0),
                    system: fields[3].parse().unwrap_or(0),
                    idle: fields[4].parse().unwrap_or(0),
                    iowait: fields[5].parse().unwrap_or(0),
                    irq: fields[6].parse().unwrap_or(0),
                    softirq: fields[7].parse().unwrap_or(0),
                    steal: fields.get(8).and_then(|v| v.parse().ok()).unwrap_or(0),
                };
            }
        }
    }
    CpuStatState::default()
}

pub fn parse_meminfo(content: &str) -> MemoryInfo {
    let mut map: HashMap<&str, u64> = HashMap::new();

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let key = parts[0].trim_end_matches(':');
            let value_kb: u64 = parts[1].parse().unwrap_or(0);
            map.insert(key, value_kb * 1024);
        }
    }

    let total = map.get("MemTotal").copied().unwrap_or(0);
    let available = map.get("MemAvailable").copied().unwrap_or(0);
    let free = map.get("MemFree").copied().unwrap_or(0);
    let buffers = map.get("Buffers").copied().unwrap_or(0);
    let cached = map.get("Cached").copied().unwrap_or(0);
    let used = total.saturating_sub(available);

    MemoryInfo {
        total_bytes: total,
        available_bytes: available,
        used_bytes: used,
        free_bytes: free,
        buffers_bytes: buffers,
        cached_bytes: cached,
    }
}

pub fn calculate_cpu_usage(prev: &CpuStatState, cur: &CpuStatState) -> f64 {
    let total_delta = cur.total().saturating_sub(prev.total());
    let busy_delta = cur.busy().saturating_sub(prev.busy());
    if total_delta == 0 {
        return 0.0;
    }
    (busy_delta as f64 / total_delta as f64) * 100.0
}

// ==============================
// COLLECTOR IMPLEMENTATION
// (остальная часть без изменений)
// ==============================

pub struct SystemCollector {
    hostname: String,
    prev_cpu_stat: Mutex<CpuStatState>,
}

impl SystemCollector {
    pub fn new(hostname: String) -> Self {
        Self {
            hostname,
            prev_cpu_stat: Mutex::new(CpuStatState::default()),
        }
    }
}

#[async_trait]
impl Collector for SystemCollector {
    fn name(&self) -> &'static str {
        "system"
    }

    async fn collect(&self, meter: &Meter) -> Result<()> {
        let base_attrs = [KeyValue::new("host_name", self.hostname.clone())];

        // CPU Info
        let cpuinfo_content = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let cpu_info = parse_cpuinfo(&cpuinfo_content);

        let cpu_info_gauge = meter
            .f64_gauge("system.cpu.info")
            .with_description("CPU metadata (always 1)")
            .build();

        let cpu_info_attrs = [
            KeyValue::new("host_name", self.hostname.clone()),
            KeyValue::new("cpu_model", cpu_info.model.clone()),
            KeyValue::new("cpu_threads", cpu_info.threads.to_string()),
        ];
        cpu_info_gauge.record(1.0, &cpu_info_attrs);

        // CPU Usage
        let stat_content = fs::read_to_string("/proc/stat").unwrap_or_default();
        let cur_stat = parse_proc_stat(&stat_content);

        let cpu_usage_gauge = meter
            .f64_gauge("system.cpu.usage")
            .with_description("CPU usage percentage (0-100)")
            .with_unit("%")
            .build();

        let mut prev_stat = self.prev_cpu_stat.lock().unwrap();
        let usage = calculate_cpu_usage(&prev_stat, &cur_stat);
        cpu_usage_gauge.record(usage, &base_attrs);
        *prev_stat = cur_stat;

        // Memory
        let meminfo_content = fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let mem = parse_meminfo(&meminfo_content);

        let mem_total_gauge = meter
            .u64_gauge("system.memory.total_bytes")
            .with_description("Total system memory in bytes")
            .with_unit("By")
            .build();
        let mem_used_gauge = meter
            .u64_gauge("system.memory.used_bytes")
            .with_description("Used system memory in bytes")
            .with_unit("By")
            .build();
        let mem_available_gauge = meter
            .u64_gauge("system.memory.available_bytes")
            .with_description("Available system memory in bytes")
            .with_unit("By")
            .build();
        let mem_free_gauge = meter
            .u64_gauge("system.memory.free_bytes")
            .with_description("Free system memory in bytes")
            .with_unit("By")
            .build();

        mem_total_gauge.record(mem.total_bytes, &base_attrs);
        mem_used_gauge.record(mem.used_bytes, &base_attrs);
        mem_available_gauge.record(mem.available_bytes, &base_attrs);
        mem_free_gauge.record(mem.free_bytes, &base_attrs);

        Ok(())
    }
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

<file path="otlp-sys-agent/tests/filesystem_test.rs">
// tests/filesystem_test.rs

use otlp_sys_agent::collectors::filesystem::{parse_proc_mounts, collect_fs_metrics};
use otlp_sys_agent::config::FilesystemConfig;

/// Реалистичный вывод /proc/mounts
fn mock_proc_mounts() -> &'static str {
    r#"sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
udev /dev devtmpfs rw,nosuid,noexec,relatime,size=8045012k,nr_inodes=2011253,mode=755 0 0
/dev/sda1 / ext4 rw,relatime,errors=remap-ro 0 0
/dev/sda2 /home ext4 rw,relatime 0 0
/dev/nvme0n1p1 /data xfs rw,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota 0 0
tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,size=1611076k,mode=755 0 0
/dev/sdb1 /mnt/backup ext4 ro,relatime 0 0
overlay /var/lib/docker/overlay2/abc/merged overlay rw,relatime,lowerdir=...,upperdir=...,workdir=... 0 0
/dev/mapper/vg-lv /var/lib/lvm ext4 rw,relatime 0 0
"#
}

#[test]
fn test_parse_proc_mounts_filters_real_devices() {
    let entries = parse_proc_mounts(mock_proc_mounts());

    // Должны остаться только /dev/* устройства:
    // sda1, sda2, nvme0n1p1, sdb1, mapper/vg-lv
    // НЕ должны: sysfs, proc, udev, tmpfs, overlay
    assert_eq!(entries.len(), 5);
}

#[test]
fn test_parse_proc_mounts_correct_fields() {
    let entries = parse_proc_mounts(mock_proc_mounts());

    // Первый реальный девайс: /dev/sda1
    let root = &entries[0];
    assert_eq!(root.device, "/dev/sda1");
    assert_eq!(root.mount_point, "/");
    assert_eq!(root.fs_type, "ext4");

    // NVMe устройство
    let nvme = &entries[2];
    assert_eq!(nvme.device, "/dev/nvme0n1p1");
    assert_eq!(nvme.mount_point, "/data");
    assert_eq!(nvme.fs_type, "xfs");
}

#[test]
fn test_parse_proc_mounts_skips_virtual_fs() {
    let entries = parse_proc_mounts(mock_proc_mounts());

    for entry in &entries {
        assert!(
            entry.device.starts_with("/dev/"),
            "Обнаружено не-блочное устройство: {}",
            entry.device
        );
    }
}

#[test]
fn test_parse_proc_mounts_empty_input() {
    let entries = parse_proc_mounts("");
    assert!(entries.is_empty());
}

#[test]
fn test_parse_proc_mounts_malformed_lines() {
    let content = "incomplete\n/dev/sda1 /\n/dev/sda2 /home ext4 rw 0 0\n";
    let entries = parse_proc_mounts(content);
    // Только одна строка имеет >= 4 полей и /dev/
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].device, "/dev/sda2");
}

#[test]
fn test_collect_fs_metrics_integration() {
    // Интеграционный тест: работает только на Linux с /proc/mounts
    // Используем default config (без игнорирования типов ФС)
    let config = FilesystemConfig {
        enabled: true,
        ignore_mount_points: vec![],
        ignore_fs_types: vec![],
    };

    let metrics = collect_fs_metrics(&config);

    // На любой Linux-системе должен быть хотя бы корень (/)
    assert!(
        !metrics.is_empty(),
        "Ожидается хотя бы одна файловая система"
    );

    // Проверяем корневую ФС
    let root_fs = metrics.iter().find(|m| m.mount_point == "/");
    if let Some(root) = root_fs {
        assert!(root.total_bytes > 0, "Общий объём корня должен быть > 0");
        assert!(root.used_bytes <= root.total_bytes, "Занято <= Общего");
        assert!(root.inodes_total > 0, "Inodes total > 0");
    }
}

#[test]
fn test_collect_fs_metrics_with_config_filters() {
    // Проверяем, что config-фильтры работают
    let config = FilesystemConfig {
        enabled: true,
        ignore_mount_points: vec!["/mnt".to_string()],
        ignore_fs_types: vec!["xfs".to_string()],
    };

    let metrics = collect_fs_metrics(&config);

    // Убеждаемся, что отфильтрованные ФС не попали
    for m in &metrics {
        assert!(
            !m.mount_point.starts_with("/mnt"),
            "Точка /mnt должна быть отфильтрована"
        );
        assert!(
            m.fs_type != "xfs",
            "ФС типа xfs должна быть отфильтрована"
        );
    }
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

<file path="otlp-sys-agent/tests/system_test.rs">
use otlp_sys_agent::collectors::system::{
    calculate_cpu_usage, parse_cpuinfo, parse_meminfo, parse_proc_stat,
};

#[test]
fn test_parse_cpuinfo() {
    let content = r#"processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i7-9700 CPU @ 3.00GHz
physical id	: 0

processor	: 1
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i7-9700 CPU @ 3.00GHz
physical id	: 0
"#;
    let info = parse_cpuinfo(content);
    assert_eq!(info.model, "Intel(R) Core(TM) i7-9700 CPU @ 3.00GHz");
    assert_eq!(info.threads, 2);
}

#[test]
fn test_parse_proc_stat() {
    let content = "cpu  1000 200 300 5000 100 50 25 10 0 0\ncpu0 500 100 150 2500 50 25 12 5 0 0\n";
    let state = parse_proc_stat(content);
    assert_eq!(state.user, 1000);
    assert_eq!(state.nice, 200);
    assert_eq!(state.system, 300);
    assert_eq!(state.idle, 5000);
    assert_eq!(state.iowait, 100);
}

#[test]
fn test_parse_meminfo() {
    let content = "MemTotal:       16384000 kB\nMemFree:         4096000 kB\nMemAvailable:    8192000 kB\nBuffers:          512000 kB\nCached:          2048000 kB\n";
    let mem = parse_meminfo(content);
    assert_eq!(mem.total_bytes, 16384000 * 1024);
    assert_eq!(mem.available_bytes, 8192000 * 1024);
    assert_eq!(mem.free_bytes, 4096000 * 1024);
    assert_eq!(mem.used_bytes, (16384000 - 8192000) * 1024);
}

#[test]
fn test_calculate_cpu_usage() {
    let prev = otlp_sys_agent::collectors::system::parse_proc_stat(
        "cpu  1000 0 500 8000 500 0 0 0 0 0\n"
    );
    let cur = otlp_sys_agent::collectors::system::parse_proc_stat(
        "cpu  2000 0 1000 9000 500 0 0 0 0 0\n"
    );
    // busy_delta = (2000-1000) + (1000-500) = 1500
    // total_delta = (2000+1000+9000+500) - (1000+500+8000+500) = 2500
    // usage = 1500/2500 * 100 = 60%
    let usage = calculate_cpu_usage(&prev, &cur);
    assert!((usage - 60.0).abs() < 0.01, "Expected 60%, got {}", usage);
}

#[test]
fn test_calculate_cpu_usage_zero_delta() {
    let state = parse_proc_stat("cpu  1000 0 500 8000 500 0 0 0 0 0\n");
    let usage = calculate_cpu_usage(&state, &state);
    assert_eq!(usage, 0.0);
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

<file path="otlp-sys-agent/src/collectors/network.rs">
// src/collectors/network.rs

use crate::collector::Collector;
use crate::config::NetworkConfig;
use anyhow::Result;
use async_trait::async_trait;
use nix::ifaddrs::getifaddrs;
use opentelemetry::metrics::Meter;
use opentelemetry::KeyValue;
use std::collections::HashMap;
use std::fs;
use std::net::Ipv6Addr;
use std::path::Path;
use tracing::{debug, warn};

/// Полная информация о сетевом интерфейсе
#[derive(Debug, Clone)]
pub struct NetworkInterfaceInfo {
    pub name: String,
    pub mac: String,
    pub speed_mbps: Option<u64>,
    pub duplex: Option<String>,
    pub operstate: String,
    pub flags: u32,          // <-- ДОБАВЛЕНО
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
}

/// I/O статистика интерфейса
#[derive(Debug, Clone, Default, Copy)]
pub struct NetworkIoStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

// ==============================
// ЧИСТЫЕ ФУНКЦИИ ПАРСИНГА (для юнит-тестов)
// ==============================

/// Парсит MAC-адрес, нормализуя регистр и убирая trailing newline
pub fn parse_mac(raw: &str) -> String {
    raw.trim().to_lowercase()
}

/// Парсит скорость из sysfs. Возвращает None, если:
/// - файл недоступен (интерфейс down, виртуальный)
/// - значение невалидно
/// - значение == -1 (нет линка)
/// - значение == 4294961 (магическое значение для virtio без линка)
pub fn parse_speed_mbps(raw: &str) -> Option<u64> {
    let s = raw.trim();
    let v = s.parse::<i64>().ok()?;
    if v <= 0 || v == 4294961 {
        return None;
    }
    Some(v as u64)
}

/// Парсит duplex из sysfs
pub fn parse_duplex(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s == "unknown" {
        None
    } else {
        Some(s.to_string())
    }
}

/// Парсит operstate из sysfs
pub fn parse_operstate(raw: &str) -> String {
    let s = raw.trim();
    if s.is_empty() {
        "unknown".to_string()
    } else {
        s.to_string()
    }
}

/// Парсит hex-флаги интерфейса из sysfs.
/// Пример: "0x11091" -> 0x11091
pub fn parse_interface_flags(raw: &str) -> u32 {
    let s = raw.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(s, 16).unwrap_or(0)
}

/// Определяет, UP ли интерфейс, по operstate и флагам.
///
/// Логика:
/// - operstate == "up" → UP
/// - operstate == "down" → DOWN
/// - operstate == "unknown" → проверяем флаг IFF_UP (0x1)
///   (PPP, bridge и другие интерфейсы без carrier detection)
pub fn is_interface_up(operstate: &str, flags: u32) -> bool {
    match operstate {
        "up" => true,
        "down" => false,
        _ => {
            // IFF_UP = 0x1
            (flags & 0x1) != 0
        }
    }
}

/// Фильтр интерфейсов
pub fn should_skip_interface(name: &str, config: &NetworkConfig) -> bool {
    // Точные совпадения
    if config.ignore_exact.contains(&name.to_string()) {
        return true;
    }
    // По префиксам
    for prefix in &config.ignore_interfaces {
        if name.starts_with(prefix) || name == prefix {
            return true;
        }
    }
    false
}

/// Парсит sysfs-статистику из содержимого директории statistics/
pub fn parse_statistics(stats: &HashMap<String, String>) -> NetworkIoStats {
    let get = |key: &str| -> u64 {
        stats.get(key).and_then(|v| v.trim().parse().ok()).unwrap_or(0)
    };

    NetworkIoStats {
        rx_bytes: get("rx_bytes"),
        tx_bytes: get("tx_bytes"),
        rx_packets: get("rx_packets"),
        tx_packets: get("tx_packets"),
        rx_errors: get("rx_errors"),
        tx_errors: get("tx_errors"),
        rx_dropped: get("rx_dropped"),
        tx_dropped: get("tx_dropped"),
    }
}

// ==============================
// ФУНКЦИИ ЧТЕНИЯ СИСТЕМНЫХ ДАННЫХ
// ==============================

/// Утилита: чтение строки из sysfs-файла
fn read_sys_str(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

/// Собирает map {имя_интерфейса -> (Vec<IPv4>, Vec<IPv6>)}
fn collect_ip_addresses() -> HashMap<String, (Vec<String>, Vec<String>)> {
    let mut map: HashMap<String, (Vec<String>, Vec<String>)> = HashMap::new();

    let addrs = match getifaddrs() {
        Ok(a) => a,
        Err(e) => {
            warn!("Не удалось получить список IP-адресов: {}", e);
            return map;
        }
    };

    for ifaddr in addrs {
        let name = ifaddr.interface_name;
        let entry = map.entry(name).or_insert_with(|| (Vec::new(), Vec::new()));

        if let Some(addr) = ifaddr.address {
            // addr имеет тип nix::sys::socket::SockaddrStorage

            // Пытаемся получить IPv4
            if let Some(ipv4) = addr.as_sockaddr_in() {
                let ip = ipv4.ip(); // возвращает std::net::Ipv4Addr
                // Пропускаем link-local (169.254.0.0/16)
                if !ip.is_link_local() {
                    entry.0.push(ip.to_string());
                }
            }
            // Пытаемся получить IPv6
            else if let Some(ipv6) = addr.as_sockaddr_in6() {
                let ip = ipv6.ip(); // возвращает std::net::Ipv6Addr
                // Пропускаем link-local (fe80::)
                if !is_ipv6_link_local(&ip) {
                    entry.1.push(ip.to_string());
                }
            }
        }
    }

    map
}

fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    let seg = ip.segments();
    (seg[0] & 0xffc0) == 0xfe80
}

/// Читает sysfs-статистику из директории /sys/class/net/<iface>/statistics/
fn read_interface_statistics(iface_path: &Path) -> NetworkIoStats {
    let stats_dir = iface_path.join("statistics");
    let mut map = HashMap::new();

    let entries = match fs::read_dir(&stats_dir) {
        Ok(e) => e,
        Err(_) => return NetworkIoStats::default(),
    };

    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                map.insert(name.to_string(), content);
            }
        }
    }

    parse_statistics(&map)
}

/// Основная функция: сбор информации о всех физических сетевых интерфейсах
pub fn collect_network_info(config: &NetworkConfig) -> Vec<NetworkInterfaceInfo> {
    let mut interfaces = Vec::new();
    let net_path = Path::new("/sys/class/net");

    let entries = match fs::read_dir(net_path) {
        Ok(e) => e,
        Err(err) => {
            warn!("Не удалось прочитать /sys/class/net: {}", err);
            return interfaces;
        }
    };

    let ip_map = if config.collect_ip {
        collect_ip_addresses()
    } else {
        HashMap::new()
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();

        if should_skip_interface(&name, config) {
            continue;
        }

        let iface_path = entry.path();

        // MAC
        let mac = read_sys_str(&iface_path.join("address"))
            .map(|s| parse_mac(&s))
            .unwrap_or_default();

        // Speed (может отсутствовать для виртуальных и down-интерфейсов)
        let speed_mbps = read_sys_str(&iface_path.join("speed"))
            .and_then(|s| parse_speed_mbps(&s));

        // Duplex
        let duplex = read_sys_str(&iface_path.join("duplex"))
            .and_then(|s| parse_duplex(&s));

        // Operstate
        let operstate = read_sys_str(&iface_path.join("operstate"))
            .map(|s| parse_operstate(&s))
            .unwrap_or_else(|| "unknown".to_string());

        // Flags (для определения UP на PPP и других интерфейсах с operstate=unknown)
        let flags = read_sys_str(&iface_path.join("flags"))
            .map(|s| parse_interface_flags(&s))
            .unwrap_or(0);

        // IP адреса
        let (ipv4, ipv6) = ip_map
            .get(&name)
            .cloned()
            .unwrap_or_else(|| (Vec::new(), Vec::new()));

        interfaces.push(NetworkInterfaceInfo {
            name,
            mac,
            speed_mbps,
            duplex,
            operstate,
            flags,       // <-- ДОБАВЛЕНО
            ipv4,
            ipv6,
        });
    }

    // Сортируем для стабильного порядка метрик
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    interfaces
}

/// Сбор I/O статистики для всех интерфейсов (без фильтрации)
pub fn collect_network_io_stats(config: &NetworkConfig) -> HashMap<String, NetworkIoStats> {
    let mut stats = HashMap::new();
    let net_path = Path::new("/sys/class/net");

    let entries = match fs::read_dir(net_path) {
        Ok(e) => e,
        Err(_) => return stats,
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();

        if should_skip_interface(&name, config) {
            continue;
        }

        let io_stats = read_interface_statistics(&entry.path());
        stats.insert(name, io_stats);
    }

    stats
}

// ==============================
// COLLECTOR IMPLEMENTATION
// ==============================

pub struct NetworkCollector {
    hostname: String,
    config: NetworkConfig,
}

impl NetworkCollector {
    pub fn new(config: NetworkConfig, hostname: String) -> Self {
        Self { config, hostname }
    }
}

#[async_trait]
impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "network"
    }

    async fn collect(&self, meter: &Meter) -> Result<()> {
        let interfaces = collect_network_info(&self.config);
        let io_stats = collect_network_io_stats(&self.config);

        // ── 1. Информационная метрика (аналог node_network_info) ──
        let info_gauge = meter
            .f64_gauge("system.network.info")
            .with_description("Network interface metadata (always 1)")
            .with_unit("1")
            .build();

        for iface in &interfaces {
            // Объединяем IP адреса через запятую (Prometheus label может содержать строки)
            let ipv4_str = if iface.ipv4.is_empty() {
                "none".to_string()
            } else {
                iface.ipv4.join(",")
            };
            let ipv6_str = if iface.ipv6.is_empty() {
                "none".to_string()
            } else {
                iface.ipv6.join(",")
            };
            let speed_str = iface
                .speed_mbps
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let duplex_str = iface.duplex.clone().unwrap_or_else(|| "unknown".to_string());
            let mac_str = if iface.mac.is_empty() {
                "unknown".to_string()
            } else {
                iface.mac.clone()
            };

            let attrs = [
                KeyValue::new("host_name", self.hostname.clone()),
                KeyValue::new("interface", iface.name.clone()),
                KeyValue::new("mac", mac_str),
                KeyValue::new("speed_mbps", speed_str),
                KeyValue::new("duplex", duplex_str),
                KeyValue::new("ipv4", ipv4_str),
                KeyValue::new("ipv6", ipv6_str),
            ];

            info_gauge.record(1.0, &attrs);

            debug!(
                interface = %iface.name,
                mac = %iface.mac,
                speed = ?iface.speed_mbps,
                ipv4 = ?iface.ipv4,
                operstate = %iface.operstate,
                "Метрики сетевого интерфейса отправлены"
            );
        }

        // ── 2. Статус интерфейса (up=1, down=0) ──
        let up_gauge = meter
            .f64_gauge("system.network.up")
            .with_description("Network interface operational status (1=up, 0=down)")
            .with_unit("1")
            .build();

        for iface in &interfaces {
            let attrs = [
                KeyValue::new("host_name", self.hostname.clone()),
                KeyValue::new("interface", iface.name.clone()),
            ];
            // ✅ Теперь используем комбинированную проверку operstate + flags
            let value: f64 = if is_interface_up(&iface.operstate, iface.flags) { 1.0 } else { 0.0 };
            up_gauge.record(value, &attrs);
        }

        // ── 3. I/O статистика (cumulative counters) ──
        let rx_bytes_counter = meter
            .u64_counter("system.network.io.rx_bytes")
            .with_description("Total bytes received on interface")
            .with_unit("By")
            .build();

        let tx_bytes_counter = meter
            .u64_counter("system.network.io.tx_bytes")
            .with_description("Total bytes transmitted from interface")
            .with_unit("By")
            .build();

        let rx_packets_counter = meter
            .u64_counter("system.network.io.rx_packets")
            .with_description("Total packets received on interface")
            .build();

        let tx_packets_counter = meter
            .u64_counter("system.network.io.tx_packets")
            .with_description("Total packets transmitted from interface")
            .build();

        let rx_errors_counter = meter
            .u64_counter("system.network.io.rx_errors")
            .with_description("Total receive errors on interface")
            .build();

        let tx_errors_counter = meter
            .u64_counter("system.network.io.tx_errors")
            .with_description("Total transmit errors on interface")
            .build();

        let rx_dropped_counter = meter
            .u64_counter("system.network.io.rx_dropped")
            .with_description("Total packets dropped on receive")
            .build();

        let tx_dropped_counter = meter
            .u64_counter("system.network.io.tx_dropped")
            .with_description("Total packets dropped on transmit")
            .build();

        for (iface_name, io) in &io_stats {
            let attrs = [
                KeyValue::new("host_name", self.hostname.clone()),
                KeyValue::new("interface", iface_name.clone()),
            ];

            rx_bytes_counter.add(io.rx_bytes, &attrs);
            tx_bytes_counter.add(io.tx_bytes, &attrs);
            rx_packets_counter.add(io.rx_packets, &attrs);
            tx_packets_counter.add(io.tx_packets, &attrs);
            rx_errors_counter.add(io.rx_errors, &attrs);
            tx_errors_counter.add(io.tx_errors, &attrs);
            rx_dropped_counter.add(io.rx_dropped, &attrs);
            tx_dropped_counter.add(io.tx_dropped, &attrs);
        }

        Ok(())
    }
}
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

    // 1. Экспортёр OTLP over HTTP (теперь использует блокирующий reqwest под капотом)
    let exporter = MetricExporter::builder()
        .with_http()
        .with_endpoint(&config.otlp.endpoint)
        .with_timeout(Duration::from_secs(config.otlp.timeout_secs))
        .build()?;

    // 2. PeriodicReader принимает ТОЛЬКО exporter.
    // Runtime больше не передается — reader сам создаст std::thread.
    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(config.agent.interval_secs))
        .build();

    // 3. Resource создается через builder (API 0.32.x)
    let resource = Resource::builder()
        .with_attribute(KeyValue::new("service.name", "otlp-sys-agent"))
        .with_attribute(KeyValue::new("host.name", hostname))
        .build();

    // 4. Сборка MeterProvider
    let provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .build();

    Ok(provider)
}
</file>

<file path="otlp-sys-agent/tests/disk_test.rs">
// tests/disk_test.rs

use otlp_sys_agent::collectors::disk::{
    parse_proc_partitions, find_partitions, calculate_unallocated, should_skip_device,
};
use otlp_sys_agent::config::DiskConfig;
use std::collections::HashMap;

/// Реалистичный вывод /proc/partitions
fn mock_proc_partitions() -> &'static str {
    r#"major minor  #blocks  name

   8        0  976762584 sda
   8        1  974761984 sda1
   8        2    2000000 sda2
   8       16  488386584 sdb
   8       17  488386584 sdb1
 259        0 1000204886 nvme0n1
 259        1  512000000 nvme0n1p1
 259        2  488204886 nvme0n1p2
 253        0  500000000 dm-0
 253        1  400000000 dm-1
   7        0    4096000 loop0
 252        0   16777216 zram0
"#
}

#[test]
fn test_parse_proc_partitions_sizes() {
    let map = parse_proc_partitions(mock_proc_partitions());

    // sda: 976762584 blocks * 1024 = 1000204886016 bytes
    assert_eq!(map.get("sda"), Some(&(976762584u64 * 1024)));
    // sda1: 974761984 * 1024
    assert_eq!(map.get("sda1"), Some(&(974761984u64 * 1024)));
    // nvme0n1
    assert_eq!(map.get("nvme0n1"), Some(&(1000204886u64 * 1024)));
    // dm-0 тоже парсится
    assert_eq!(map.get("dm-0"), Some(&(500000000u64 * 1024)));
}

#[test]
fn test_parse_proc_partitions_count() {
    let map = parse_proc_partitions(mock_proc_partitions());
    // sda, sda1, sda2, sdb, sdb1, nvme0n1, nvme0n1p1, nvme0n1p2, dm-0, dm-1, loop0, zram0
    assert_eq!(map.len(), 12);
}

#[test]
fn test_parse_proc_partitions_empty() {
    let map = parse_proc_partitions("");
    assert!(map.is_empty());
}

#[test]
fn test_parse_proc_partitions_header_only() {
    let content = "major minor  #blocks  name\n\n";
    let map = parse_proc_partitions(content);
    assert!(map.is_empty());
}

// ─── find_partitions ───

#[test]
fn test_find_partitions_sata() {
    let map = parse_proc_partitions(mock_proc_partitions());
    let parts = find_partitions("sda", &map);

    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].0, "sda1");
    assert_eq!(parts[1].0, "sda2");
}

#[test]
fn test_find_partitions_nvme() {
    let map = parse_proc_partitions(mock_proc_partitions());
    let parts = find_partitions("nvme0n1", &map);

    // NVMe использует суффикс "p": nvme0n1p1, nvme0n1p2
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].0, "nvme0n1p1");
    assert_eq!(parts[1].0, "nvme0n1p2");
}

#[test]
fn test_find_partitions_no_partitions() {
    let mut empty_map = HashMap::new();
    empty_map.insert("sdc".to_string(), 1000000000u64);

    let parts = find_partitions("sdc", &empty_map);
    assert!(parts.is_empty());
}

#[test]
fn test_find_partitions_does_not_match_similar_names() {
    let mut map = HashMap::new();
    map.insert("sda".to_string(), 1000u64);
    map.insert("sda1".to_string(), 500u64);
    map.insert("sdaa".to_string(), 200u64);  // НЕ раздел sda!
    map.insert("sdab".to_string(), 300u64);  // НЕ раздел sda!

    let parts = find_partitions("sda", &map);
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].0, "sda1");
}

// ─── calculate_unallocated ───

#[test]
fn test_calculate_unallocated_with_free_space() {
    // Диск 1TB, разделы занимают 900GB
    let total = 1000 * 1024 * 1024 * 1024; // 1 TB
    let partitions = vec![
        ("sda1".to_string(), 500 * 1024 * 1024 * 1024),
        ("sda2".to_string(), 400 * 1024 * 1024 * 1024),
    ];

    let unallocated = calculate_unallocated(total, &partitions);
    assert_eq!(unallocated, 100 * 1024 * 1024 * 1024); // 100 GB свободно
}

#[test]
fn test_calculate_unallocated_fully_partitioned() {
    let total = 1000u64 * 1024 * 1024 * 1024;
    let partitions = vec![
        ("sda1".to_string(), total), // Весь диск занят одним разделом
    ];

    let unallocated = calculate_unallocated(total, &partitions);
    assert_eq!(unallocated, 0);
}

#[test]
fn test_calculate_unallocated_empty_disk() {
    let total = 1000u64 * 1024 * 1024 * 1024;
    let partitions: Vec<(String, u64)> = vec![];

    let unallocated = calculate_unallocated(total, &partitions);
    assert_eq!(unallocated, total); // Весь диск неразмечен
}

#[test]
fn test_calculate_unallocated_overflow_protection() {
    // Сумма разделов > размера диска (не должно паниковать)
    let total = 100u64;
    let partitions = vec![
        ("sda1".to_string(), 80u64),
        ("sda2".to_string(), 80u64), // В сумме 160 > 100
    ];

    let unallocated = calculate_unallocated(total, &partitions);
    assert_eq!(unallocated, 0); // saturating_sub защищает от underflow
}

// ─── should_skip_device ───

#[test]
fn test_skip_loop_devices() {
    let config = DiskConfig::default();
    assert!(should_skip_device("loop0", &config));
    assert!(should_skip_device("loop15", &config));
}

#[test]
fn test_skip_ram_devices() {
    let config = DiskConfig::default();
    assert!(should_skip_device("ram0", &config));
    assert!(should_skip_device("zram0", &config));
}

#[test]
fn test_skip_device_mapper_when_enabled() {
    let config = DiskConfig {
        ignore_device_mapper: true,
        ..Default::default()
    };
    assert!(should_skip_device("dm-0", &config));
    assert!(should_skip_device("dm-1", &config));
}

#[test]
fn test_keep_device_mapper_when_disabled() {
    let config = DiskConfig {
        ignore_device_mapper: false,
        ..Default::default()
    };
    assert!(!should_skip_device("dm-0", &config));
}

#[test]
fn test_keep_real_disks() {
    let config = DiskConfig::default();
    assert!(!should_skip_device("sda", &config));
    assert!(!should_skip_device("nvme0n1", &config));
    assert!(!should_skip_device("vda", &config));
}

#[test]
fn test_skip_custom_ignore_list() {
    let config = DiskConfig {
        ignore_devices: vec!["sr0".to_string(), "sdc".to_string()],
        ..Default::default()
    };
    assert!(should_skip_device("sr0", &config));
    assert!(should_skip_device("sdc", &config));
    assert!(!should_skip_device("sda", &config));
}
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

<file path="otlp-sys-agent/tests/network_test.rs">
// tests/network_test.rs

use otlp_sys_agent::collectors::network::{
    collect_network_info, is_interface_up, parse_duplex, parse_interface_flags, parse_mac,
    parse_operstate, parse_speed_mbps, parse_statistics, should_skip_interface
};
use otlp_sys_agent::config::NetworkConfig;
use std::collections::HashMap;

// ─── parse_mac ───

#[test]
fn test_parse_mac_normalizes() {
    assert_eq!(parse_mac("AA:BB:CC:DD:EE:FF\n"), "aa:bb:cc:dd:ee:ff");
    assert_eq!(parse_mac("00:11:22:33:44:55"), "00:11:22:33:44:55");
}

#[test]
fn test_parse_mac_empty() {
    assert_eq!(parse_mac(""), "");
}

// ─── parse_speed_mbps ───

#[test]
fn test_parse_speed_valid() {
    assert_eq!(parse_speed_mbps("1000"), Some(1000));
    assert_eq!(parse_speed_mbps("100\n"), Some(100));
    assert_eq!(parse_speed_mbps("2500"), Some(2500));
    assert_eq!(parse_speed_mbps("10000"), Some(10000)); // 10G
}

#[test]
fn test_parse_speed_invalid() {
    assert_eq!(parse_speed_mbps("-1"), None);
    assert_eq!(parse_speed_mbps("0"), None);
    assert_eq!(parse_speed_mbps("unknown"), None);
    assert_eq!(parse_speed_mbps("4294961"), None); // virtio magic
    assert_eq!(parse_speed_mbps(""), None);
}

// ─── parse_duplex ───

#[test]
fn test_parse_duplex() {
    assert_eq!(parse_duplex("full"), Some("full".to_string()));
    assert_eq!(parse_duplex("half"), Some("half".to_string()));
    assert_eq!(parse_duplex("unknown"), None);
    assert_eq!(parse_duplex(""), None);
}

// ─── parse_operstate ───

#[test]
fn test_parse_operstate() {
    assert_eq!(parse_operstate("up"), "up");
    assert_eq!(parse_operstate("down"), "down");
    assert_eq!(parse_operstate("unknown"), "unknown");
    assert_eq!(parse_operstate(""), "unknown");
}

// ─── parse_interface_flags ───

#[test]
fn test_parse_flags_with_prefix() {
    assert_eq!(parse_interface_flags("0x11091"), 0x11091);
}

#[test]
fn test_parse_flags_without_prefix() {
    assert_eq!(parse_interface_flags("11091"), 0x11091);
}

#[test]
fn test_parse_flags_with_whitespace() {
    assert_eq!(parse_interface_flags("  0x1091\n"), 0x1091);
}

#[test]
fn test_parse_flags_empty() {
    assert_eq!(parse_interface_flags(""), 0);
}

#[test]
fn test_parse_flags_invalid() {
    assert_eq!(parse_interface_flags("not_hex"), 0);
}

// ─── is_interface_up ───

#[test]
fn test_up_operstate_is_up() {
    assert!(is_interface_up("up", 0));
}

#[test]
fn test_down_operstate_is_down() {
    assert!(!is_interface_up("down", 0x11091));
}

#[test]
fn test_unknown_with_iff_up_is_up() {
    // PPP: operstate=unknown, но IFF_UP установлен
    // ppp0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP>
    // 0x1 (UP) | 0x10 (POINTOPOINT) | 0x80 (NOARP) | 0x1000 (MULTICAST) | 0x10000 (LOWER_UP)
    let flags = 0x11091;
    assert!(is_interface_up("unknown", flags));
}

#[test]
fn test_unknown_without_iff_up_is_down() {
    // Интерфейс выключен: operstate=unknown, IFF_UP не установлен
    // Только POINTOPOINT | NOARP | MULTICAST, без IFF_UP
    let flags = 0x11080;
    assert!(!is_interface_up("unknown", flags));
}

#[test]
fn test_unknown_with_only_iff_up() {
    // Только IFF_UP, без LOWER_UP (интерфейс поднят, но кабель не подключён)
    assert!(is_interface_up("unknown", 0x1));
}

#[test]
fn test_lowerlayerdown_state_checks_flags() {
    // operstate=lowerlayerdown → проверяем флаги
    let flags_up = 0x1; // IFF_UP
    assert!(is_interface_up("lowerlayerdown", flags_up));

    let flags_down = 0x0;
    assert!(!is_interface_up("lowerlayerdown", flags_down));
}

#[test]
fn test_zero_flags_is_down() {
    assert!(!is_interface_up("unknown", 0));
}

// ─── should_skip_interface ───

#[test]
fn test_skip_loopback() {
    let config = NetworkConfig::default();
    assert!(should_skip_interface("lo", &config));
}

#[test]
fn test_skip_docker_interfaces() {
    let config = NetworkConfig::default();
    assert!(should_skip_interface("docker0", &config));
    assert!(should_skip_interface("br-1234abcd", &config));
    assert!(should_skip_interface("veth1234567", &config));
}

#[test]
fn test_skip_wireguard() {
    let config = NetworkConfig::default();
    assert!(should_skip_interface("wg0", &config));
    assert!(should_skip_interface("wg-server", &config));
}

#[test]
fn test_keep_physical_interfaces() {
    let config = NetworkConfig::default();
    assert!(!should_skip_interface("eth0", &config));
    assert!(!should_skip_interface("enp3s0", &config));
    assert!(!should_skip_interface("eno1", &config));
    assert!(!should_skip_interface("wlan0", &config));
    assert!(!should_skip_interface("bond0", &config));
}

#[test]
fn test_skip_exact_match() {
    let config = NetworkConfig {
        ignore_exact: vec!["eth0".to_string(), "dummy0".to_string()],
        ..Default::default()
    };
    assert!(should_skip_interface("eth0", &config));
    assert!(should_skip_interface("dummy0", &config));
    assert!(!should_skip_interface("eth1", &config));
}

#[test]
fn test_skip_custom_prefix() {
    let config = NetworkConfig {
        ignore_interfaces: vec!["custom".to_string()],
        ..Default::default()
    };
    assert!(should_skip_interface("custom0", &config));
    assert!(should_skip_interface("customnet", &config));
    assert!(!should_skip_interface("eth0", &config));
}

// ─── parse_statistics ───

#[test]
fn test_parse_statistics_full() {
    let mut map = HashMap::new();
    map.insert("rx_bytes".to_string(), "1000000".to_string());
    map.insert("tx_bytes".to_string(), "2000000".to_string());
    map.insert("rx_packets".to_string(), "1000".to_string());
    map.insert("tx_packets".to_string(), "2000".to_string());
    map.insert("rx_errors".to_string(), "5".to_string());
    map.insert("tx_errors".to_string(), "3".to_string());
    map.insert("rx_dropped".to_string(), "1".to_string());
    map.insert("tx_dropped".to_string(), "2".to_string());

    let stats = parse_statistics(&map);
    assert_eq!(stats.rx_bytes, 1000000);
    assert_eq!(stats.tx_bytes, 2000000);
    assert_eq!(stats.rx_packets, 1000);
    assert_eq!(stats.tx_packets, 2000);
    assert_eq!(stats.rx_errors, 5);
    assert_eq!(stats.tx_errors, 3);
    assert_eq!(stats.rx_dropped, 1);
    assert_eq!(stats.tx_dropped, 2);
}

#[test]
fn test_parse_statistics_missing_fields() {
    let mut map = HashMap::new();
    map.insert("rx_bytes".to_string(), "500".to_string());
    // tx_bytes, packets и т.д. отсутствуют

    let stats = parse_statistics(&map);
    assert_eq!(stats.rx_bytes, 500);
    assert_eq!(stats.tx_bytes, 0);
    assert_eq!(stats.rx_packets, 0);
}

#[test]
fn test_parse_statistics_empty_map() {
    let map = HashMap::new();
    let stats = parse_statistics(&map);
    assert_eq!(stats.rx_bytes, 0);
    assert_eq!(stats.tx_bytes, 0);
}

// ─── collect_network_info (интеграционный) ───

#[test]
fn test_collect_network_info_integration() {
    let config = NetworkConfig {
        enabled: true,
        ignore_interfaces: vec!["lo".to_string()], // убираем loopback для чистоты
        ignore_exact: vec![],
        collect_ip: true,
        ..Default::default()
    };

    let interfaces = collect_network_info(&config);

    // На любой Linux-системе должен быть хотя бы один не-loopback интерфейс
    assert!(
        !interfaces.is_empty(),
        "Ожидается хотя бы один сетевой интерфейс"
    );

    // Проверяем, что loopback отфильтрован
    for iface in &interfaces {
        assert_ne!(iface.name, "lo", "Loopback должен быть отфильтрован");
        // MAC должен быть валидным (или пустым для виртуальных)
        if !iface.mac.is_empty() {
            assert!(
                iface.mac.contains(':'),
                "MAC {} не выглядит валидным",
                iface.mac
            );
        }
    }
}

#[test]
fn test_collect_network_info_without_ip() {
    let config = NetworkConfig {
        enabled: true,
        ignore_interfaces: vec!["lo".to_string()],
        ignore_exact: vec![],
        collect_ip: false,
        ..Default::default()
    };

    let interfaces = collect_network_info(&config);

    for iface in &interfaces {
        assert!(iface.ipv4.is_empty(), "IPv4 не должен собираться");
        assert!(iface.ipv6.is_empty(), "IPv6 не должен собираться");
    }
}

#[test]
fn test_collect_network_info_flags_populated() {
    let config = NetworkConfig {
        enabled: true,
        ignore_interfaces: vec!["lo".to_string()],
        ignore_exact: vec![],
        collect_ip: false,
        ..Default::default()
    };

    let interfaces = collect_network_info(&config);

    // Проверяем, что флаги прочитаны (не все нулевые для UP интерфейсов)
    for iface in &interfaces {
        if iface.operstate == "up" {
            // UP интерфейс должен иметь IFF_UP флаг
            assert!(
                iface.flags & 0x1 != 0,
                "Интерфейс {} в состоянии up, но IFF_UP не установлен (flags=0x{:x})",
                iface.name,
                iface.flags
            );
        }
    }
}
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

    #[serde(default)]
    pub filesystem: FilesystemConfig,

    #[serde(default)]
    pub disk: DiskConfig,

    #[serde(default)]
    pub network: NetworkConfig,
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

// DiskConfig:

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

// NetworkConfig:

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Префиксы интерфейсов для игнорирования
    #[serde(default = "default_ignore_interfaces")]
    pub ignore_interfaces: Vec<String>,
    /// Точные имена интерфейсов для игнорирования
    #[serde(default)]
    pub ignore_exact: Vec<String>,
    /// Собирать IP-адреса (требует getifaddrs)
    #[serde(default = "default_true")]
    pub collect_ip: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ignore_interfaces: default_ignore_interfaces(),
            ignore_exact: Vec::new(),
            collect_ip: true,
        }
    }
}

fn default_ignore_interfaces() -> Vec<String> {
    vec![
        "lo".to_string(),
        "veth".to_string(),
        "docker".to_string(),
        "br-".to_string(),
        "virbr".to_string(),
        "vnet".to_string(),
        "tun".to_string(),
        "tap".to_string(),
        "wg".to_string(),
        "cni".to_string(),
        "flannel".to_string(),
    ]
}

// FilesystemConfig:

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
  filesystem:
      enabled: true
      ignore_mount_points:
        - /proc
        - /sys
        - /dev
        - /run
        - /snap
      ignore_fs_types:
        - tmpfs
        - devtmpfs
        - squashfs
        - overlay
  disk:
      enabled: true
      ignore_device_mapper: true    # Игнорировать LVM (dm-0, dm-1)
      ignore_devices: []            # Пример: ["sr0"] для CD-ROM
      collect_io: true              # Собирать read/write counters
  network:
      enabled: true
      ignore_interfaces:
        - lo
        - veth
        - docker
        - br-
        - virbr
        - tun
        - tap
        - wg
      ignore_exact: []
      collect_ip: true
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


##  Пример PromQL запросов для Grafana для filesystem
```
# Общий объём диска (в GB)
system_filesystem_total_bytes{host_name="server-01", mountpoint="/"} / 1024/1024/1024

# Занято (в GB)
system_filesystem_used_bytes{host_name="server-01", mountpoint="/"} / 1024/1024/1024

# Свободно (в GB)
system_filesystem_free_bytes{host_name="server-01", mountpoint="/"} / 1024/1024/1024

# Резерв (неразмеченное место root)
system_filesystem_reserved_bytes{host_name="server-01"} / 1024/1024/1024

# Процент использования диска
100 * (system_filesystem_used_bytes / system_filesystem_total_bytes)

# Список всех серверов и их точек монтирования
group by (host_name, mountpoint, fstype) (system_filesystem_total_bytes)
```

##  Пример PromQL запросов для Grafana для disk
```
# Неразмеченное место на дисках (GB)
system_disk_unallocated_bytes / 1024/1024/1024

# Скорость чтения с диска (MB/s)
rate(system_disk_io_read_bytes[5m]) / 1024/1024

# Скорость записи на диск (MB/s)
rate(system_disk_io_write_bytes[5m]) / 1024/1024

# Утилизация диска (% времени занят)
rate(system_disk_io_io_time_ms[5m]) / 10

# IOPS (операций в секунду)
rate(system_disk_io_reads_completed[5m]) + rate(system_disk_io_writes_completed[5m])
```

##  Пример PromQL запросов для Grafana для Network
```
# Скорость RX на выбранном uplink-интерфейсе (bit/s)
rate(system_network_io_rx_bytes{interface="$interface"}[1m]) * 8

# Скорость TX
rate(system_network_io_tx_bytes{interface="$interface"}[1m]) * 8

# Процент использования линка (если скорость известна)
(
  rate(system_network_io_rx_bytes{interface="$interface"}[1m]) * 8
  / on(interface) group_left() 
  (system_network_info * 1000000)  # speed_mbps -> bps
) * 100

# Ошибки на интерфейсе (rate в секунду)
rate(system_network_io_rx_errors{interface="$interface"}[5m])
+ rate(system_network_io_tx_errors{interface="$interface"}[5m])

# Drops (сигнал перегрузки буферов)
rate(system_network_io_rx_dropped{interface="$interface"}[5m])

# Таблица всех серверов и их uplink-интерфейсов
system_network_info{speed_mbps!="unknown"}
```
</file>

<file path="otlp-sys-agent/src/collectors/mod.rs">
pub mod iptables;
pub mod temperature;
pub mod process;
pub mod filesystem;
pub mod disk;
pub mod network;
pub mod system;
</file>

<file path="otlp-sys-agent/src/main.rs">
use anyhow::Result;
use opentelemetry::metrics::MeterProvider;
use otlp_sys_agent::collector::CollectorRegistry;
use otlp_sys_agent::collectors::iptables::IptablesCollector;
use otlp_sys_agent::collectors::process::ProcessCollector;
use otlp_sys_agent::collectors::temperature::SysfsTempCollector;
use otlp_sys_agent::collectors::filesystem::FilesystemCollector;
use otlp_sys_agent::collectors::disk::DiskCollector;
use otlp_sys_agent::collectors::network::NetworkCollector;
use otlp_sys_agent::collectors::system::SystemCollector;

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

    // Регистрация filesystem коллектора
    if cfg.collectors.filesystem.enabled {
        registry.register(FilesystemCollector::new(
            cfg.collectors.filesystem.clone(),
            hostname.clone(),
        ));
    }

    // Регистрация Disk коллектора
    if cfg.collectors.disk.enabled {
        registry.register(DiskCollector::new(
            cfg.collectors.disk.clone(),
            hostname.clone(),
        ));
    }

    // Регистрация Network коллектора
    if cfg.collectors.network.enabled {
        registry.register(NetworkCollector::new(
            cfg.collectors.network.clone(),
            hostname.clone(),
        ));
    }

    // Регистрация System коллектора
    registry.register(SystemCollector::new(hostname.clone()));

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
      # - gh release create {{.RAW_TAG}} {{.DIST_DIR}}/{{.APP_NAME}}-release.tar.gz --title "Release {{.RAW_TAG}}" --notes "Автоматический релиз {{.RAW_TAG}}" --clobber
      - gh release create {{.RAW_TAG}} {{.DIST_DIR}}/{{.APP_NAME}}-release.tar.gz --title "Release {{.RAW_TAG}}" --notes "Автоматический релиз {{.RAW_TAG}}"
</file>

<file path="otlp-sys-agent/Cargo.toml">
[package]
name = "otlp-sys-agent"
version = "0.1.8"
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
opentelemetry-otlp = { version = "0.32.0", features = ["http-proto", "reqwest-blocking-client", "reqwest-rustls", "metrics"] }

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

nix = { version = "0.31.3", features = ["fs", "net"] }

[profile.release]
opt-level = "z"     # Оптимизация по размеру бинарника
lto = true          # Link-Time Optimization для максимальной производительности
codegen-units = 1   # Максимальная оптимизация при сборке
panic = "abort"     # Убирает стэктрейсы из бинарника (уменьшает размер)
strip = true        # Автоматически вырезает отладочные символы

[dev-dependencies]
tempfile = "3.10"
</file>

</files>
