use crate::collector::Collector;
use crate::config::DiskConfig;
use anyhow::Result;
use async_trait::async_trait;
use opentelemetry::metrics::{Counter, Gauge, Meter};
use opentelemetry::KeyValue;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct DiskInfo {
    pub device: String,
    pub model: String,
    pub total_bytes: u64,
    pub rotational: bool,
    pub removable: bool,
    pub partitions: Vec<(String, u64)>,
    pub unallocated_bytes: u64,
}

#[derive(Debug, Clone, Default, Copy)]
pub struct DiskIoStats {
    pub reads_completed: u64,
    pub read_bytes: u64,
    pub writes_completed: u64,
    pub write_bytes: u64,
    pub io_time_ms: u64,
    pub io_in_progress: u64,
}

#[derive(Debug, Clone, Default, Copy)]
struct DiskIoPrevState {
    reads_completed: u64,
    read_sectors: u64,
    writes_completed: u64,
    write_sectors: u64,
    io_time_ms: u64,
}

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

pub fn calculate_unallocated(total_bytes: u64, partitions: &[(String, u64)]) -> u64 {
    let allocated: u64 = partitions.iter().map(|(_, size)| size).sum();
    total_bytes.saturating_sub(allocated)
}

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

fn read_proc_partitions() -> HashMap<String, u64> {
    match fs::read_to_string("/proc/partitions") {
        Ok(content) => parse_proc_partitions(&content),
        Err(_) => HashMap::new(),
    }
}

fn read_sys_u64(path: &Path) -> Option<u64> {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
}

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

        let total_bytes = match read_sys_u64(&dev_path.join("size")) {
            Some(sectors) => sectors * 512,
            None => continue,
        };

        if total_bytes == 0 {
            continue;
        }

        let model = fs::read_to_string(dev_path.join("device/model"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| {
                fs::read_to_string(dev_path.join("model"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "unknown".to_string())
            });

        let rotational = read_sys_u64(&dev_path.join("queue/rotational"))
            .map(|v| v == 1)
            .unwrap_or(false);

        let removable = read_sys_u64(&dev_path.join("removable"))
            .map(|v| v == 1)
            .unwrap_or(false);

        let disk_partitions = find_partitions(&device_name, &partitions_map);
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

pub fn collect_disk_io_stats(config: &DiskConfig) -> HashMap<String, DiskIoStats> {
    let mut stats = HashMap::new();
    let sys_block_path = Path::new("/sys/block");

    let entries = match fs::read_dir(sys_block_path) {
        Ok(e) => e,
        Err(_) => return stats,
    };

    for entry in entries.flatten() {
        let device_name = entry.file_name().to_string_lossy().to_string();

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

pub struct DiskMetrics {
    total_bytes: Gauge<u64>,
    unallocated_bytes: Gauge<u64>,
    partition_size_bytes: Gauge<u64>,
    read_bytes: Counter<u64>,
    write_bytes: Counter<u64>,
    reads_completed: Counter<u64>,
    writes_completed: Counter<u64>,
    io_time_ms: Counter<u64>,
    io_in_progress: Gauge<u64>,
}

impl DiskMetrics {
    pub fn new(meter: &Meter) -> Self {
        Self {
            total_bytes: meter
                .u64_gauge("system.disk.total_bytes")
                .with_description("Total size of physical disk in bytes")
                .with_unit("By")
                .build(),
            unallocated_bytes: meter
                .u64_gauge("system.disk.unallocated_bytes")
                .with_description("Unallocated (free) space on physical disk")
                .with_unit("By")
                .build(),
            partition_size_bytes: meter
                .u64_gauge("system.disk.partition_size_bytes")
                .with_description("Size of disk partition in bytes")
                .with_unit("By")
                .build(),
            read_bytes: meter
                .u64_counter("system.disk.io.read_bytes")
                .with_description("Bytes read from disk")
                .with_unit("By")
                .build(),
            write_bytes: meter
                .u64_counter("system.disk.io.write_bytes")
                .with_description("Bytes written to disk")
                .with_unit("By")
                .build(),
            reads_completed: meter
                .u64_counter("system.disk.io.reads_completed")
                .with_description("Number of completed read operations")
                .build(),
            writes_completed: meter
                .u64_counter("system.disk.io.writes_completed")
                .with_description("Number of completed write operations")
                .build(),
            io_time_ms: meter
                .u64_counter("system.disk.io.io_time_ms")
                .with_description("Time spent doing I/Os in milliseconds")
                .with_unit("ms")
                .build(),
            io_in_progress: meter
                .u64_gauge("system.disk.io.in_progress")
                .with_description("Number of I/Os currently in progress")
                .build(),
        }
    }
}

pub struct DiskCollector {
    hostname: String,
    config: DiskConfig,
    prev_io: Mutex<HashMap<String, DiskIoPrevState>>,
    metrics: DiskMetrics,
}

impl DiskCollector {
    pub fn new(config: DiskConfig, hostname: String, meter: &Meter) -> Self {
        Self {
            config,
            hostname,
            prev_io: Mutex::new(HashMap::new()),
            metrics: DiskMetrics::new(meter),
        }
    }
}

#[async_trait]
impl Collector for DiskCollector {
    fn name(&self) -> &'static str {
        "disk"
    }

    async fn collect(&self, _meter: &Meter) -> Result<()> {
        let disks = collect_disk_info(&self.config);

        for disk in &disks {
            let base_attrs = [
                KeyValue::new("host_name", self.hostname.clone()),
                KeyValue::new("device", disk.device.clone()),
                KeyValue::new("model", disk.model.clone()),
                KeyValue::new("rotational", disk.rotational),
                KeyValue::new("removable", disk.removable),
            ];

            self.metrics.total_bytes.record(disk.total_bytes, &base_attrs);
            self.metrics.unallocated_bytes.record(disk.unallocated_bytes, &base_attrs);

            for (part_name, part_size) in &disk.partitions {
                let part_attrs = [
                    KeyValue::new("host_name", self.hostname.clone()),
                    KeyValue::new("device", disk.device.clone()),
                    KeyValue::new("partition", part_name.clone()),
                ];
                self.metrics.partition_size_bytes.record(*part_size, &part_attrs);
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

        if !self.config.collect_io {
            return Ok(());
        }

        let io_stats = collect_disk_io_stats(&self.config);
        let mut prev_map = self.prev_io.lock().unwrap();
        let mut next_map = HashMap::new();

        for (device, io) in &io_stats {
            let attrs = [
                KeyValue::new("host_name", self.hostname.clone()),
                KeyValue::new("device", device.clone()),
            ];

            let cur_read_sectors = io.read_bytes / 512;
            let cur_write_sectors = io.write_bytes / 512;

            if let Some(prev) = prev_map.get(device) {
                let delta_read_bytes = cur_read_sectors.saturating_sub(prev.read_sectors) * 512;
                let delta_write_bytes = cur_write_sectors.saturating_sub(prev.write_sectors) * 512;
                let delta_reads = io.reads_completed.saturating_sub(prev.reads_completed);
                let delta_writes = io.writes_completed.saturating_sub(prev.writes_completed);
                let delta_io_time = io.io_time_ms.saturating_sub(prev.io_time_ms);

                self.metrics.read_bytes.add(delta_read_bytes, &attrs);
                self.metrics.write_bytes.add(delta_write_bytes, &attrs);
                self.metrics.reads_completed.add(delta_reads, &attrs);
                self.metrics.writes_completed.add(delta_writes, &attrs);
                self.metrics.io_time_ms.add(delta_io_time, &attrs);
            }

            self.metrics.io_in_progress.record(io.io_in_progress, &attrs);

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
