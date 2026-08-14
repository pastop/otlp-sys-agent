// src/collectors/filesystem.rs

use crate::collector::Collector;
use crate::config::FilesystemConfig;
use anyhow::Result;
use async_trait::async_trait;
use nix::sys::statvfs::{statvfs, FsFlags};
use opentelemetry::metrics::Meter;
use opentelemetry::KeyValue;
use std::collections::HashSet;
use std::fs;
use std::os::linux::fs::MetadataExt;
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

/// Типы ФС, которые считаем реальным хранилищем,
/// даже если device не начинается с /dev/ (типично для LXC: ZFS, NFS и т.д.)
const REAL_FS_TYPES: &[&str] = &[
    "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "reiserfs",
    "jfs", "vfat", "exfat", "ntfs", "ntfs3", "nfs", "nfs4", "cifs", "erofs",
];

/// Определяет, является ли запись реальным хранилищем.
/// В LXC device может быть "rpool/data/subvol-102-disk-0" (ZFS) или "overlay".
pub fn is_real_storage(device: &str, fs_type: &str, include_overlay: bool) -> bool {
    if device.starts_with("/dev/") {
        return true;
    }
    if REAL_FS_TYPES.contains(&fs_type) {
        return true;
    }
    include_overlay && fs_type == "overlay"
}

/// Парсинг /proc/mounts БЕЗ фильтрации (все валидные строки)
pub fn parse_proc_mounts_all(content: &str) -> Vec<MountEntry> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        entries.push(MountEntry {
            device: parts[0].to_string(),
            mount_point: parts[1].to_string(),
            fs_type: parts[2].to_string(),
        });
    }
    entries
}

/// Прежняя функция (обратная совместимость тестов): только /dev/*
pub fn parse_proc_mounts(content: &str) -> Vec<MountEntry> {
    parse_proc_mounts_all(content)
        .into_iter()
        .filter(|e| e.device.starts_with("/dev/"))
        .collect()
}

/// Полный сбор метрик: парсинг + фильтрация по config + statvfs
pub fn collect_fs_metrics(config: &FilesystemConfig) -> Vec<FsMetrics> {
    let mut metrics = Vec::new();
    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
    let entries = parse_proc_mounts_all(&mounts);
    let mut seen_devs: HashSet<u64> = HashSet::new();

    for entry in entries {
        // Фильтр: реальное хранилище (включая ZFS/overlay/NFS в LXC)
        if !is_real_storage(&entry.device, &entry.fs_type, config.include_overlay) {
            continue;
        }

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

        // Дедупликация bind-mount'ов одной ФС по st_dev,
        // чтобы sum by (host_name) в дашборде не задваивал объёмы
        if let Ok(meta) = fs::metadata(&entry.mount_point) {
            if !seen_devs.insert(meta.st_dev()) {
                continue;
            }
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
