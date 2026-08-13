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
