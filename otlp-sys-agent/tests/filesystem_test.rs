// tests/filesystem_test.rs

use otlp_sys_agent::collectors::filesystem::{
    collect_fs_metrics, is_real_storage, parse_proc_mounts, parse_proc_mounts_all,
};
use otlp_sys_agent::config::FilesystemConfig;

/// Реалистичный вывод /proc/mounts (обычный хост)
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

/// Типичный /proc/mounts LXC-контейнера (Proxmox, ZFS-бэкенд)
fn mock_lxc_proc_mounts() -> &'static str {
    r#"rpool/data/subvol-102-disk-0 / zfs rw,relatime,xattr,noacl 0 0
overlay / overlay rw,relatime,lowerdir=/l1,upperdir=/u1,workdir=/w1 0 0
none /dev tmpfs rw,relatime,mode=755 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
"#
}

// ─── parse_proc_mounts (старое поведение, /dev/* only) ───

#[test]
fn test_parse_proc_mounts_filters_real_devices() {
    let entries = parse_proc_mounts(mock_proc_mounts());
    // sda1, sda2, nvme0n1p1, sdb1, mapper/vg-lv
    assert_eq!(entries.len(), 5);
}

#[test]
fn test_parse_proc_mounts_correct_fields() {
    let entries = parse_proc_mounts(mock_proc_mounts());
    let root = &entries[0];
    assert_eq!(root.device, "/dev/sda1");
    assert_eq!(root.mount_point, "/");
    assert_eq!(root.fs_type, "ext4");

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
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].device, "/dev/sda2");
}

// ─── LXC / ZFS: демонстрация бага и нового фильтра ───

#[test]
fn test_lxc_old_filter_loses_everything() {
    // Старый фильтр /dev/* не находил НИЧЕГО в LXC — это и был баг
    let entries = parse_proc_mounts(mock_lxc_proc_mounts());
    assert_eq!(entries.len(), 0);
}

#[test]
fn test_lxc_parse_all_entries() {
    let entries = parse_proc_mounts_all(mock_lxc_proc_mounts());
    assert_eq!(entries.len(), 5);
    assert_eq!(entries[0].device, "rpool/data/subvol-102-disk-0");
    assert_eq!(entries[0].fs_type, "zfs");
}

#[test]
fn test_lxc_new_filter_finds_zfs() {
    let entries = parse_proc_mounts_all(mock_lxc_proc_mounts());
    let real: Vec<_> = entries
        .iter()
        .filter(|e| is_real_storage(&e.device, &e.fs_type, false))
        .collect();
    // Только ZFS-датасет (overlay выключен, tmpfs/proc/sysfs не реальное хранилище)
    assert_eq!(real.len(), 1);
    assert_eq!(real[0].fs_type, "zfs");
}

#[test]
fn test_lxc_new_filter_with_overlay() {
    let entries = parse_proc_mounts_all(mock_lxc_proc_mounts());
    let real: Vec<_> = entries
        .iter()
        .filter(|e| is_real_storage(&e.device, &e.fs_type, true))
        .collect();
    // ZFS + overlay
    assert_eq!(real.len(), 2);
}

// ─── is_real_storage ───

#[test]
fn test_is_real_storage() {
    // Классические блочные устройства
    assert!(is_real_storage("/dev/sda1", "ext4", false));
    assert!(is_real_storage("/dev/mapper/pve-vm--100--disk--1", "ext4", false));
    // ZFS-датасет в LXC (device без /dev/)
    assert!(is_real_storage("rpool/data/subvol-102-disk-0", "zfs", false));
    // overlay — только при явном включении
    assert!(!is_real_storage("overlay", "overlay", false));
    assert!(is_real_storage("overlay", "overlay", true));
    // Псевдо-ФС никогда
    assert!(!is_real_storage("proc", "proc", false));
    assert!(!is_real_storage("tmpfs", "tmpfs", false));
    assert!(!is_real_storage("none", "cgroup2", false));
    assert!(!is_real_storage("sysfs", "sysfs", false));
}

// ─── collect_fs_metrics (интеграционные) ───

#[test]
fn test_collect_fs_metrics_integration() {
    let config = FilesystemConfig {
        enabled: true,
        ignore_mount_points: vec![],
        ignore_fs_types: vec![],
        include_overlay: false,
    };

    let metrics = collect_fs_metrics(&config);

    assert!(
        !metrics.is_empty(),
        "Ожидается хотя бы одна файловая система"
    );

    let root_fs = metrics.iter().find(|m| m.mount_point == "/");
    if let Some(root) = root_fs {
        assert!(root.total_bytes > 0, "Общий объём корня должен быть > 0");
        assert!(root.used_bytes <= root.total_bytes, "Занято <= Общего");
        assert!(root.inodes_total > 0, "Inodes total > 0");
    }
}

#[test]
fn test_collect_fs_metrics_with_config_filters() {
    let config = FilesystemConfig {
        enabled: true,
        ignore_mount_points: vec!["/mnt".to_string()],
        ignore_fs_types: vec!["xfs".to_string()],
        include_overlay: false,
    };

    let metrics = collect_fs_metrics(&config);

    for m in &metrics {
        assert!(
            !m.mount_point.starts_with("/mnt"),
            "Точка /mnt должна быть отфильтрована"
        );
        assert!(m.fs_type != "xfs", "ФС типа xfs должна быть отфильтрована");
    }
}
