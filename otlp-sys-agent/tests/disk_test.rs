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
    let map = parse_proc_partitions(mock_proc_partitions());
    // sdb имеет только sdb1, но проверим диск без разделов
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
