// tests/network_test.rs

use otlp_sys_agent::collectors::network::{
    collect_network_info, parse_duplex, parse_mac, parse_operstate, parse_speed_mbps,
    parse_statistics, should_skip_interface, NetworkIoStats,
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
    };

    let interfaces = collect_network_info(&config);

    // На любой Linux-системе должен быть хотя бы один не-loopback интерфейс
    // (даже если это виртуальный)
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
    };

    let interfaces = collect_network_info(&config);

    for iface in &interfaces {
        assert!(iface.ipv4.is_empty(), "IPv4 не должен собираться");
        assert!(iface.ipv6.is_empty(), "IPv6 не должен собираться");
    }
}
