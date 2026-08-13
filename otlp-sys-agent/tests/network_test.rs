// tests/network_test.rs

use otlp_sys_agent::collectors::network::{
    collect_network_info, is_interface_up, parse_duplex, parse_interface_flags, parse_mac,
    parse_operstate, parse_speed_mbps, parse_statistics, should_skip_interface, NetworkIoStats,
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
