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
            let value: f64 = if iface.operstate == "up" { 1.0 } else { 0.0 };
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
