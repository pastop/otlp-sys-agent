use crate::collector::Collector;
use crate::config::NetworkConfig;
use anyhow::Result;
use async_trait::async_trait;
use nix::ifaddrs::getifaddrs;
use opentelemetry::metrics::{Counter, Gauge, Meter};
use opentelemetry::KeyValue;
use std::collections::HashMap;
use std::fs;
use std::net::Ipv6Addr;
use std::path::Path;
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct NetworkInterfaceInfo {
    pub name: String,
    pub mac: String,
    pub speed_mbps: Option<u64>,
    pub duplex: Option<String>,
    pub operstate: String,
    pub flags: u32,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
}

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

pub fn parse_mac(raw: &str) -> String {
    raw.trim().to_lowercase()
}

pub fn parse_speed_mbps(raw: &str) -> Option<u64> {
    let s = raw.trim();
    let v = s.parse::<i64>().ok()?;
    if v <= 0 || v == 4294961 {
        return None;
    }
    Some(v as u64)
}

pub fn parse_duplex(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s == "unknown" {
        None
    } else {
        Some(s.to_string())
    }
}

pub fn parse_operstate(raw: &str) -> String {
    let s = raw.trim();
    if s.is_empty() {
        "unknown".to_string()
    } else {
        s.to_string()
    }
}

pub fn parse_interface_flags(raw: &str) -> u32 {
    let s = raw.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(s, 16).unwrap_or(0)
}

pub fn is_interface_up(operstate: &str, flags: u32) -> bool {
    match operstate {
        "up" => true,
        "down" => false,
        _ => (flags & 0x1) != 0,
    }
}

pub fn should_skip_interface(name: &str, config: &NetworkConfig) -> bool {
    if config.ignore_exact.contains(&name.to_string()) {
        return true;
    }
    for prefix in &config.ignore_interfaces {
        if name.starts_with(prefix) || name == prefix {
            return true;
        }
    }
    false
}

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

fn read_sys_str(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

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
            if let Some(ipv4) = addr.as_sockaddr_in() {
                let ip = ipv4.ip();
                if !ip.is_link_local() {
                    entry.0.push(ip.to_string());
                }
            } else if let Some(ipv6) = addr.as_sockaddr_in6() {
                let ip = ipv6.ip();
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

        let mac = read_sys_str(&iface_path.join("address"))
            .map(|s| parse_mac(&s))
            .unwrap_or_default();

        let speed_mbps = read_sys_str(&iface_path.join("speed"))
            .and_then(|s| parse_speed_mbps(&s));

        let duplex = read_sys_str(&iface_path.join("duplex"))
            .and_then(|s| parse_duplex(&s));

        let operstate = read_sys_str(&iface_path.join("operstate"))
            .map(|s| parse_operstate(&s))
            .unwrap_or_else(|| "unknown".to_string());

        let flags = read_sys_str(&iface_path.join("flags"))
            .map(|s| parse_interface_flags(&s))
            .unwrap_or(0);

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
            flags,
            ipv4,
            ipv6,
        });
    }

    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    interfaces
}

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

pub struct NetworkMetrics {
    info: Gauge<f64>,
    up: Gauge<f64>,
    rx_bytes: Counter<u64>,
    tx_bytes: Counter<u64>,
    rx_packets: Counter<u64>,
    tx_packets: Counter<u64>,
    rx_errors: Counter<u64>,
    tx_errors: Counter<u64>,
    rx_dropped: Counter<u64>,
    tx_dropped: Counter<u64>,
}

impl NetworkMetrics {
    pub fn new(meter: &Meter) -> Self {
        Self {
            info: meter
                .f64_gauge("system.network.info")
                .with_description("Network interface metadata (always 1)")
                .with_unit("1")
                .build(),
            up: meter
                .f64_gauge("system.network.up")
                .with_description("Network interface operational status (1=up, 0=down)")
                .with_unit("1")
                .build(),
            rx_bytes: meter
                .u64_counter("system.network.io.rx_bytes")
                .with_description("Total bytes received on interface")
                .with_unit("By")
                .build(),
            tx_bytes: meter
                .u64_counter("system.network.io.tx_bytes")
                .with_description("Total bytes transmitted from interface")
                .with_unit("By")
                .build(),
            rx_packets: meter
                .u64_counter("system.network.io.rx_packets")
                .with_description("Total packets received on interface")
                .build(),
            tx_packets: meter
                .u64_counter("system.network.io.tx_packets")
                .with_description("Total packets transmitted from interface")
                .build(),
            rx_errors: meter
                .u64_counter("system.network.io.rx_errors")
                .with_description("Total receive errors on interface")
                .build(),
            tx_errors: meter
                .u64_counter("system.network.io.tx_errors")
                .with_description("Total transmit errors on interface")
                .build(),
            rx_dropped: meter
                .u64_counter("system.network.io.rx_dropped")
                .with_description("Total packets dropped on receive")
                .build(),
            tx_dropped: meter
                .u64_counter("system.network.io.tx_dropped")
                .with_description("Total packets dropped on transmit")
                .build(),
        }
    }
}

pub struct NetworkCollector {
    hostname: String,
    config: NetworkConfig,
    metrics: NetworkMetrics,
}

impl NetworkCollector {
    pub fn new(config: NetworkConfig, hostname: String, meter: &Meter) -> Self {
        Self {
            config,
            hostname,
            metrics: NetworkMetrics::new(meter),
        }
    }
}

#[async_trait]
impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "network"
    }

    async fn collect(&self, _meter: &Meter) -> Result<()> {
        let interfaces = collect_network_info(&self.config);
        let io_stats = collect_network_io_stats(&self.config);

        for iface in &interfaces {
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

            self.metrics.info.record(1.0, &attrs);

            debug!(
                interface = %iface.name,
                mac = %iface.mac,
                speed = ?iface.speed_mbps,
                ipv4 = ?iface.ipv4,
                operstate = %iface.operstate,
                "Метрики сетевого интерфейса отправлены"
            );
        }

        for iface in &interfaces {
            let attrs = [
                KeyValue::new("host_name", self.hostname.clone()),
                KeyValue::new("interface", iface.name.clone()),
            ];
            let value: f64 = if is_interface_up(&iface.operstate, iface.flags) { 1.0 } else { 0.0 };
            self.metrics.up.record(value, &attrs);
        }

        for (iface_name, io) in &io_stats {
            let attrs = [
                KeyValue::new("host_name", self.hostname.clone()),
                KeyValue::new("interface", iface_name.clone()),
            ];

            self.metrics.rx_bytes.add(io.rx_bytes, &attrs);
            self.metrics.tx_bytes.add(io.tx_bytes, &attrs);
            self.metrics.rx_packets.add(io.rx_packets, &attrs);
            self.metrics.tx_packets.add(io.tx_packets, &attrs);
            self.metrics.rx_errors.add(io.rx_errors, &attrs);
            self.metrics.tx_errors.add(io.tx_errors, &attrs);
            self.metrics.rx_dropped.add(io.rx_dropped, &attrs);
            self.metrics.tx_dropped.add(io.tx_dropped, &attrs);
        }

        Ok(())
    }
}
