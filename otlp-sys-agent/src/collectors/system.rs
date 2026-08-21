use crate::collector::Collector;
use anyhow::Result;
use async_trait::async_trait;
use opentelemetry::metrics::{Gauge, Meter};
use opentelemetry::KeyValue;
use std::collections::HashMap;
use std::fs;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct CpuInfo {
    pub model: String,
    pub cores: u64,
    pub threads: u64,
}

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
    pub fn total(&self) -> u64 {
        self.user + self.nice + self.system + self.idle
            + self.iowait + self.irq + self.softirq + self.steal
    }

    pub fn busy(&self) -> u64 {
        self.user + self.nice + self.system + self.irq + self.softirq + self.steal
    }
}

#[derive(Debug, Clone)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub buffers_bytes: u64,
    pub cached_bytes: u64,
}

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

pub struct SystemMetrics {
    cpu_info: Gauge<f64>,
    cpu_usage: Gauge<f64>,
    mem_total: Gauge<u64>,
    mem_used: Gauge<u64>,
    mem_available: Gauge<u64>,
    mem_free: Gauge<u64>,
}

impl SystemMetrics {
    pub fn new(meter: &Meter) -> Self {
        Self {
            cpu_info: meter
                .f64_gauge("system.cpu.info")
                .with_description("CPU metadata (always 1)")
                .build(),
            cpu_usage: meter
                .f64_gauge("system.cpu.usage")
                .with_description("CPU usage percentage (0-100)")
                .with_unit("%")
                .build(),
            mem_total: meter
                .u64_gauge("system.memory.total_bytes")
                .with_description("Total system memory in bytes")
                .with_unit("By")
                .build(),
            mem_used: meter
                .u64_gauge("system.memory.used_bytes")
                .with_description("Used system memory in bytes")
                .with_unit("By")
                .build(),
            mem_available: meter
                .u64_gauge("system.memory.available_bytes")
                .with_description("Available system memory in bytes")
                .with_unit("By")
                .build(),
            mem_free: meter
                .u64_gauge("system.memory.free_bytes")
                .with_description("Free system memory in bytes")
                .with_unit("By")
                .build(),
        }
    }
}

pub struct SystemCollector {
    hostname: String,
    prev_cpu_stat: Mutex<CpuStatState>,
    metrics: SystemMetrics,
}

impl SystemCollector {
    pub fn new(hostname: String, meter: &Meter) -> Self {
        Self {
            hostname,
            prev_cpu_stat: Mutex::new(CpuStatState::default()),
            metrics: SystemMetrics::new(meter),
        }
    }
}

#[async_trait]
impl Collector for SystemCollector {
    fn name(&self) -> &'static str {
        "system"
    }

    async fn collect(&self, _meter: &Meter) -> Result<()> {
        let base_attrs = [KeyValue::new("host_name", self.hostname.clone())];

        // CPU Info
        let cpuinfo_content = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let cpu_info = parse_cpuinfo(&cpuinfo_content);

        let cpu_info_attrs = [
            KeyValue::new("host_name", self.hostname.clone()),
            KeyValue::new("cpu_model", cpu_info.model.clone()),
            KeyValue::new("cpu_threads", cpu_info.threads.to_string()),
        ];
        self.metrics.cpu_info.record(1.0, &cpu_info_attrs);

        // CPU Usage
        let stat_content = fs::read_to_string("/proc/stat").unwrap_or_default();
        let cur_stat = parse_proc_stat(&stat_content);

        let mut prev_stat = self.prev_cpu_stat.lock().unwrap();
        let usage = calculate_cpu_usage(&prev_stat, &cur_stat);
        self.metrics.cpu_usage.record(usage, &base_attrs);
        *prev_stat = cur_stat;

        // Memory
        let meminfo_content = fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let mem = parse_meminfo(&meminfo_content);

        self.metrics.mem_total.record(mem.total_bytes, &base_attrs);
        self.metrics.mem_used.record(mem.used_bytes, &base_attrs);
        self.metrics.mem_available.record(mem.available_bytes, &base_attrs);
        self.metrics.mem_free.record(mem.free_bytes, &base_attrs);

        Ok(())
    }
}
