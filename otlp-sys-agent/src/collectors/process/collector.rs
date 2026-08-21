
use anyhow::Result;
use async_trait::async_trait;
use opentelemetry::{
    metrics::{Counter, Gauge, Meter},
    KeyValue,
};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use crate::collector::Collector;
use crate::collectors::process::procfs::ProcFsReader;

#[derive(Default, Clone, Copy)]
struct ProcessLastState {
    utime_ticks: u64,
    stime_ticks: u64,
    read_bytes: u64,
    write_bytes: u64,
    syscr: u64,
    syscw: u64,
}

/// Вынес инструменты метрик
pub struct ProcessMetrics {
    rss_gauge: Gauge<u64>,
    vsize_gauge: Gauge<u64>,
    user_cpu_counter: Counter<u64>,
    sys_cpu_counter: Counter<u64>,
    threads_gauge: Gauge<u64>,
    fds_gauge: Gauge<u64>,
    io_read_counter: Counter<u64>,
    io_write_counter: Counter<u64>,
    io_syscr_counter: Counter<u64>,
    io_syscw_counter: Counter<u64>,
}

impl ProcessMetrics {
    pub fn new(meter: &Meter) -> Self {
        Self {
            rss_gauge: meter
                .u64_gauge("process.memory.rss")
                .with_description("Process resident memory size in bytes")
                .with_unit("By")
                .build(),
            vsize_gauge: meter
                .u64_gauge("process.memory.vsize")
                .with_description("Process virtual memory size in bytes")
                .with_unit("By")
                .build(),
            user_cpu_counter: meter
                .u64_counter("process.cpu.ticks.user")
                .with_description("User CPU time in ticks")
                .build(),
            sys_cpu_counter: meter
                .u64_counter("process.cpu.ticks.system")
                .with_description("System CPU time in ticks")
                .build(),
            threads_gauge: meter
                .u64_gauge("process.threads")
                .with_description("Number of threads")
                .build(),
            fds_gauge: meter
                .u64_gauge("process.open_file_descriptors")
                .with_description("Number of open file descriptors")
                .build(),
            io_read_counter: meter
                .u64_counter("process.disk.io.read_bytes")
                .with_description("Bytes read from disk")
                .with_unit("By")
                .build(),
            io_write_counter: meter
                .u64_counter("process.disk.io.write_bytes")
                .with_description("Bytes written to disk")
                .with_unit("By")
                .build(),
            io_syscr_counter: meter
                .u64_counter("process.disk.io.syscr")
                .with_description("Read syscall count")
                .build(),
            io_syscw_counter: meter
                .u64_counter("process.disk.io.syscw")
                .with_description("Write syscall count")
                .build(),
        }
    }
}

pub struct ProcessCollector {
    reader: ProcFsReader,
    hostname: String,
    metrics: ProcessMetrics,
    // Храним состояние прошлых вызовов
    last_state: Mutex<HashMap<u32, ProcessLastState>>,
}

impl ProcessCollector {
    pub fn new(hostname: String, meter: &Meter) -> Self {
        Self {
            reader: ProcFsReader::new(),
            hostname,
            metrics: ProcessMetrics::new(meter),
            last_state: Mutex::new(HashMap::with_capacity(256)), // Сразу выделяем память с запасом
        }
    }
}

#[async_trait]
impl Collector for ProcessCollector {
    fn name(&self) -> &'static str {
        "process"
    }

    async fn collect(&self, _meter: &Meter) -> Result<()> {
        let processes = self.reader.collect_processes();

        // лочка только получить снимок сразу освобождаем мютекс
        let mut prev_state_map = {
            let guard = self.last_state.lock().unwrap();
            guard.clone()
        };

        let mut active_pids = HashSet::with_capacity(processes.len());

        for proc in processes {
            active_pids.insert(proc.pid);

            let mut attrs = vec![
                KeyValue::new("host_name", self.hostname.clone()),
                KeyValue::new("process.pid", proc.pid as i64),
                KeyValue::new("process.executable.name", proc.comm),
                KeyValue::new("process.command_line", proc.cmdline),
                KeyValue::new("user.name", proc.username),
                KeyValue::new("process.state", proc.state),
            ];

            if let Some(unit) = proc.systemd_unit {
                attrs.push(KeyValue::new("systemd.unit", unit));
            }

            let prev = prev_state_map.get(&proc.pid).copied().unwrap_or_default();
            let has_prev = prev_state_map.contains_key(&proc.pid);

            let delta_utime = if has_prev {
                proc.utime_ticks.saturating_sub(prev.utime_ticks)
            } else {
                0
            };
            let delta_stime = if has_prev {
                proc.stime_ticks.saturating_sub(prev.stime_ticks)
            } else {
                0
            };

            self.metrics.rss_gauge.record(proc.rss_bytes, &attrs);
            self.metrics.vsize_gauge.record(proc.vsize_bytes, &attrs);
            self.metrics.threads_gauge.record(proc.num_threads, &attrs);

            self.metrics.user_cpu_counter.add(delta_utime, &attrs);
            self.metrics.sys_cpu_counter.add(delta_stime, &attrs);

            if let Some(fds) = proc.open_fds {
                self.metrics.fds_gauge.record(fds, &attrs);
            }

            let mut current_io = (0, 0, 0, 0);
            if let Some(io) = proc.io {
                current_io = (io.read_bytes, io.write_bytes, io.syscr, io.syscw);

                let delta_read = if has_prev {
                    io.read_bytes.saturating_sub(prev.read_bytes)
                } else {
                    0
                };
                let delta_write = if has_prev {
                    io.write_bytes.saturating_sub(prev.write_bytes)
                } else {
                    0
                };
                let delta_syscr = if has_prev {
                    io.syscr.saturating_sub(prev.syscr)
                } else {
                    0
                };
                let delta_syscw = if has_prev {
                    io.syscw.saturating_sub(prev.syscw)
                } else {
                    0
                };

                self.metrics.io_read_counter.add(delta_read, &attrs);
                self.metrics.io_write_counter.add(delta_write, &attrs);
                self.metrics.io_syscr_counter.add(delta_syscr, &attrs);
                self.metrics.io_syscw_counter.add(delta_syscw, &attrs);
            }

            prev_state_map.insert(
                proc.pid,
                ProcessLastState {
                    utime_ticks: proc.utime_ticks,
                    stime_ticks: proc.stime_ticks,
                    read_bytes: current_io.0,
                    write_bytes: current_io.1,
                    syscr: current_io.2,
                    syscw: current_io.3,
                },
            );
        }

        // тут пишем в мапу уникальные
        {
            let mut guard = self.last_state.lock().unwrap();
            *guard = prev_state_map;
            guard.retain(|pid, _| active_pids.contains(pid));
        }

        Ok(())
    }
}
