use crate::collector::Collector;
use crate::collectors::process::procfs::ProcFsReader;
use anyhow::Result;
use async_trait::async_trait;
use opentelemetry::metrics::Meter;
use opentelemetry::KeyValue;

pub struct ProcessCollector {
    reader: ProcFsReader,
    hostname: String,
}

impl ProcessCollector {
    pub fn new(hostname: String) -> Self {
        Self {
            reader: ProcFsReader::new(),
            hostname,
        }
    }
}



#[async_trait]
impl Collector for ProcessCollector {
    fn name(&self) -> &'static str {
        "process"
    }

    async fn collect(&self, meter: &Meter) -> Result<()> {
        let processes = self.reader.collect_processes();

        // 1. Инициализация инструментов метрик OpenTelemetry (.build() вместо .init())
        let rss_gauge = meter
            .u64_gauge("process.memory.rss")
            .with_description("Process resident memory size in bytes")
            .with_unit("By")
            .build();

        let vsize_gauge = meter
            .u64_gauge("process.memory.vsize")
            .with_description("Process virtual memory size in bytes")
            .with_unit("By")
            .build();

        let user_cpu_counter = meter
            .u64_counter("process.cpu.ticks.user")
            .with_description("User CPU time in ticks")
            .build();

        let sys_cpu_counter = meter
            .u64_counter("process.cpu.ticks.system")
            .with_description("System CPU time in ticks")
            .build();

        let threads_gauge = meter
            .u64_gauge("process.threads")
            .with_description("Number of threads")
            .build();

        let fds_gauge = meter
            .u64_gauge("process.open_file_descriptors")
            .with_description("Number of open file descriptors")
            .build();

        let io_read_counter = meter
            .u64_counter("process.disk.io.read_bytes")
            .with_description("Bytes read from disk")
            .with_unit("By")
            .build();

        let io_write_counter = meter
            .u64_counter("process.disk.io.write_bytes")
            .with_description("Bytes written to disk")
            .with_unit("By")
            .build();

        let io_syscr_counter = meter
            .u64_counter("process.disk.io.syscr")
            .with_description("Read syscall count")
            .build();

        let io_syscw_counter = meter
            .u64_counter("process.disk.io.syscw")
            .with_description("Write syscall count")
            .build();

        // 2. Обход процессов и запись значений
        for proc in processes {
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

            rss_gauge.record(proc.rss_bytes, &attrs);
            vsize_gauge.record(proc.vsize_bytes, &attrs);
            user_cpu_counter.add(proc.utime_ticks, &attrs);
            sys_cpu_counter.add(proc.stime_ticks, &attrs);
            threads_gauge.record(proc.num_threads, &attrs);

            if let Some(fds) = proc.open_fds {
                fds_gauge.record(fds, &attrs);
            }

            if let Some(io) = proc.io {
                io_read_counter.add(io.read_bytes, &attrs);
                io_write_counter.add(io.write_bytes, &attrs);
                io_syscr_counter.add(io.syscr, &attrs);
                io_syscw_counter.add(io.syscw, &attrs);
            }
        }

        Ok(())
    }
}
