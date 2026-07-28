use crate::collector::Collector;
use crate::collectors::process::procfs::ProcFsReader;
use anyhow::Result;
use async_trait::async_trait;
use opentelemetry::metrics::Meter;
use opentelemetry::KeyValue;
use std::collections::HashMap;
use std::sync::Mutex;

/// Структурное хранение предыдущего состояния накопительных счётчиков процесса
#[derive(Default, Clone, Copy)]
struct ProcessLastState {
    utime_ticks: u64,
    stime_ticks: u64,
    read_bytes: u64,
    write_bytes: u64,
    syscr: u64,
    syscw: u64,
}

pub struct ProcessCollector {
    reader: ProcFsReader,
    hostname: String,
    // Хранение истории между итерациями сбора (PID -> State)
    last_state: Mutex<HashMap<u32, ProcessLastState>>,
}

impl ProcessCollector {
    pub fn new(hostname: String) -> Self {
        Self {
            reader: ProcFsReader::new(),
            hostname,
            last_state: Mutex::new(HashMap::new()),
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

        // 1. Инициализация инструментов метрик OpenTelemetry
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

        // Получаем блокировку предыдущего состояния
        let mut prev_state_map = self.last_state.lock().unwrap();
        let mut next_state_map = HashMap::new();

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

            // Получаем прошлые данные по этому PID (если процесс уже отслеживался)
            let prev = prev_state_map.get(&proc.pid).copied().unwrap_or_default();
            let has_prev = prev_state_map.contains_key(&proc.pid);

            // Считаем дельту для CPU (saturating_sub защищает от переполнений при сбросе)
            let delta_utime = if has_prev { proc.utime_ticks.saturating_sub(prev.utime_ticks) } else { 0 };
            let delta_stime = if has_prev { proc.stime_ticks.saturating_sub(prev.stime_ticks) } else { 0 };

            // Запись мгновенных метрик (Gauges)
            rss_gauge.record(proc.rss_bytes, &attrs);
            vsize_gauge.record(proc.vsize_bytes, &attrs);
            threads_gauge.record(proc.num_threads, &attrs);

            // Запись счетчиков CPU (передаем только прирост delta)
            user_cpu_counter.add(delta_utime, &attrs);
            sys_cpu_counter.add(delta_stime, &attrs);

            if let Some(fds) = proc.open_fds {
                fds_gauge.record(fds, &attrs);
            }

            // Обработка I/O метрик (тоже считаются через дельту)
            let mut current_io = (0, 0, 0, 0);
            if let Some(io) = proc.io {
                current_io = (io.read_bytes, io.write_bytes, io.syscr, io.syscw);

                let delta_read = if has_prev { io.read_bytes.saturating_sub(prev.read_bytes) } else { 0 };
                let delta_write = if has_prev { io.write_bytes.saturating_sub(prev.write_bytes) } else { 0 };
                let delta_syscr = if has_prev { io.syscr.saturating_sub(prev.syscr) } else { 0 };
                let delta_syscw = if has_prev { io.syscw.saturating_sub(prev.syscw) } else { 0 };

                io_read_counter.add(delta_read, &attrs);
                io_write_counter.add(delta_write, &attrs);
                io_syscr_counter.add(delta_syscr, &attrs);
                io_syscw_counter.add(delta_syscw, &attrs);
            }

            // Сохраняем текущие показания для следующего шага
            next_state_map.insert(
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

        // Обновляем состояние (завершённые PID автоматически удаляются)
        *prev_state_map = next_state_map;

        Ok(())
    }
}
