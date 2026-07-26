use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Метрики ввода-вывода (I/O) процесса из /proc/[pid]/io
#[derive(Debug, Clone, Default)]
pub struct ProcessIoInfo {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub syscr: u64, // Количество системных вызовов чтения (read syscalls)
    pub syscw: u64, // Количество системных вызовов записи (write syscalls)
}

/// Структура базовой информации о процессе из /proc
#[derive(Debug, Clone)]
pub struct ProcessProcInfo {
    pub pid: u32,
    pub comm: String,
    pub cmdline: String,
    pub uid: u32,
    pub username: String,
    pub state: String,
    pub systemd_unit: Option<String>,
    pub utime_ticks: u64,
    pub stime_ticks: u64,
    pub vsize_bytes: u64,
    pub rss_bytes: u64,
    pub num_threads: u64,
    pub io: Option<ProcessIoInfo>, // I/O статистика
    pub open_fds: Option<u64>,     // Кол-во открытых дескрипторов
}

/// Чтец файловой системы /proc
pub struct ProcFsReader {
    user_map: HashMap<u32, String>,
    page_size: u64,
}

impl ProcFsReader {
    pub fn new() -> Self {
        Self {
            user_map: Self::load_user_map(),
            page_size: 4096, // Стандартный размер страницы памяти Linux (4 KiB)
        }
    }

    /// Быстрая загрузка пользователей из /etc/passwd для маппинга UID -> Имя пользователя
    fn load_user_map() -> HashMap<u32, String> {
        let mut map = HashMap::new();
        if let Ok(content) = fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 {
                    if let Ok(uid) = parts[2].parse::<u32>() {
                        map.insert(uid, parts[0].to_string());
                    }
                }
            }
        }
        map
    }

    /// Обход всех директорий PID в /proc
    pub fn collect_processes(&self) -> Vec<ProcessProcInfo> {
        let proc_path = Path::new("/proc");
        let mut processes = Vec::new();

        let entries = match fs::read_dir(proc_path) {
            Ok(e) => e,
            Err(_) => return processes,
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();

            // Если имя папки состоит только из цифр — это PID
            if let Ok(pid) = name_str.parse::<u32>() {
                if let Some(info) = self.read_process_info(pid) {
                    processes.push(info);
                }
            }
        }

        processes
    }

    /// Парсинг /proc/[pid]/stat, /proc/[pid]/status и /proc/[pid]/cmdline
    fn read_process_info(&self, pid: u32) -> Option<ProcessProcInfo> {
        let pid_dir = Path::new("/proc").join(pid.to_string());

        // 1. Чтение /proc/[pid]/stat
        let stat_content = fs::read_to_string(pid_dir.join("stat")).ok()?;
        let (comm, rest) = parse_stat_comm(&stat_content)?;
        let fields: Vec<&str> = rest.split_whitespace().collect();

        // Поля после comm (вырезан comm в скобках, поэтому сдвиг):
        // fields[0]  -> state (R, S, D, Z, T и др.)
        // fields[11] -> utime (14-е поле в оригинале)
        // fields[12] -> stime (15-е поле в оригинале)
        // fields[17] -> num_threads (20-е поле в оригинале)
        // fields[20] -> vsize (23-е поле в оригинале)
        // fields[21] -> rss в страницах (24-е поле в оригинале)
        if fields.len() < 22 {
            return None;
        }

        let state = fields[0].to_string();
        let utime_ticks = fields[11].parse::<u64>().unwrap_or(0);
        let stime_ticks = fields[12].parse::<u64>().unwrap_or(0);
        let num_threads = fields[17].parse::<u64>().unwrap_or(1);
        let vsize_bytes = fields[20].parse::<u64>().unwrap_or(0);
        let rss_pages = fields[21].parse::<u64>().unwrap_or(0);
        let rss_bytes = rss_pages * self.page_size;

        // 2. Чтение /proc/[pid]/status для UID
        let uid = read_proc_uid(&pid_dir.join("status")).unwrap_or(0);
        let username = self
            .user_map
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| uid.to_string());

        // 3. Чтение /proc/[pid]/cmdline
        let cmdline = match fs::read(pid_dir.join("cmdline")) {
            Ok(bytes) => {
                let raw = String::from_utf8_lossy(&bytes);
                let clean = raw.replace('\0', " ").trim().to_string();
                if clean.is_empty() {
                    comm.clone()
                } else {
                    clean
                }
            }
            Err(_) => comm.clone(),
        };

        // 4. Определение systemd_unit из /proc/[pid]/cgroup
        let systemd_unit = read_process_systemd_unit(&pid_dir.join("cgroup"));

        // 5. Чтение I/O статистики из /proc/[pid]/io
        let io = read_process_io(&pid_dir.join("io"));

        // 6. Подсчет открытых файловых дескрипторов из /proc/[pid]/fd
        let open_fds = count_open_fds(&pid_dir.join("fd"));

        Some(ProcessProcInfo {
            pid,
            comm,
            cmdline,
            uid,
            username,
            state,
            systemd_unit,
            utime_ticks,
            stime_ticks,
            vsize_bytes,
            rss_bytes,
            num_threads,
            io,
            open_fds,
        })
    }
}

/// Парсинг файла /proc/[pid]/io
pub fn read_process_io(io_path: &Path) -> Option<ProcessIoInfo> {
    let content = fs::read_to_string(io_path).ok()?;
    let mut io = ProcessIoInfo::default();

    for line in content.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(key), Some(val)) = (parts.next(), parts.next()) {
            if let Ok(value) = val.parse::<u64>() {
                match key {
                    "read_bytes:" => io.read_bytes = value,
                    "write_bytes:" => io.write_bytes = value,
                    "syscr:" => io.syscr = value,
                    "syscw:" => io.syscw = value,
                    _ => {}
                }
            }
        }
    }

    Some(io)
}

/// Подсчет открытых файлов/сокетов в директории /proc/[pid]/fd
pub fn count_open_fds(fd_dir: &Path) -> Option<u64> {
    let entries = fs::read_dir(fd_dir).ok()?;
    let count = entries.filter_map(|e| e.ok()).count() as u64;
    Some(count)
}

/// Извлечение названия systemd unit из /proc/[pid]/cgroup
pub fn read_process_systemd_unit(cgroup_path: &Path) -> Option<String> {
    let content = fs::read_to_string(cgroup_path).ok()?;

    for line in content.lines() {
        // Формат cgroup v2: 0::/system.slice/nginx.service
        // Формат cgroup v1: 5:name=systemd:/system.slice/docker.service
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            let path_str = parts[2];
            if let Some(unit) = extract_unit_from_cgroup_path(path_str) {
                return Some(unit);
            }
        }
    }

    None
}

/// Вычленение имени юнита (.service, .socket, .scope) из пути cgroup
pub fn extract_unit_from_cgroup_path(path: &str) -> Option<String> {
    let segments: Vec<&str> = path.split('/').collect();

    for seg in segments.iter().rev() {
        if seg.ends_with(".service") {
            return Some(seg.to_string());
        }
    }

    for seg in segments.iter().rev() {
        if seg.ends_with(".socket") || seg.ends_with(".scope") {
            return Some(seg.to_string());
        }
    }

    for seg in segments.iter().rev() {
        if seg.ends_with(".slice") && !seg.is_empty() {
            return Some(seg.to_string());
        }
    }

    None
}

/// Вырезает имя процесса comm из скобок `(...)`, так как имя может содержать пробелы и скобки
pub fn parse_stat_comm(stat_str: &str) -> Option<(String, &str)> {
    let open_bracket = stat_str.find('(')?;
    let close_bracket = stat_str.rfind(')')?;

    if open_bracket >= close_bracket {
        return None;
    }

    let comm = stat_str[open_bracket + 1..close_bracket].to_string();
    let rest = stat_str[close_bracket + 1..].trim();

    Some((comm, rest))
}

/// Извлечение Real UID из строки Uid:\t1000\t1000...
fn read_proc_uid(path: &Path) -> Option<u32> {
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        if line.starts_with("Uid:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse::<u32>().ok();
            }
        }
    }
    None
}
