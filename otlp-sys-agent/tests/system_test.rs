use otlp_sys_agent::collectors::system::{
    calculate_cpu_usage, parse_cpuinfo, parse_meminfo, parse_proc_stat,
};

#[test]
fn test_parse_cpuinfo() {
    let content = r#"processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i7-9700 CPU @ 3.00GHz
physical id	: 0

processor	: 1
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i7-9700 CPU @ 3.00GHz
physical id	: 0
"#;
    let info = parse_cpuinfo(content);
    assert_eq!(info.model, "Intel(R) Core(TM) i7-9700 CPU @ 3.00GHz");
    assert_eq!(info.threads, 2);
}

#[test]
fn test_parse_proc_stat() {
    let content = "cpu  1000 200 300 5000 100 50 25 10 0 0\ncpu0 500 100 150 2500 50 25 12 5 0 0\n";
    let state = parse_proc_stat(content);
    assert_eq!(state.user, 1000);
    assert_eq!(state.nice, 200);
    assert_eq!(state.system, 300);
    assert_eq!(state.idle, 5000);
    assert_eq!(state.iowait, 100);
}

#[test]
fn test_parse_meminfo() {
    let content = "MemTotal:       16384000 kB\nMemFree:         4096000 kB\nMemAvailable:    8192000 kB\nBuffers:          512000 kB\nCached:          2048000 kB\n";
    let mem = parse_meminfo(content);
    assert_eq!(mem.total_bytes, 16384000 * 1024);
    assert_eq!(mem.available_bytes, 8192000 * 1024);
    assert_eq!(mem.free_bytes, 4096000 * 1024);
    assert_eq!(mem.used_bytes, (16384000 - 8192000) * 1024);
}

#[test]
fn test_calculate_cpu_usage() {
    let prev = otlp_sys_agent::collectors::system::parse_proc_stat(
        "cpu  1000 0 500 8000 500 0 0 0 0 0\n"
    );
    let cur = otlp_sys_agent::collectors::system::parse_proc_stat(
        "cpu  2000 0 1000 9000 500 0 0 0 0 0\n"
    );
    // busy_delta = (2000-1000) + (1000-500) = 1500
    // total_delta = (2000+1000+9000+500) - (1000+500+8000+500) = 2500
    // usage = 1500/2500 * 100 = 60%
    let usage = calculate_cpu_usage(&prev, &cur);
    assert!((usage - 60.0).abs() < 0.01, "Expected 60%, got {}", usage);
}

#[test]
fn test_calculate_cpu_usage_zero_delta() {
    let state = parse_proc_stat("cpu  1000 0 500 8000 500 0 0 0 0 0\n");
    let usage = calculate_cpu_usage(&state, &state);
    assert_eq!(usage, 0.0);
}
