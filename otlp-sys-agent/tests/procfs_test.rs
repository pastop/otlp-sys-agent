use otlp_sys_agent::collectors::process::procfs::{
    extract_unit_from_cgroup_path, parse_stat_comm, read_process_io,
};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_parse_stat_comm_standard() {
    let raw_stat = "1234 (nginx) S 1 1234 1234 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 4 0 1000 1000000 500";
    let (comm, rest) = parse_stat_comm(raw_stat).expect("Не удалось распарсить stat");
    assert_eq!(comm, "nginx");
    assert!(rest.starts_with("S 1 1234"));
}

#[test]
fn test_parse_stat_comm_with_spaces_and_brackets() {
    // Важно: имя процесса может содержать пробелы и скобки (например: "(sd-pam worker)")
    let raw_stat = "5678 (sd-pam (worker)) S 1 5678 5678 0 -1";
    let (comm, rest) = parse_stat_comm(raw_stat).expect("Не удалось распарсить stat со скобками");
    assert_eq!(comm, "sd-pam (worker)");
    assert_eq!(rest, "S 1 5678 5678 0 -1");
}

#[test]
fn test_extract_unit_from_cgroup_path() {
    // cgroup v2
    assert_eq!(
        extract_unit_from_cgroup_path("/system.slice/nginx.service"),
        Some("nginx.service".to_string())
    );

    // cgroup v1 с вложенным scope
    assert_eq!(
        extract_unit_from_cgroup_path("/system.slice/docker.service/docker-1234.scope"),
        Some("docker.service".to_string())
    );

    // Пользовательские сессии
    assert_eq!(
        extract_unit_from_cgroup_path("/user.slice/user-1000.slice/session-2.scope"),
        Some("session-2.scope".to_string())
    );

    // Пустой/коренной cgroup
    assert_eq!(extract_unit_from_cgroup_path("/"), None);
}

#[test]
fn test_read_process_io_parsing() {
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(
        temp_file,
        "rchar: 1000\nwchar: 2000\nsyscr: 15\nsyscw: 25\nread_bytes: 1048576\nwrite_bytes: 2097152"
    )
    .unwrap();

    let io_info = read_process_io(temp_file.path()).expect("Ошибка чтения файла io");

    assert_eq!(io_info.read_bytes, 1048576);
    assert_eq!(io_info.write_bytes, 2097152);
    assert_eq!(io_info.syscr, 15);
    assert_eq!(io_info.syscw, 25);
}
