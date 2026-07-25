# OTLP System Agent

Легковесный агент на Rust для сбора системных метрик (`iptables`, `hwmon temperature`) и отправки их по протоколу OTLP (OpenTelemetry) в Prometheus / VictoriaMetrics.

---

## 🛠 Разработка (Dev)

### Требования
* Rust (`rustup default stable`)
* `task` (Taskfile runner)
* `zig` и `cargo-zigbuild` (для кросс-компиляции)

### Локальный запуск
1. Скопируйте шаблон переменных окружения при необходимости:
   ```bash
   cp .env.example .env
   ```
