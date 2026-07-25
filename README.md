# OTLP System Agent

Легковесный агент на Rust для сбора системных метрик (`iptables`, `hwmon temperature`) и их отправки по протоколу OTLP (OpenTelemetry) в Prometheus / VictoriaMetrics / OpenTelemetry Collector.

---

## Быстрый старт на сервере (Prod)

Для установки на целевой сервер **не требуется** компилятор Rust, `git` или исходный код. Нужны только готовность принять OTLP-метрики на вашем коллекторе и права `root` для установки службы.

### Пошаговый цикл установки:

#### 1. Скачивание релизного архива
Скачайте актуальную версию архива со страницы **Releases** :

```bash
wget https://github.com/pastop/otlp-sys-agent/releases/download/0.1.1/otlp-sys-agent-release.tar.gz
```
(Или используйте curl -O ...)

2. Распаковка архива
Распакуйте архив во временную директорию и перейдите в неё:

```Bash
mkdir -p /tmp/agent-install && tar -xvf otlp-sys-agent-release.tar.gz -C /tmp/agent-install
cd /tmp/agent-install
```
3. Запуск автоматической установки
Выполните инсталляционный скрипт с правами root:

```Bash
sudo ./install.sh
```
Что делает `install.sh` под капотом:

Автоматически определяет архитектуру процессора (x86_64 или aarch64) и выбирает нужный статический бинарник.

Создает изолированного системного пользователя otlp-agent.

Копирует бинарник в `/usr/local/bin/otlp-sys-agent`

Создает директорию `/etc/otlp-sys-agent/` и копирует дефолтный `config.yaml` (если его там еще нет).

Регистрирует unit-файл `otlp-sys-agent.service` в systemd, перезагружает демон, включает автозапуск и сразу запускает сервис.

!!! ВАЖНОЕ ПРЕДУПРЕЖДЕНИЕ ПРО sudo !!!
Скрипт установки `install.sh` обязателен к запуску через `sudo`, так как он регистрирует службу `systemd` и создает системного пользователя.

Внутри файла конфигурации `/etc/otlp-sys-agent/config.yaml` использовать `sudo` КАТЕГОРИЧЕСКИ НЕЛЬЗЯ!

Неверно: `command: "sudo iptables-save -c"` - (Приведёт к ошибке sudoers_audit / Operation not permitted)

Правильно: `command: "iptables-save -c"`

Почему так? Сервис запускается от непривилегированного пользователя otlp-agent, но systemd при старте выдает процессу точечные Linux Capabilities (CAP_NET_ADMIN и CAP_NET_RAW). Агент может читать правила iptables напрямую без вызова sudo.

4. Настройка конфигурации
Отредактируйте конфигурационный файл, указав адрес вашего OTLP-приёмника:

```Bash
sudo nano /etc/otlp-sys-agent/config.yaml
```
Пример рабочей конфигурации:

```YAML
agent:
  interval_secs: 10
  log_level: "info"
  # Если оставить пустым "", имя хоста подтянется автоматически из системы
  host_name: "" 

otlp:
  endpoint: "http://10.0.0.5:4317" # Адрес вашего OTel Collector / VictoriaMetrics
  timeout_secs: 5

collectors:
  temperature:
    enabled: true

  iptables:
    enabled: true
    command: "iptables-save -c" # БЕЗ sudo!
    collect_chain_totals: true
    only_with_metadata: false
    ignore_chains: []
    target_filter: []
```
5. Перезапуск и проверка статуса
После внесения изменений в конфиг перезапустите сервис:

```Bash
sudo systemctl restart otlp-sys-agent
```
Проверьте статус и логи работы:

```Bash
# Проверка статуса службы
sudo systemctl status otlp-sys-agent

# Чтение логов в реальном времени
sudo journalctl -u otlp-sys-agent -f
```
Успешный запуск сопровождается логом:

```Plaintext
INFO otlp_sys_agent: Агент успешно запущен. hostname=pastop-pc endpoint=http://10.0.0.5:4317
```
🛠 Разработка и сборка (Dev)
Инструкция для разработчиков, желающих внести изменения в код или собрать релизный архив самостоятельно.

Требования
Rust (rustup default stable)

Task (Taskfile runner)

Zig и cargo-zigbuild (для кросс-компиляции под aarch64 и x86_64 с musl)

Подготовка окружения:
```Bash
# Установка зависимости в Arch Linux
sudo pacman -S zig
cargo install cargo-zigbuild
```
Команды разработки:
Локальный запуск агента в dev-режиме:

```Bash
task dev
```
Запуск юнит-тестов:

```Bash
task test
```
Сборка релизного архива (Full Cycle Build):

```Bash
task release
```
(Скомпилирует бинарники под x86_64 и ARM64 через Zig, сгенерирует `install.sh`, `systemd.service` и упакует всё в `dist/otlp-sys-agent-release.tar.gz`).

## Пример дашборда представлен в `GrafanaDashBoardExample.json` и `GrafanaCPUTempDashBoardExample.json`
