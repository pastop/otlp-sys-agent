use anyhow::Result;
use opentelemetry::metrics::MeterProvider;
use otlp_sys_agent::collector::CollectorRegistry;
use otlp_sys_agent::collectors::iptables::IptablesCollector;
use otlp_sys_agent::collectors::process::ProcessCollector;
use otlp_sys_agent::collectors::temperature::SysfsTempCollector;
use otlp_sys_agent::collectors::filesystem::FilesystemCollector;
use otlp_sys_agent::collectors::disk::DiskCollector;

use otlp_sys_agent::config::AppConfig;
use otlp_sys_agent::telemetry;
use std::time::Duration;
use tokio::signal;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Загрузка конфигурации
    let cfg = AppConfig::load()?;

    // 2. Инициализация логирования
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&cfg.agent.log_level)),
        )
        .init();

    info!(
        hostname = %cfg.get_hostname(),
        endpoint = %cfg.otlp.endpoint,
        interval = cfg.agent.interval_secs,
        "Запуск OTLP System Agent"
    );

    // 3. Инициализация OpenTelemetry
    let meter_provider = telemetry::init_meter_provider(&cfg)?;
    let meter = meter_provider.meter("otlp-sys-agent");

    // 4. Регистрация активных коллекторов
    let hostname = cfg.get_hostname();
    let mut registry = CollectorRegistry::new();

    if cfg.collectors.temperature.enabled {
        registry.register(SysfsTempCollector::new(hostname.clone()));
    }

    // Регистрация iptables коллектора
    if cfg.collectors.iptables.enabled {
        registry.register(IptablesCollector::new(
            cfg.collectors.iptables.clone(),
            hostname.clone(),
        ));
    }

    // Регистрация process коллектора
    if cfg.collectors.process.enabled {
        registry.register(ProcessCollector::new(hostname.clone()));
    }

    if registry.is_empty() {
        warn!("Нет активных коллекторов в конфигурации! Завершение работы.");
        return Ok(());
    }

    // Регистрация filesystem коллектора
    if cfg.collectors.filesystem.enabled {
        registry.register(FilesystemCollector::new(
            cfg.collectors.filesystem.clone(),
            hostname.clone(),
        ));
    }

    if cfg.collectors.disk.enabled {
        registry.register(DiskCollector::new(
            cfg.collectors.disk.clone(),
            hostname.clone(),
        ));
    }

    // 5. Главный асинхронный цикл сбора
    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.agent.interval_secs));

    info!("Агент успешно запущен. Для остановки нажмите Ctrl+C.");

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                registry.collect_all(&meter).await;
            }
            _ = shutdown_signal() => {
                info!("Получен сигнал остановки. Сброс метрик и выключение...");
                break;
            }
        }
    }

    // 6. Graceful shutdown: принудительный флаш (flush) невыгруженных метрик
    if let Err(e) = meter_provider.shutdown() {
        tracing::error!(error = %e, "Ошибка при закрытии OTLP MeterProvider");
    } else {
        info!("OpenTelemetry MeterProvider корректно завершил работу.");
    }

    info!("Агент остановлен.");
    Ok(())
}

/// Асинхронный перехват сигналов SIGINT (Ctrl+C) и SIGTERM (systemctl stop)
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Не удалось установить обработчик Ctrl+C");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Не удалось установить обработчик SIGTERM")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
