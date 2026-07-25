use anyhow::Result;
use async_trait::async_trait;
use opentelemetry::metrics::Meter;
use tracing::{error, info};

/// Базовый асинхронный трейт для всех сборщиков метрик.
/// Каждый новый источник метрик (температура, iptables) должен имплементировать этот трейт.
#[async_trait]
pub trait Collector: Send + Sync {
    /// Уникальное имя коллектора (используется для логов и фильтрации в конфиге)
    fn name(&self) -> &'static str;

    /// Основной метод сбора метрик и отправки их в OpenTelemetry Meter
    async fn collect(&self, meter: &Meter) -> Result<()>;
}

/// Реестр всех активных коллекторов системы
#[derive(Default)]
pub struct CollectorRegistry {
    collectors: Vec<Box<dyn Collector>>,
}

impl CollectorRegistry {
    pub fn new() -> Self {
        Self {
            collectors: Vec::new(),
        }
    }

    /// Регистрация нового коллектора
    pub fn register<C: Collector + 'static>(&mut self, collector: C) {
        info!("Зарегистрирован коллектор: {}", collector.name());
        self.collectors.push(Box::new(collector));
    }

    /// Последовательный или параллельный запуск сбора со всех зарегистрированных коллекторов
    pub async fn collect_all(&self, meter: &Meter) {
        for collector in &self.collectors {
            if let Err(err) = collector.collect(meter).await {
                error!(
                    collector = collector.name(),
                    error = %err,
                    "Ошибка при сборе метрик"
                );
            }
        }
    }

    /// Количество активных коллекторов
    pub fn len(&self) -> usize {
        self.collectors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.collectors.is_empty()
    }
}
