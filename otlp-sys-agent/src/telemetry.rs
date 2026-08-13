use crate::config::AppConfig;
use anyhow::Result;
use opentelemetry::KeyValue;
use opentelemetry_otlp::{MetricExporter, WithExportConfig};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::Resource;
use std::time::Duration;

pub fn init_meter_provider(config: &AppConfig) -> Result<SdkMeterProvider> {
    let hostname = config.get_hostname();

    // 1. Экспортёр OTLP over HTTP (теперь использует блокирующий reqwest под капотом)
    let exporter = MetricExporter::builder()
        .with_http()
        .with_endpoint(&config.otlp.endpoint)
        .with_timeout(Duration::from_secs(config.otlp.timeout_secs))
        .build()?;

    // 2. PeriodicReader принимает ТОЛЬКО exporter.
    // Runtime больше не передается — reader сам создаст std::thread.
    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(config.agent.interval_secs))
        .build();

    // 3. Resource создается через builder (API 0.32.x)
    let resource = Resource::builder()
        .with_attribute(KeyValue::new("service.name", "otlp-sys-agent"))
        .with_attribute(KeyValue::new("host.name", hostname))
        .build();

    // 4. Сборка MeterProvider
    let provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .build();

    Ok(provider)
}
