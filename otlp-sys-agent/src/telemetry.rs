use crate::config::AppConfig;
use anyhow::Result;
use opentelemetry::KeyValue;
use opentelemetry_otlp::{MetricExporter, WithExportConfig};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::Resource;
use std::time::Duration;

pub fn init_meter_provider(config: &AppConfig) -> Result<SdkMeterProvider> {
    let hostname = config.get_hostname();

    // Переключаем экспортер на OTLP over HTTP
    let exporter = MetricExporter::builder()
        .with_http()
        .with_endpoint(&config.otlp.endpoint)
        .with_timeout(Duration::from_secs(config.otlp.timeout_secs))
        .build()?;

    let reader = PeriodicReader::builder(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_interval(Duration::from_secs(config.agent.interval_secs))
        .build();

    let resource = Resource::new(vec![
        KeyValue::new("service.name", "otlp-sys-agent"),
        KeyValue::new("host.name", hostname),
    ]);

    let provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .build();

    Ok(provider)
}
