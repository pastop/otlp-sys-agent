use crate::collector::Collector;
use anyhow::Result;
use async_trait::async_trait;
use opentelemetry::metrics::Meter;
use opentelemetry::KeyValue;
use std::fs;
use std::path::Path;
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct TempReadout {
    pub chip: String,
    pub label: String,
    pub celsius: f64,
}

pub struct SysfsTempCollector {
    hostname: String,
}

impl SysfsTempCollector {

    pub fn new(hostname: String) -> Self {
        Self { hostname }
    }

    pub fn read_temperatures() -> Vec<TempReadout> {
        let mut readouts = Vec::new();
        let hwmon_path = Path::new("/sys/class/hwmon");

        if !hwmon_path.exists() {
            warn!("Директория /sys/class/hwmon не найдена");
            return readouts;
        }

        let entries = match fs::read_dir(hwmon_path) {
            Ok(e) => e,
            Err(err) => {
                warn!("Ошибка чтения /sys/class/hwmon: {}", err);
                return readouts;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let chip_name = fs::read_to_string(path.join("name"))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string());

            if let Ok(sensor_entries) = fs::read_dir(&path) {
                for sensor in sensor_entries.flatten() {
                    let file_name = sensor.file_name();
                    let name_str = file_name.to_string_lossy();

                    if name_str.starts_with("temp") && name_str.ends_with("_input") {
                        let prefix = name_str.trim_end_matches("_input");

                        let label = fs::read_to_string(path.join(format!("{}_label", prefix)))
                            .map(|s| s.trim().to_string())
                            .unwrap_or_else(|_| prefix.to_string());

                        if let Ok(content) = fs::read_to_string(sensor.path()) {
                            if let Ok(milli_celsius) = content.trim().parse::<f64>() {
                                readouts.push(TempReadout {
                                    chip: chip_name.clone(),
                                    label,
                                    celsius: milli_celsius / 1000.0,
                                });
                            }
                        }
                    }
                }
            }
        }

        readouts
    }
}

#[async_trait]
impl Collector for SysfsTempCollector {
    fn name(&self) -> &'static str {
        "temperature"
    }

    async fn collect(&self, meter: &Meter) -> Result<()> {
        // Создаем метрику типа Gauge
        let gauge = meter
            .f64_gauge("system.hardware.temperature.celsius")
            .with_description("Temperature readout from system hardware sensors")
            .with_unit("Cel")
            .build();

        let temps = Self::read_temperatures();
        for temp in temps {
            debug!(
                chip = %temp.chip,
                label = %temp.label,
                celsius = %temp.celsius,
                "Отправка показаний температуры"
            );

            // Фиксируем значение с метками чипа и сенсора
            gauge.record(
                temp.celsius,
                &[
                    KeyValue::new("host_name", self.hostname.clone()),
                    KeyValue::new("chip", temp.chip),
                    KeyValue::new("label", temp.label),
                ],
            );
        }

        Ok(())
    }
}
