use anyhow::{Context, Result};
use async_trait::async_trait;
use opentelemetry::metrics::Meter;
use opentelemetry::KeyValue;
use std::process::Stdio;
use tokio::process::Command;

use crate::collector::Collector;
use crate::config::IptablesCollectorConfig;

/// Структура итоговой статистики цепочки
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ChainTotal {
    pub table: String,
    pub chain: String,
    pub policy: String,
    pub packets: u64,
    pub bytes: u64,
}

/// Структура распарсенного правила
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct ParsedRule {
    pub table: String,
    pub chain: String,
    pub packets: u64,
    pub bytes: u64,
    pub target: Option<String>,
    pub match_set: Option<String>,
    pub match_comment: Option<String>,
    pub proto: Option<String>,
    pub dport: Option<String>,
    pub src: Option<String>,
    pub dst: Option<String>,
}

#[derive(Debug, Default)]
pub struct IptablesDump {
    pub chain_totals: Vec<ChainTotal>,
    pub rules: Vec<ParsedRule>,
}

/// Асинхронно вызывает команду iptables-save и парсит её вывод
pub async fn collect_iptables_data(config: &IptablesCollectorConfig) -> Result<IptablesDump> {
    let raw_output = execute_iptables_command(&config.command).await?;
    Ok(parse_iptables_save(&raw_output, config))
}

/// Выполнение команды (например: `sudo iptables-save -c`)
async fn execute_iptables_command(cmd_str: &str) -> Result<String> {
    let parts: Vec<&str> = cmd_str.split_whitespace().collect();
    if parts.is_empty() {
        anyhow::bail!("Команда iptables_save не может быть пустой");
    }

    let program = parts[0];
    let args = &parts[1..];

    let output = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| format!("Не удалось выполнить команду: {}", cmd_str))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Команда '{}' завершилась с ошибкой: {}", cmd_str, stderr);
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Чистая функция парсинга вывода `iptables-save -c`
pub fn parse_iptables_save(input: &str, config: &IptablesCollectorConfig) -> IptablesDump {
    let mut dump = IptablesDump::default();
    let mut current_table = "filter".to_string();

    for line in input.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // 1. Определение текущей таблицы (*filter, *nat, *raw, etc.)
        if let Some(table_name) = line.strip_prefix('*') {
            current_table = table_name.trim().to_string();
            continue;
        }

        // 2. Парсинг итоговых счетчиков цепочки (:INPUT ACCEPT [123:456])
        if line.starts_with(':') && config.collect_chain_totals {
            if let Some(total) = parse_chain_total(line, &current_table) {
                if !config.ignore_chains.contains(&total.chain) {
                    dump.chain_totals.push(total);
                }
            }
            continue;
        }

        // 3. Парсинг правил ([150:12000] -A INPUT ...)
        if line.starts_with('[') {
            if let Some(rule) = parse_rule_line(line, &current_table) {
                // Фильтрация по цепочкам
                if config.ignore_chains.contains(&rule.chain) {
                    continue;
                }

                // Фильтрация по таргету (если задан target_filter)
                if !config.target_filter.is_empty() {
                    if let Some(ref t) = rule.target {
                        if !config.target_filter.contains(t) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }

                // Режим only_with_metadata
                if config.only_with_metadata
                    && rule.match_set.is_none()
                    && rule.match_comment.is_none()
                {
                    continue;
                }

                dump.rules.push(rule);
            }
        }
    }

    dump
}

/// Парсинг строки итогов цепочки: `:INPUT ACCEPT [100:2000]`
fn parse_chain_total(line: &str, table: &str) -> Option<ChainTotal> {
    let line = line.strip_prefix(':')?;
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let chain = parts[0].to_string();
    let policy = parts[1].to_string();
    let counters_str = parts[2];

    let (packets, bytes) = parse_counters(counters_str)?;

    Some(ChainTotal {
        table: table.to_string(),
        chain,
        policy,
        packets,
        bytes,
    })
}

/// Парсинг строки правила: `[150:12000] -A INPUT -p tcp -m set --match-set crowdsec-blacklists src -j DROP`
fn parse_rule_line(line: &str, table: &str) -> Option<ParsedRule> {
    let mut rule = ParsedRule {
        table: table.to_string(),
        ..Default::default()
    };

    let mut tokens = tokenize(line);
    if tokens.is_empty() {
        return None;
    }

    let counters_str = tokens.remove(0);
    let (packets, bytes) = parse_counters(&counters_str)?;
    rule.packets = packets;
    rule.bytes = bytes;

    let mut i = 0;
    while i < tokens.len() {
        match tokens[i].as_str() {
            "-A" | "--append" => {
                if i + 1 < tokens.len() {
                    rule.chain = tokens[i + 1].clone();
                    i += 1;
                }
            }
            "-j" | "--jump" => {
                if i + 1 < tokens.len() {
                    rule.target = Some(tokens[i + 1].clone());
                    i += 1;
                }
            }
            "--match-set" => {
                if i + 1 < tokens.len() {
                    rule.match_set = Some(tokens[i + 1].clone());
                    i += 1;
                }
            }
            "--comment" => {
                if i + 1 < tokens.len() {
                    rule.match_comment = Some(tokens[i + 1].clone());
                    i += 1;
                }
            }
            "-p" | "--protocol" => {
                if i + 1 < tokens.len() {
                    rule.proto = Some(tokens[i + 1].clone());
                    i += 1;
                }
            }
            "--dport" | "--destination-port" => {
                if i + 1 < tokens.len() {
                    rule.dport = Some(tokens[i + 1].clone());
                    i += 1;
                }
            }
            "-s" | "--source" => {
                if i + 1 < tokens.len() {
                    rule.src = Some(tokens[i + 1].clone());
                    i += 1;
                }
            }
            "-d" | "--destination" => {
                if i + 1 < tokens.len() {
                    rule.dst = Some(tokens[i + 1].clone());
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    if rule.chain.is_empty() {
        return None;
    }

    Some(rule)
}

/// Извлечение числа пакетов и байт из скобок `[123:4567]`
fn parse_counters(s: &str) -> Option<(u64, u64)> {
    let s = s.strip_prefix('[')?.strip_suffix(']')?;
    let mut parts = s.split(':');
    let pkts = parts.next()?.parse::<u64>().ok()?;
    let bytes = parts.next()?.parse::<u64>().ok()?;
    Some((pkts, bytes))
}

/// Простой токенизатор, учитывающий кавычки для `--comment "some text"`
fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in line.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
            }
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(ch);
            }
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

// ========================
// COLLECTOR IMPLEMENTATION
// ========================

pub struct IptablesCollector {
    config: IptablesCollectorConfig,
    hostname: String,
}

impl IptablesCollector {
    pub fn new(config: IptablesCollectorConfig, hostname: String) -> Self {
        Self { config, hostname }
    }
}

#[async_trait]
impl Collector for IptablesCollector {
    fn name(&self) -> &'static str {
        "iptables"
    }

    async fn collect(&self, meter: &Meter) -> Result<()> {
        let dump = collect_iptables_data(&self.config).await?;

        let chain_packets = meter
            .u64_counter("system.iptables.chain.packets")
            .with_description("Total packets evaluated by iptables chain policy")
            .build();

        let chain_bytes = meter
            .u64_counter("system.iptables.chain.bytes")
            .with_description("Total bytes evaluated by iptables chain policy")
            .build();

        let rule_packets = meter
            .u64_counter("system.iptables.rule.packets")
            .with_description("Total packets matched by specific iptables rule")
            .build();

        let rule_bytes = meter
            .u64_counter("system.iptables.rule.bytes")
            .with_description("Total bytes matched by specific iptables rule")
            .build();

        // 1. Экспорт итоговых счетчиков цепочек
        for chain in dump.chain_totals {
            let attrs = [
                KeyValue::new("host_name", self.hostname.clone()),
                KeyValue::new("table", chain.table),
                KeyValue::new("chain", chain.chain),
                KeyValue::new("policy", chain.policy),
            ];
            chain_packets.add(chain.packets, &attrs);
            chain_bytes.add(chain.bytes, &attrs);
        }

        // 2. Экспорт счетчиков отдельных правил
        for rule in dump.rules {
            let mut attrs = vec![
                KeyValue::new("host_name", self.hostname.clone()),
                KeyValue::new("table", rule.table),
                KeyValue::new("chain", rule.chain),
            ];

            if let Some(target) = rule.target {
                attrs.push(KeyValue::new("target", target));
            }
            if let Some(set) = rule.match_set {
                attrs.push(KeyValue::new("match_set", set));
            }
            if let Some(comment) = rule.match_comment {
                attrs.push(KeyValue::new("comment", comment));
            }
            if let Some(proto) = rule.proto {
                attrs.push(KeyValue::new("proto", proto));
            }
            if let Some(dport) = rule.dport {
                attrs.push(KeyValue::new("dport", dport));
            }
            if let Some(src) = rule.src {
                attrs.push(KeyValue::new("src", src));
            }
            if let Some(dst) = rule.dst {
                attrs.push(KeyValue::new("dst", dst));
            }

            rule_packets.add(rule.packets, &attrs);
            rule_bytes.add(rule.bytes, &attrs);
        }

        Ok(())
    }
}
