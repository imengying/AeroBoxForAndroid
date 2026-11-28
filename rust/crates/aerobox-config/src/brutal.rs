//! TCP Brutal bandwidth settings for the sing-mux control exchange.
use serde_json::{Value, json};

use crate::{Fields, Result, error};

pub(crate) fn convert(value: Value, path: &str) -> Result<Value> {
    let mut fields = Fields::new(value, path)?;
    let enabled = fields.boolean("enabled", false)?;
    let mut parsed = json!({"enabled": enabled});
    for key in ["up_mbps", "down_mbps"] {
        let rate = fields.take(key).map_or(Ok(0), |value| {
            value.as_u64().ok_or_else(|| {
                error(
                    format!("{path}.{key}"),
                    "expected non-negative integer Mbps",
                )
            })
        })?;
        if enabled && rate.checked_mul(125_000).is_none_or(|bps| bps < 65_536) {
            return Err(error(
                format!("{path}.{key}"),
                "enabled TCP Brutal requires positive Mbps without overflow",
            ));
        }
        parsed[key] = rate.into();
    }
    fields.finish()?;
    Ok(parsed)
}
