//! Strict conversion of AeroBox Android node settings to the Rust runtime.
//! Unrecognized options return a field path, never a silent security downgrade.
#![forbid(unsafe_code)]
mod brutal;
mod dial_fields;
mod dns;
mod document;
mod naive_windows;
mod outbound;
mod singbox;
mod ss_plugin;
pub use document::{normalize_json, normalize_value};
pub use outbound::convert_outbound;
use serde_json::{Map, Value};
#[derive(Debug, thiserror::Error)]
#[error("{path}: {message}")]
pub struct Error {
    pub path: String,
    pub message: String,
}
pub type Result<T> = std::result::Result<T, Error>;
pub(crate) fn error(path: impl Into<String>, message: impl Into<String>) -> Error {
    Error {
        path: path.into(),
        message: message.into(),
    }
}
pub(crate) struct Fields {
    pub path: String,
    pub values: Map<String, Value>,
}
impl Fields {
    pub fn new(value: Value, path: &str) -> Result<Self> {
        let Value::Object(values) = value else {
            return Err(error(path, "expected an object"));
        };
        Ok(Self {
            path: path.into(),
            values,
        })
    }
    pub fn take(&mut self, key: &str) -> Option<Value> {
        self.values.remove(key)
    }
    pub fn required(&mut self, key: &str) -> Result<Value> {
        self.take(key)
            .ok_or_else(|| error(format!("{}.{}", self.path, key), "required field"))
    }
    pub fn string(&mut self, key: &str) -> Result<Option<String>> {
        self.take(key)
            .map(|v| {
                v.as_str()
                    .map(String::from)
                    .ok_or_else(|| error(format!("{}.{}", self.path, key), "expected a string"))
            })
            .transpose()
    }
    pub fn text(&mut self, key: &str) -> Result<String> {
        self.string(key)?
            .ok_or_else(|| error(format!("{}.{}", self.path, key), "required string"))
    }
    pub fn boolean(&mut self, key: &str, default: bool) -> Result<bool> {
        self.take(key).map_or(Ok(default), |v| {
            v.as_bool()
                .ok_or_else(|| error(format!("{}.{}", self.path, key), "expected a boolean"))
        })
    }
    pub fn default_only(&mut self, key: &str, allowed: &[Value]) -> Result<()> {
        if let Some(v) = self.take(key) {
            if !allowed.contains(&v) {
                return Err(error(
                    format!("{}.{}", self.path, key),
                    "this non-default option is not implemented by the Rust backend",
                ));
            }
        }
        Ok(())
    }
    pub fn copy(&mut self, key: &str, output: &mut Value, to: &str) {
        if let Some(value) = self.take(key) {
            output[to] = value;
        }
    }
    pub fn finish(self) -> Result<()> {
        if let Some(key) = self.values.keys().next() {
            Err(error(
                format!("{}.{}", self.path, key),
                "unrecognized or not yet implemented option",
            ))
        } else {
            Ok(())
        }
    }
}
pub(crate) fn address(host: &str, port: u64, path: &str) -> Result<String> {
    if host.is_empty()
        || host.chars().any(char::is_whitespace)
        || host.contains(['/', '\\', '@', '#', '?'])
        || !(1..=65535).contains(&port)
    {
        return Err(error(path, "invalid server address or port"));
    }
    Ok(if host.contains(':') {
        format!("[{}]:{port}", host.trim_matches(['[', ']']))
    } else {
        format!("{host}:{port}")
    })
}
pub(crate) fn seconds(value: Value, path: &str) -> Result<u64> {
    let text = value
        .as_str()
        .ok_or_else(|| error(path, "duration must be a string"))?;
    let (number, factor) = if let Some(n) = text.strip_suffix("ms") {
        (n, 0)
    } else if let Some(n) = text.strip_suffix('s') {
        (n, 1)
    } else if let Some(n) = text.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = text.strip_suffix('h') {
        (n, 3600)
    } else {
        return Err(error(path, "expected duration with ms/s/m/h suffix"));
    };
    let count: u64 = number
        .parse()
        .map_err(|_| error(path, "duration must be a non-negative integer"))?;
    if factor == 0 {
        if count % 1000 != 0 {
            return Err(error(path, "this option requires whole seconds"));
        }
        return Ok(count / 1000);
    }
    count
        .checked_mul(factor)
        .ok_or_else(|| error(path, "duration overflow"))
}
