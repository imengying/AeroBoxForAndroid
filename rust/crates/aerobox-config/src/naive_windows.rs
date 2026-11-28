//! Match AeroBox's pinned Android Cronet receive-window semantics.
//!
//! cronet-go 0d28acc44093df24b2526dea3d6ffefd6b0a54f0,
//! naive_client.go:394-414. Its HTTP/2 ReceiveWindow means the connection window,
//! while HTTP/3 uses it as the per-stream window. Zero means unspecified.
use serde_json::Value;

use crate::{Fields, Result, error};

const KIB: u32 = 1024;
const MIB: u32 = 1024 * KIB;
// The fixed Cronet C++ options reader uses FindInt for both H2 and QUIC.
// QUIC's wire format allows larger values, but they never took effect in the App.
const MAX_WINDOW: u32 = i32::MAX as u32;
const MIN_QUIC_WINDOW: u32 = 16 * KIB;

pub(crate) fn apply(fields: &mut Fields, settings: &mut Value, quic: bool) -> Result<()> {
    let stream_path = format!("{}.stream_receive_window", fields.path);
    let session_path = format!("{}.quic_session_receive_window", fields.path);
    let receive = optional_size(fields, "stream_receive_window", &stream_path)?;
    let quic_session = optional_size(fields, "quic_session_receive_window", &session_path)?;
    let (stream, session) = if quic {
        // QUICHE raises smaller nonzero values to its minimum flow-control window.
        (
            receive.unwrap_or(6 * MIB).max(MIN_QUIC_WINDOW),
            quic_session.unwrap_or(15 * MIB).max(MIN_QUIC_WINDOW),
        )
    } else {
        if quic_session.is_some() {
            return Err(error(
                &session_path,
                "this option only applies when Naive quic is enabled",
            ));
        }
        let session = receive.unwrap_or(128 * MIB);
        (session / 2, session)
    };

    settings["stream_receive_window"] = stream.into();
    settings["session_receive_window"] = session.into();
    Ok(())
}

fn optional_size(fields: &mut Fields, key: &str, path: &str) -> Result<Option<u32>> {
    fields
        .take(key)
        .map(|value| memory_bytes(value, path))
        .transpose()
        .map(|value| value.filter(|value| *value != 0))
}

fn memory_bytes(value: Value, path: &str) -> Result<u32> {
    let bytes = if let Some(bytes) = value.as_u64() {
        bytes
    } else {
        let value = value
            .as_str()
            .ok_or_else(|| error(path, "expected an integer byte count or memory size"))?
            .trim();
        let split = value
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(value.len());
        let count: u64 = value[..split]
            .parse()
            .map_err(|_| error(path, "invalid integer memory size"))?;
        // sing's MemoryBytes uses powers of 1024 even for KB/MB/GB.
        let shift = match value[split..].trim().to_ascii_lowercase().as_str() {
            "" | "b" => 0,
            "k" | "kb" | "ki" | "kib" => 10,
            "m" | "mb" | "mi" | "mib" => 20,
            "g" | "gb" | "gi" | "gib" => 30,
            "t" | "tb" | "ti" | "tib" => 40,
            "p" | "pb" | "pi" | "pib" => 50,
            "e" | "eb" | "ei" | "eib" => 60,
            _ => return Err(error(path, "unknown memory size unit")),
        };
        count
            .checked_mul(1u64 << shift)
            .ok_or_else(|| error(path, "memory size overflow"))?
    };
    if bytes > u64::from(MAX_WINDOW) {
        return Err(error(
            path,
            "Naive receive window must not exceed 2147483647 bytes",
        ));
    }
    Ok(bytes as u32)
}
