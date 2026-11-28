//! AeroBox's synchronous host facade and Android JNI adapter.

use shoes::{
    config::Config,
    embedding::{EmbeddedCore, Platform, StandaloneProbes, StartCancellation},
};
use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Condvar, Mutex, OnceLock},
};

#[cfg(target_os = "android")]
mod jni_bridge;
#[cfg(any(target_os = "android", test))]
mod system_dns;

/// Owns the executor and the embedded service. Lifecycle transitions are
/// serialized; statistics and probes can run concurrently with shutdown.
pub struct AndroidRuntime {
    executor: tokio::runtime::Runtime,
    state: Mutex<HostState>,
    changed: Condvar,
}

#[derive(Default)]
struct HostState {
    core: Option<Arc<EmbeddedCore>>,
    starting: Option<StartCancellation>,
    stopping: bool,
    probes: Option<Arc<StandaloneProbes>>,
    probe_users: usize,
    probe_closing: bool,
}

fn parse_config(value: serde_json::Value, tun_fd: Option<i32>) -> io::Result<Vec<Config>> {
    let value = aerobox_config::normalize_value(value, tun_fd).map_err(io::Error::other)?;
    let configs: Vec<Config> = serde_json::from_value(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    if let Some(fd) = tun_fd {
        let count = configs
            .iter()
            .filter(|config| matches!(config, Config::TunServer(_)))
            .count();
        if fd < 0 || count != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a supplied TUN descriptor requires a nonnegative fd and exactly one TUN entry",
            ));
        }
    }
    Ok(configs)
}

impl AndroidRuntime {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            executor: tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("aerobox")
                .enable_all()
                .build()?,
            state: Mutex::new(HostState::default()),
            changed: Condvar::new(),
        })
    }

    /// Parse the current document once and borrow the supplied TUN descriptor
    /// until the embedded service duplicates it during startup.
    pub fn start(
        &self,
        json: &str,
        tun_fd: Option<i32>,
        platform: Option<Arc<dyn Platform>>,
    ) -> io::Result<()> {
        self.check_call_context()?;
        let configs = parse_config(serde_json::from_str(json)?, tun_fd)?;
        let cancellation = StartCancellation::new();
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("core state lock poisoned"))?;
            while state.stopping || state.probe_closing {
                state = self
                    .changed
                    .wait(state)
                    .map_err(|_| io::Error::other("core state lock poisoned"))?;
            }
            if state.core.is_some() || state.starting.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "core already started or starting",
                ));
            }
            state.starting = Some(cancellation.clone());
            if let Some(probes) = &state.probes {
                probes.cancel();
            }
            while state.probe_users != 0 || state.probe_closing {
                state = self
                    .changed
                    .wait(state)
                    .map_err(|_| io::Error::other("core state lock poisoned"))?;
            }
        }
        let started = self.executor.block_on(EmbeddedCore::start_cancellable(
            configs,
            platform,
            cancellation.clone(),
        ));
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("core state lock poisoned"))?;
        // Publish or finish cancellation while stop waits for full cleanup.
        let result = match started {
            Ok(core) if cancellation.is_cancelled() => {
                drop(state);
                let cleanup = self.executor.block_on(core.shutdown());
                state = self
                    .state
                    .lock()
                    .map_err(|_| io::Error::other("core state lock poisoned"))?;
                cleanup.and(Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "startup cancelled",
                )))
            }
            Ok(core) => {
                state.core = Some(Arc::new(core));
                Ok(())
            }
            Err(error) => Err(error),
        };
        state.starting = None;
        self.changed.notify_all();
        result
    }

    pub fn check(&self, json: &str) -> io::Result<()> {
        self.check_details(json).map(|_| ())
    }

    pub fn check_details(&self, json: &str) -> io::Result<serde_json::Value> {
        self.check_call_context()?;
        let mut value: serde_json::Value = serde_json::from_str(json).map_err(io::Error::other)?;
        let mut requires_tun = false;
        if let Some(inbounds) = value
            .get_mut("inbounds")
            .and_then(serde_json::Value::as_array_mut)
        {
            for inbound in inbounds {
                if inbound["type"] == "tun" && inbound.get("device_fd").is_none() {
                    // Check only compiles this local copy; it never opens or
                    // duplicates the placeholder descriptor.
                    inbound["device_fd"] = 0.into();
                    requires_tun = true;
                }
            }
        }
        let configs = parse_config(value, None)?;
        let deferred = self
            .executor
            .block_on(EmbeddedCore::check_document(configs))?;
        Ok(
            serde_json::json!({"deferredRemoteRules": deferred, "requiresTunDescriptor": requires_tun}),
        )
    }

    /// May run concurrently with start; cancels startup before waiting for it.
    pub fn stop(&self) -> io::Result<()> {
        self.check_call_context()?;
        let service = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("core state lock poisoned"))?;
            if state.stopping {
                while state.stopping {
                    state = self
                        .changed
                        .wait(state)
                        .map_err(|_| io::Error::other("core state lock poisoned"))?;
                }
                return Ok(());
            }
            state.stopping = true;
            if let Some(cancellation) = &state.starting {
                cancellation.cancel();
            }
            if let Some(probes) = &state.probes {
                probes.cancel();
            }
            while state.starting.is_some() || state.probe_users != 0 || state.probe_closing {
                state = self
                    .changed
                    .wait(state)
                    .map_err(|_| io::Error::other("core state lock poisoned"))?;
            }
            state.core.take()
        };
        let result = match service {
            Some(service) => self.executor.block_on(service.shutdown()),
            None => Ok(()),
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("core state lock poisoned"))?;
        state.stopping = false;
        self.changed.notify_all();
        result
    }

    pub fn network_changed(&self) -> io::Result<()> {
        self.with_core(|core| self.executor.block_on(core.network_changed()))
    }
    pub fn stats(&self) -> io::Result<serde_json::Value> {
        self.with_core(|core| {
            serde_json::to_value(self.executor.block_on(core.stats())?).map_err(io::Error::other)
        })
    }
    pub fn connections(&self) -> io::Result<serde_json::Value> {
        self.with_core(|core| self.executor.block_on(core.connections()))
    }
    pub fn close_connection(&self, id: &str) -> io::Result<()> {
        self.with_core(|core| self.executor.block_on(core.close_connection(id.to_owned())))
    }
    pub fn urltest_config(
        &self,
        json: &str,
        name: &str,
        url: &str,
        timeout_ms: u64,
        platform: Option<Arc<dyn Platform>>,
    ) -> io::Result<u16> {
        self.check_call_context()?;
        let configs = parse_config(serde_json::from_str(json)?, None)?;
        let name = if name == "direct" && configs.iter().any(|entry| matches!(entry, shoes::config::Config::ClientConfigGroup(group) if group.client_group == "__aerobox_direct")) { "__aerobox_direct" } else { name };
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("core state lock poisoned"))?;
        while state.probe_closing && !state.stopping && state.starting.is_none() {
            state = self
                .changed
                .wait(state)
                .map_err(|_| io::Error::other("core state lock poisoned"))?;
        }
        if state.stopping || state.starting.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "core lifecycle transition in progress",
            ));
        }
        if let Some(core) = state.core.clone() {
            drop(state);
            return self.executor.block_on(core.probe_document(
                configs,
                name.into(),
                url.into(),
                timeout_ms,
            ));
        }
        if state.probe_users >= 16 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "probe concurrency limit reached",
            ));
        }
        let probes = match &state.probes {
            Some(probes) => probes.clone(),
            None => {
                let probes = Arc::new(
                    self.executor
                        .block_on(async { StandaloneProbes::new(platform) })?,
                );
                state.probes = Some(probes.clone());
                probes
            }
        };
        state.probe_users += 1;
        drop(state);
        let result =
            self.executor
                .block_on(probes.probe(configs, name.into(), url.into(), timeout_ms));
        drop(probes);
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("core state lock poisoned"))?;
        state.probe_users -= 1;
        if state.probe_users == 0 {
            state.probe_closing = true;
            let probes = state.probes.take().expect("active probes have a context");
            drop(state);
            self.executor.block_on(probes.shutdown());
            drop(probes);
            state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("core state lock poisoned"))?;
            state.probe_closing = false;
        }
        self.changed.notify_all();
        result
    }

    pub fn is_running(&self) -> bool {
        self.state
            .lock()
            .is_ok_and(|state| state.core.as_ref().is_some_and(|core| core.is_running()))
    }
    fn with_core<T>(
        &self,
        operation: impl FnOnce(&EmbeddedCore) -> io::Result<T>,
    ) -> io::Result<T> {
        self.check_call_context()?;
        let core = self
            .state
            .lock()
            .map_err(|_| io::Error::other("core state lock poisoned"))?
            .core
            .clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "core is stopped"))?;
        operation(&core)
    }
    fn check_call_context(&self) -> io::Result<()> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "blocking host APIs must run outside Tokio and platform callbacks",
            ));
        }
        Ok(())
    }
}

impl Drop for AndroidRuntime {
    fn drop(&mut self) {
        // Normal hosts call stop explicitly. This fallback still joins all
        // service tasks before the executor is destroyed.
        if let Ok(state) = self.state.get_mut() {
            if let Some(core) = state.core.take() {
                let _ = self.executor.block_on(core.shutdown());
            }
        }
    }
}

static LOGS: OnceLock<Arc<Mutex<VecDeque<String>>>> = OnceLock::new();

struct BufferedLogs(Arc<Mutex<VecDeque<String>>>);
impl shoes::logging::LogWriter for BufferedLogs {
    fn write_log(&self, record: &log::Record, formatted: &str) {
        if let Ok(mut lines) = self.0.lock() {
            if lines.len() == 500 {
                lines.pop_front();
            }
            // The Android error store filters by a leading severity. Preserve
            // native timestamp/target context after that explicit prefix.
            let level = record.level().as_str();
            let mut line = String::with_capacity((level.len() + 1 + formatted.len()).min(4096));
            line.push_str(level);
            line.push(' ');
            // Bound retained log memory even for adversarial remote errors.
            let mut end = formatted.len().min(4096 - line.len());
            while !formatted.is_char_boundary(end) {
                end -= 1;
            }
            line.push_str(&formatted[..end]);
            lines.push_back(line);
        }
    }
    fn flush(&self) {}
}

pub fn initialize_logs(level: &str) -> io::Result<()> {
    static INITIALIZED: OnceLock<Result<(), String>> = OnceLock::new();
    let level = shoes::logging::parse_log_level(level)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid log level"))?;
    INITIALIZED
        .get_or_init(|| {
            let logs = LOGS
                .get_or_init(|| Arc::new(Mutex::new(VecDeque::new())))
                .clone();
            shoes::logging::init_multi_logger(
                vec![Box::new(BufferedLogs(logs))],
                vec![shoes::logging::Directive { name: None, level }],
            )
            .map_err(|error| error.to_string())
        })
        .as_ref()
        .map(|_| ())
        .map_err(|error| io::Error::other(error.clone()))
}

pub fn drain_logs() -> Vec<String> {
    LOGS.get()
        .and_then(|logs| logs.lock().ok())
        .map(|mut lines| lines.drain(..).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod buffered_logs_tests {
    use super::*;
    use shoes::logging::LogWriter;

    #[test]
    fn logs_expose_the_severity_consumed_by_android() {
        let lines = Arc::new(Mutex::new(VecDeque::new()));
        let writer = BufferedLogs(lines.clone());
        for level in [log::Level::Info, log::Level::Warn, log::Level::Error] {
            writer.write_log(
                &log::Record::builder().level(level).build(),
                &format!("[2026-11-28T16:00:00.000 {level} shoes::tun] message"),
            );
        }
        let retained = lines.lock().unwrap();
        assert_eq!(
            retained
                .iter()
                .map(|line| line.split_once(' ').unwrap().0)
                .collect::<Vec<_>>(),
            ["INFO", "WARN", "ERROR"],
        );
        assert_eq!(
            retained[2],
            "ERROR [2026-11-28T16:00:00.000 ERROR shoes::tun] message",
        );
    }

    #[test]
    fn logs_bound_retained_lines_and_utf8_bytes_including_the_prefix() {
        let lines = Arc::new(Mutex::new(VecDeque::new()));
        let writer = BufferedLogs(lines.clone());
        let record = log::Record::builder().level(log::Level::Error).build();
        writer.write_log(&record, "oldest");
        let message = "错误".repeat(1000);
        for _ in 0..500 {
            writer.write_log(&record, &message);
        }
        let retained = lines.lock().unwrap();
        assert_eq!(retained.len(), 500);
        for line in retained.iter() {
            assert!(line.len() <= 4096);
            assert!(line.starts_with("ERROR 错误"));
            assert!(!line.contains("oldest"));
        }
    }
}
