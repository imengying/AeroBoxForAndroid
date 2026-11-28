use super::AndroidRuntime;
use jni::sys::{jint, jlong};
use jni::{
    EnvUnowned, Outcome,
    objects::{Global, JByteArray, JClass, JObject, JString, JValue},
};
use serde_json::{Value, json};
use shoes::embedding::{
    ConnectionOwner, ConnectionOwnerQuery, PhysicalNetworkSnapshot, Platform, PlatformDnsQuery,
};
use std::{
    io,
    sync::{Arc, OnceLock},
};

fn runtime() -> io::Result<&'static AndroidRuntime> {
    static RUNTIME: OnceLock<Result<AndroidRuntime, String>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| AndroidRuntime::new().map_err(|error| error.to_string()))
        .as_ref()
        .map_err(|error| io::Error::other(error.clone()))
}

fn envelope(result: io::Result<Value>) -> String {
    match result {
        Ok(value) => json!({"ok": true, "value": value}).to_string(),
        Err(error) => {
            json!({"ok": false, "error": error.to_string(), "kind": format!("{:?}", error.kind())})
                .to_string()
        }
    }
}

fn emit<'local>(
    unowned: &mut EnvUnowned<'local>,
    action: impl FnOnce() -> io::Result<Value>,
) -> JString<'local> {
    let text = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
        Ok(result) => envelope(result),
        Err(_) => envelope(Err(io::Error::other("native core panicked"))),
    };
    match unowned.with_env(|env| env.new_string(text)).into_outcome() {
        Outcome::Ok(value) => value,
        _ => JString::null(),
    }
}

fn read_string(unowned: &mut EnvUnowned<'_>, value: &JString<'_>) -> io::Result<String> {
    match unowned
        .with_env(|env| value.try_to_string(env))
        .into_outcome()
    {
        Outcome::Ok(value) => Ok(value),
        Outcome::Err(error) => Err(io::Error::other(error.to_string())),
        Outcome::Panic(_) => Err(io::Error::other("JNI string conversion failed")),
    }
}

struct AndroidPlatform {
    vm: jni::JavaVM,
    callbacks: Global<JObject<'static>>,
    system_dns: bool,
}
impl AndroidPlatform {
    fn new(env: &mut jni::Env<'_>, callbacks: JObject<'_>) -> jni::errors::Result<Self> {
        // A JNI failure must not silently select a different DNS transport.
        let system_dns = env
            .call_method(
                &callbacks,
                jni::jni_str!("supportsSystemDns"),
                jni::jni_sig!("()Z"),
                &[],
            )?
            .z()?;
        Ok(Self {
            vm: env.get_java_vm()?,
            callbacks: env.new_global_ref(callbacks)?,
            system_dns,
        })
    }
}
impl Platform for AndroidPlatform {
    fn connection_owner(&self, query: ConnectionOwnerQuery) -> io::Result<Option<ConnectionOwner>> {
        query.validate()?;
        let json = self
            .vm
            .attach_current_thread(
                |env: &mut jni::Env| -> jni::errors::Result<Option<String>> {
                    let source = env.new_string(query.source.ip().to_string())?;
                    let destination = env.new_string(query.destination.ip().to_string())?;
                    let value = env
                        .call_method(
                            &self.callbacks,
                            jni::jni_str!("connectionOwner"),
                            jni::jni_sig!(
                                "(ILjava/lang/String;ILjava/lang/String;I)Ljava/lang/String;"
                            ),
                            &[
                                JValue::Int(query.ip_protocol.into()),
                                JValue::Object(&source),
                                JValue::Int(query.source.port().into()),
                                JValue::Object(&destination),
                                JValue::Int(query.destination.port().into()),
                            ],
                        )?
                        .l()?;
                    if value.is_null() {
                        return Ok(None);
                    }
                    let value = env.cast_local::<JString>(value)?;
                    let length = env
                        .call_method(&value, jni::jni_str!("length"), jni::jni_sig!("()I"), &[])?
                        .i()?;
                    if !(0..=32768).contains(&length) {
                        return Ok(None);
                    }
                    Ok(Some(value.try_to_string(env)?))
                },
            )
            .map_err(|error| io::Error::other(error.to_string()))?;
        match json {
            Some(json) => ConnectionOwner::from_json(&json),
            None => Ok(None),
        }
    }

    fn supports_system_dns(&self) -> bool {
        self.system_dns
    }

    fn exchange_system_dns(
        self: Arc<Self>,
        query: PlatformDnsQuery,
    ) -> shoes::resolver::DnsExchangeFuture {
        Box::pin(super::system_dns::exchange(self, query))
    }

    fn protect(&self, fd: i32) -> io::Result<()> {
        let allowed = self
            .vm
            .attach_current_thread(|env: &mut jni::Env| -> jni::errors::Result<bool> {
                env.call_method(
                    &self.callbacks,
                    jni::jni_str!("protect"),
                    jni::jni_sig!("(I)Z"),
                    &[JValue::Int(fd)],
                )?
                .z()
            })
            .map_err(|error| io::Error::other(error.to_string()))?;
        if allowed {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VpnService.protect returned false",
            ))
        }
    }
    fn physical_networks(&self) -> io::Result<PhysicalNetworkSnapshot> {
        let json = self
            .vm
            .attach_current_thread(|env: &mut jni::Env| -> jni::errors::Result<String> {
                let value = env
                    .call_method(
                        &self.callbacks,
                        jni::jni_str!("physicalNetworks"),
                        jni::jni_sig!("()Ljava/lang/String;"),
                        &[],
                    )?
                    .l()?;
                env.cast_local::<JString>(value)?.try_to_string(env)
            })
            .map_err(|error| io::Error::other(error.to_string()))?;
        PhysicalNetworkSnapshot::from_json(&json)
    }

    fn protect_on_network(&self, fd: i32, generation: u64, handle: u64) -> io::Result<()> {
        let allowed = self
            .vm
            .attach_current_thread(|env: &mut jni::Env| -> jni::errors::Result<bool> {
                env.call_method(
                    &self.callbacks,
                    jni::jni_str!("protectOnNetwork"),
                    jni::jni_sig!("(IJJ)Z"),
                    &[
                        JValue::Int(fd),
                        // JNI Long preserves all 64 bits; Kotlin treats identifiers
                        // as unsigned when encoding JSON and comparing sort order.
                        JValue::Long(generation as jlong),
                        JValue::Long(handle as jlong),
                    ],
                )?
                .z()
            })
            .map_err(|error| io::Error::other(error.to_string()))?;
        if allowed {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "platform refused physical-network socket protection",
            ))
        }
    }

    fn dns_servers(&self) -> io::Result<Vec<std::net::SocketAddr>> {
        let json = self
            .vm
            .attach_current_thread(|env: &mut jni::Env| -> jni::errors::Result<String> {
                let value = env
                    .call_method(
                        &self.callbacks,
                        jni::jni_str!("dnsServers"),
                        jni::jni_sig!("()Ljava/lang/String;"),
                        &[],
                    )?
                    .l()?;
                env.cast_local::<JString>(value)?.try_to_string(env)
            })
            .map_err(|error| io::Error::other(error.to_string()))?;
        let values: Vec<String> = serde_json::from_str(&json).map_err(io::Error::other)?;
        values
            .into_iter()
            .map(|address| {
                address
                    .parse()
                    .or_else(|_| {
                        address
                            .parse::<std::net::IpAddr>()
                            .map(|ip| std::net::SocketAddr::new(ip, 53))
                    })
                    .map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("invalid physical DNS address: {error}"),
                        )
                    })
            })
            .collect()
    }
}

impl super::system_dns::DnsCallbacks for AndroidPlatform {
    fn start(&self, id: u64, query: &PlatformDnsQuery) -> io::Result<()> {
        self.vm
            .attach_current_thread(|env: &mut jni::Env| -> jni::errors::Result<()> {
                let bytes = env.byte_array_from_slice(&query.message)?;
                env.call_method(
                    &self.callbacks,
                    jni::jni_str!("startDnsQuery"),
                    jni::jni_sig!("(JJJ[B)V"),
                    &[
                        JValue::Long(id as jlong),
                        JValue::Long(query.network.generation as jlong),
                        JValue::Long(query.network.handle as jlong),
                        JValue::Object(&bytes),
                    ],
                )?
                .v()
            })
            .map_err(|error| io::Error::other(error.to_string()))
    }

    fn cancel(&self, id: u64) {
        let result =
            self.vm
                .attach_current_thread(|env: &mut jni::Env| -> jni::errors::Result<()> {
                    env.call_method(
                        &self.callbacks,
                        jni::jni_str!("cancelDnsQuery"),
                        jni::jni_sig!("(J)V"),
                        &[JValue::Long(id as jlong)],
                    )?
                    .v()
                });
        if let Err(error) = result {
            log::debug!("platform DNS cancellation failed: {error}");
        }
    }
}

/// Completion is deliberately independent of AndroidRuntime and its lifecycle
/// locks; Android may invoke this before startDnsQuery returns on the same thread.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_aerobox_core_native_RustCoreNative_nativeDnsQueryComplete<
    'local,
>(
    mut unowned: EnvUnowned<'local>,
    _: JClass<'local>,
    id: jlong,
    answer: JByteArray<'local>,
    rcode: jint,
    errno: jint,
    message: JString<'local>,
) {
    let result = unowned
        .with_env(|env| -> jni::errors::Result<io::Result<Vec<u8>>> {
            Ok((|| -> io::Result<Vec<u8>> {
                if !answer.is_null() {
                    let length = answer.len(env).map_err(io::Error::other)?;
                    if !(12..=65535).contains(&length) || errno != 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid platform DNS completion",
                        ));
                    }
                    // The actual packet (including extended RCODE) is authoritative.
                    return env.convert_byte_array(&answer).map_err(io::Error::other);
                }
                let detail = if message.is_null() {
                    "Android DNS query failed".to_owned()
                } else {
                    let length = env
                        .call_method(&message, jni::jni_str!("length"), jni::jni_sig!("()I"), &[])
                        .and_then(|value| value.i())
                        .map_err(io::Error::other)?;
                    if !(0..=4096).contains(&length) {
                        "Android DNS error message too long".to_owned()
                    } else {
                        message.try_to_string(env).map_err(io::Error::other)?
                    }
                };
                let kind = if errno > 0 {
                    io::Error::from_raw_os_error(errno).kind()
                } else {
                    io::ErrorKind::InvalidData
                };
                Err(io::Error::new(
                    kind,
                    format!("{detail} (errno={errno}, rcode={rcode})"),
                ))
            })())
        })
        .into_outcome();
    let result = match result {
        Outcome::Ok(result) => result,
        Outcome::Err(error) => Err(io::Error::other(error.to_string())),
        Outcome::Panic(_) => Err(io::Error::other("platform DNS completion panicked")),
    };
    super::system_dns::complete(id as u64, result);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_aerobox_core_native_RustCoreNative_nativeInit<'local>(
    mut env: EnvUnowned<'local>,
    _: JClass<'local>,
    level: JString<'local>,
) -> JString<'local> {
    let level = read_string(&mut env, &level);
    emit(&mut env, || {
        super::initialize_logs(&level?)?;
        runtime()?;
        Ok(json!({"version": env!("CARGO_PKG_VERSION"), "backend": "shoes-rustcrypto"}))
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_aerobox_core_native_RustCoreNative_nativeStart<'local>(
    mut env: EnvUnowned<'local>,
    _: JClass<'local>,
    config: JString<'local>,
    fd: jint,
    callbacks: JObject<'local>,
) -> JString<'local> {
    let config = read_string(&mut env, &config);
    let platform = match env
        .with_env(|env| AndroidPlatform::new(env, callbacks))
        .into_outcome()
    {
        Outcome::Ok(platform) => Ok(platform),
        Outcome::Err(error) => Err(io::Error::other(error.to_string())),
        Outcome::Panic(_) => Err(io::Error::other("JNI callback conversion failed")),
    };
    emit(&mut env, || {
        runtime()?.start(&config?, (fd >= 0).then_some(fd), Some(Arc::new(platform?)))?;
        Ok(Value::Null)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_aerobox_core_native_RustCoreNative_nativeCheck<'local>(
    mut env: EnvUnowned<'local>,
    _: JClass<'local>,
    config: JString<'local>,
) -> JString<'local> {
    let config = read_string(&mut env, &config);
    emit(&mut env, || runtime()?.check_details(&config?))
}

macro_rules! no_args {
    ($name:ident, $action:expr) => {
        #[unsafe(no_mangle)]
        pub extern "system" fn $name<'local>(
            mut env: EnvUnowned<'local>,
            _: JClass<'local>,
        ) -> JString<'local> {
            emit(&mut env, $action)
        }
    };
}
no_args!(
    Java_com_aerobox_core_native_RustCoreNative_nativeStop,
    || {
        runtime()?.stop()?;
        Ok(Value::Null)
    }
);
no_args!(
    Java_com_aerobox_core_native_RustCoreNative_nativeNetworkChanged,
    || {
        runtime()?.network_changed()?;
        Ok(Value::Null)
    }
);
no_args!(
    Java_com_aerobox_core_native_RustCoreNative_nativeStats,
    || runtime()?.stats()
);
no_args!(
    Java_com_aerobox_core_native_RustCoreNative_nativeConnections,
    || runtime()?.connections()
);
no_args!(
    Java_com_aerobox_core_native_RustCoreNative_nativeIsRunning,
    || Ok(json!(runtime()?.is_running()))
);
no_args!(
    Java_com_aerobox_core_native_RustCoreNative_nativeDrainLogs,
    || Ok(json!(super::drain_logs()))
);

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_aerobox_core_native_RustCoreNative_nativeCloseConnection<'local>(
    mut env: EnvUnowned<'local>,
    _: JClass<'local>,
    id: JString<'local>,
) -> JString<'local> {
    let id = read_string(&mut env, &id);
    emit(&mut env, || {
        runtime()?.close_connection(&id?)?;
        Ok(Value::Null)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_aerobox_core_native_RustCoreNative_nativeUrlTestConfig<'local>(
    mut env: EnvUnowned<'local>,
    _: JClass<'local>,
    config: JString<'local>,
    name: JString<'local>,
    url: JString<'local>,
    timeout_ms: jlong,
    callbacks: JObject<'local>,
) -> JString<'local> {
    let config = read_string(&mut env, &config);
    let name = read_string(&mut env, &name);
    let url = read_string(&mut env, &url);
    let platform = match env
        .with_env(|env| AndroidPlatform::new(env, callbacks))
        .into_outcome()
    {
        Outcome::Ok(platform) => Ok(platform),
        Outcome::Err(error) => Err(io::Error::other(error.to_string())),
        Outcome::Panic(_) => Err(io::Error::other("JNI callback conversion failed")),
    };
    emit(&mut env, || {
        let timeout_ms = u64::try_from(timeout_ms)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "negative timeout"))?;
        Ok(json!(runtime()?.urltest_config(
            &config?,
            &name?,
            &url?,
            timeout_ms,
            Some(Arc::new(platform?))
        )?))
    })
}
