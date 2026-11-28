use super::*;

struct Cleanup {
    lifetime: Option<crate::network_tasks::NetworkLifetime>,
    parent: Option<crate::network_tasks::NetworkTasks>,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(lifetime) = self.lifetime.take() {
            lifetime.cancel();
            if let Some(parent) = &self.parent {
                parent.spawn_completion(async move { lifetime.wait().await });
            }
        }
    }
}

/// A temporary outbound document shares the physical network but owns its own
/// transport tasks. It creates no listeners and never publishes a service generation.
pub(crate) async fn run(
    mut configs: Vec<Config>,
    name: String,
    url: String,
    timeout_ms: u64,
) -> io::Result<u16> {
    use crate::control::{
        probes::{ProbeQuery, ProbeState},
        runtime::Generation,
        selection::SelectionOwner,
    };
    if configs.iter().any(|entry| {
        matches!(
            entry,
            Config::Server(_) | Config::TunServer(_) | Config::ClashApi(_) | Config::CacheFile(_)
        )
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "probe document must contain no listeners or controller state",
        ));
    }
    let query = ProbeQuery::parse(
        &std::collections::HashMap::from([
            ("url".into(), url),
            ("timeout".into(), timeout_ms.to_string()),
        ]),
        false,
    )?;
    const GROUP: &str = "__aerobox_probe";
    if configs.iter().any(
        |entry| matches!(entry, Config::ClientConfigGroup(group) if group.client_group == GROUP),
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reserved probe group name",
        ));
    }
    configs.extend(serde_json::from_value::<Vec<Config>>(serde_json::json!([
        {"client_group":GROUP,"type":"selector","client_chains":[{"chain":[name]}]},
        {"address":"127.0.0.1:0","protocol":{"type":"socks"},"rules":[{"conditions":{"any_destination":true},"client_chain":GROUP}]}
    ])).map_err(io::Error::other)?);
    let parent = crate::network_tasks::NetworkTasks::current();
    let cleanup = Cleanup {
        lifetime: Some(Default::default()),
        parent: parent.clone(),
    };
    let lifetime = cleanup.lifetime.as_ref().unwrap();
    let operation = lifetime.scope(async {
        let (configs, _) = crate::config::convert_cert_paths(configs).await?;
        let mut validated = crate::config::compile_configs(configs).await?;

        validated.refresh_catalog()?;
        let mut dns = crate::dns::build_dns_registry_with_limits(
            std::mem::take(&mut validated.dns_groups),
            validated.global_limits,
        )
        .await?;
        let crate::config::ResolvedConfig::Server(server) = &validated.configs[0] else {
            unreachable!()
        };
        let resolver = dns.get_for_server(server.dns.as_ref());
        let catalog = validated
            .catalog
            .take()
            .ok_or_else(|| io::Error::other("probe catalog missing"))?;
        let mut owner = SelectionOwner::new(None)?;
        owner.activate(catalog.selection.clone())?;
        let generation = Generation {
            id: 0,
            catalog,
            rules: Vec::new(),
            leaf_udp_support: Default::default(),
            probes: ProbeState::new(resolver, dns.forbidden_ranges().to_vec()),
        };
        let result = crate::control::probes::request(&generation, GROUP, &query)
            .await
            .map(|(delay, _)| delay);
        result
    });
    let result = tokio::select! {
        biased;
        _ = async { match &parent { Some(parent) => parent.cancelled.cancelled().await, None => std::future::pending().await } } => Err(io::Error::new(io::ErrorKind::Interrupted,"probe network retired")),
        result = tokio::time::timeout(query.timeout,operation) => result.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut,"outbound probe timed out"))),
    };
    lifetime.cancel();
    lifetime.wait().await;
    result
}
