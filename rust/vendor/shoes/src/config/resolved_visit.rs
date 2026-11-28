use std::io;

use super::ValidatedConfigs;
use super::client_visit::sorted_targets;
use super::resolved::{
    ResolvedClientChain as ClientChain, ResolvedClientConfig as ClientConfig,
    ResolvedClientHop as ClientChainHop, ResolvedConfig as Config,
    ResolvedRuleActionConfig as RuleActionConfig, ResolvedRuleConfig as RuleConfig,
    ResolvedServerProxyConfig as ServerProxyConfig,
};
use crate::option_util::NoneOrSome;

type Visitor<'a> = dyn FnMut(&mut ClientConfig) -> io::Result<()> + 'a;

pub(crate) fn rules(configs: &[Config]) -> impl Iterator<Item = &RuleConfig> {
    configs.iter().flat_map(|config| {
        let (rules, protocol) = match config {
            Config::Server(server) => (&server.rules, Some(&server.protocol)),
            Config::TunServer(tun) => (&tun.rules, None),
        };
        rules
            .iter()
            .chain(protocol.into_iter().flat_map(protocol_rules))
    })
}

fn protocol_rules(protocol: &ServerProxyConfig) -> Box<dyn Iterator<Item = &RuleConfig> + '_> {
    let mut targets = Vec::new();
    match protocol {
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,

            reality_targets,
            ..
        } => {
            for target in tls_targets
                .values()
                .chain(default_tls_target.iter().map(Box::as_ref))
            {
                targets.push((&target.override_rules, &target.protocol));
            }

            for target in reality_targets.values() {
                targets.push((&target.override_rules, &target.protocol));
            }
        }
        ServerProxyConfig::Websocket { targets: websocket } => {
            targets.extend(
                websocket
                    .iter()
                    .map(|target| (&target.override_rules, &target.protocol)),
            );
        }

        _ => {}
    }
    Box::new(
        targets
            .into_iter()
            .flat_map(|(rules, protocol)| rules.iter().chain(protocol_rules(protocol))),
    )
}

pub(crate) fn visit_chain(chain: &mut ClientChain, visitor: &mut Visitor<'_>) -> io::Result<()> {
    for hop in chain.hops.iter_mut() {
        visit_hop(hop, visitor)?;
    }
    Ok(())
}

pub(crate) fn visit_hop(hop: &mut ClientChainHop, visitor: &mut Visitor<'_>) -> io::Result<()> {
    super::plan_ops::visit_leaves(hop, &mut |client| visit_client(client, visitor))
}

pub(crate) fn visit_client(client: &mut ClientConfig, visitor: &mut Visitor<'_>) -> io::Result<()> {
    visitor(client)
}

pub(crate) fn client_tree(client: &ClientConfig) -> impl Iterator<Item = &ClientConfig> {
    std::iter::once(client)
}

fn visit_rules(rules: &mut NoneOrSome<RuleConfig>, visitor: &mut Visitor<'_>) -> io::Result<()> {
    for rule in rules.iter_mut() {
        if let RuleActionConfig::Allow { client_chains, .. } = &mut rule.action {
            for chain in client_chains.iter_mut() {
                visit_chain(chain, visitor)?;
            }
        }
    }
    Ok(())
}

fn visit_protocol(protocol: &mut ServerProxyConfig, visitor: &mut Visitor<'_>) -> io::Result<()> {
    match protocol {
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,

            reality_targets,
            ..
        } => {
            for (_, target) in sorted_targets(tls_targets) {
                visit_rules(&mut target.override_rules, visitor)?;
                visit_protocol(&mut target.protocol, visitor)?;
            }
            if let Some(target) = default_tls_target {
                visit_rules(&mut target.override_rules, visitor)?;
                visit_protocol(&mut target.protocol, visitor)?;
            }

            for (_, target) in sorted_targets(reality_targets) {
                visit_rules(&mut target.override_rules, visitor)?;
                visit_protocol(&mut target.protocol, visitor)?;
                for hop in target.dest_client_chain.iter_mut() {
                    visit_hop(hop, visitor)?;
                }
            }
        }
        ServerProxyConfig::Websocket { targets } => {
            for target in targets.iter_mut() {
                visit_rules(&mut target.override_rules, visitor)?;
                visit_protocol(&mut target.protocol, visitor)?;
            }
        }

        _ => {}
    }
    Ok(())
}

impl ValidatedConfigs {
    pub(crate) fn refresh_catalog(&mut self) -> io::Result<()> {
        if let Some(mut catalog) = self.catalog.take() {
            self.visit_clients(&mut |client| {
                catalog.update_client(client);
                Ok(())
            })?;
            self.catalog = Some(catalog);
        }
        Ok(())
    }

    pub(crate) fn visit_clients(&mut self, visitor: &mut Visitor<'_>) -> io::Result<()> {
        for source in &mut self.remote_rules {
            if let Some(download) = &mut source.download {
                visit_chain(&mut download.client_chain, visitor)?;
            }
        }
        for config in &mut self.configs {
            match config {
                Config::Server(server) => {
                    visit_rules(&mut server.rules, visitor)?;
                    visit_protocol(&mut server.protocol, visitor)?;
                }
                Config::TunServer(tun) => visit_rules(&mut tun.rules, visitor)?,
            }
        }

        for group in &mut self.dns_groups {
            for spec in &mut group.specs {
                for chain in &mut spec.client_chains {
                    visit_chain(chain, visitor)?;
                }
            }
        }
        Ok(())
    }
}
