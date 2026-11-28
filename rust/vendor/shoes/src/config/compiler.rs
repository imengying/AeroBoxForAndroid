//! Private routing drafts preserve expansion-before-settings-validation ordering.

use std::collections::HashMap;
use std::io;

use super::composition::{MAX_HOPS, MAX_NODES, invalid};
use super::plan_ops;
use super::resolved::{ChainPlan, HopPlan, ResolvedClientChain, ResolvedClientConfig};
use super::{ClientChainHop, ClientConfig, ConfigSelection, GlobalLimits};
use crate::option_util::OneOrSome;

#[derive(Debug, Clone)]
pub(super) enum DraftClient {
    Pending { source: ClientConfig },
    Ready(ResolvedClientConfig),
}

pub(super) type Groups = HashMap<String, HopPlan<DraftClient>>;

#[derive(Default)]
pub(super) struct NodeBudget {
    nodes: usize,
}

impl NodeBudget {
    pub(super) fn charge(&mut self, nodes: usize) -> io::Result<()> {
        self.nodes = self.nodes.saturating_add(nodes);
        if self.nodes > MAX_NODES {
            return Err(invalid("client composition exceeds 16384 nodes"));
        }
        Ok(())
    }
}

impl DraftClient {
    pub(super) fn resolved(&self) -> &ResolvedClientConfig {
        match self {
            Self::Ready(client) => client,
            Self::Pending { .. } => unreachable!("group settings have been validated"),
        }
    }

    pub(super) fn origin_mut(&mut self) -> &mut Option<crate::control::catalog::MemberOrigin> {
        match self {
            Self::Pending { source, .. } => &mut source.control,
            Self::Ready(client) => &mut client.control,
        }
    }
}

fn draft_client(source: ClientConfig, budget: &mut NodeBudget) -> io::Result<DraftClient> {
    budget.charge(1)?;
    Ok(DraftClient::Pending { source })
}

pub(super) fn expand(
    hops: OneOrSome<ClientChainHop>,
    groups: &Groups,
    budget: &mut NodeBudget,
) -> io::Result<ChainPlan<DraftClient>> {
    expand_with(hops, groups, budget, &mut Ok)
}

pub(super) fn compile_client(
    client: ClientConfig,
    groups: &Groups,
    pems: &HashMap<String, String>,
    limits: GlobalLimits,
) -> io::Result<ResolvedClientConfig> {
    let chain = compile_chain(
        OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(client))),
        groups,
        pems,
        limits,
    )?;
    match chain.hops {
        OneOrSome::One(HopPlan::Single(client)) => Ok(client),
        _ => unreachable!("an inline client compiles to a single hop"),
    }
}

pub(super) fn compile_chain(
    hops: OneOrSome<ClientChainHop>,
    groups: &Groups,
    pems: &HashMap<String, String>,
    limits: GlobalLimits,
) -> io::Result<ResolvedClientChain> {
    let draft = expand_with(hops, groups, &mut NodeBudget::default(), &mut |client| {
        lower_client(client, pems, limits).map(DraftClient::Ready)
    })?;
    lower_chain(draft, pems, limits)
}

fn expand_with(
    hops: OneOrSome<ClientChainHop>,
    groups: &Groups,
    budget: &mut NodeBudget,
    inline: &mut impl FnMut(DraftClient) -> io::Result<DraftClient>,
) -> io::Result<ChainPlan<DraftClient>> {
    fn selection(
        value: ConfigSelection<ClientConfig>,
        _groups: &Groups,
        budget: &mut NodeBudget,
    ) -> io::Result<ConfigSelection<DraftClient>> {
        Ok(match value {
            ConfigSelection::Config(client) => {
                ConfigSelection::Config(draft_client(client, budget)?)
            }
            ConfigSelection::GroupName(name) => ConfigSelection::GroupName(name),
        })
    }
    let pending = plan_ops::map_one(hops, &mut |hop| {
        let (pool, values) = match hop {
            ClientChainHop::Single(value) => {
                (false, OneOrSome::One(selection(value, groups, budget)?))
            }
            ClientChainHop::Pool(values) => {
                budget.charge(1)?;
                (
                    true,
                    plan_ops::map_one(values, &mut |value| selection(value, groups, budget))?,
                )
            }
        };
        // Carrier expansion for the whole stage precedes inline settings validation.
        let values = plan_ops::map_one(values, &mut |value| {
            Ok::<_, io::Error>(match value {
                ConfigSelection::Config(client) => ConfigSelection::Config(inline(client)?),
                ConfigSelection::GroupName(name) => ConfigSelection::GroupName(name),
            })
        })?;
        for value in values.iter() {
            if let ConfigSelection::GroupName(name) = value
                && !groups.contains_key(name)
            {
                return Err(invalid(format!("Unknown client group: {name}")));
            }
        }
        Ok::<_, io::Error>((pool, values))
    })?;
    // Referenced subtrees are charged before cloning.
    let mut nodes = 0usize;
    let mut length = 0usize;
    for (pool, values) in pending.iter() {
        let mut longest = 0usize;
        nodes = nodes.saturating_add(usize::from(*pool));
        for value in values.iter() {
            let (count, hops) = match value {
                ConfigSelection::Config(client) => (client_nodes(client, usize::from(*pool))?, 1),
                ConfigSelection::GroupName(name) => {
                    let size = measure(&groups[name], usize::from(*pool))?;
                    budget.charge(size.0)?;
                    size
                }
            };
            nodes = nodes.saturating_add(count);
            longest = longest.max(hops);
            if nodes > MAX_NODES {
                return Err(invalid("client composition exceeds 16384 nodes"));
            }
        }
        length = length.saturating_add(longest);
        if length > MAX_HOPS {
            return Err(invalid("client composition exceeds 16384 nodes or 64 hops"));
        }
    }
    let hops = plan_ops::map_one(pending, &mut |(pool, values)| {
        let mut hops = values.into_vec().into_iter().map(|value| match value {
            ConfigSelection::Config(client) => HopPlan::Single(client),
            ConfigSelection::GroupName(name) => {
                #[cfg(test)]
                tests::CLONED_NODES.with(|count| {
                    count.set(count.get() + measure(&groups[&name], 0).unwrap().0);
                });
                groups[&name].clone()
            }
        });
        Ok::<_, io::Error>(if pool {
            plan_ops::pool_choice(
                hops.map(|hop| ChainPlan {
                    hops: OneOrSome::One(hop),
                })
                .collect(),
            )
        } else {
            hops.next().expect("single stage has one selection")
        })
    })?;
    plan_ops::validate(&hops, client_nodes, validate_position)?;
    Ok(ChainPlan { hops })
}

pub(super) fn measure(hop: &HopPlan<DraftClient>, depth: usize) -> io::Result<(usize, usize)> {
    plan_ops::measure(hop, depth, client_nodes)
}

fn client_nodes(client: &DraftClient, depth: usize) -> io::Result<usize> {
    match client {
        DraftClient::Ready(client) => super::composition::client_nodes(client, depth),
        DraftClient::Pending { .. } => Ok(1),
    }
}

fn validate_position(client: &DraftClient, offset: usize) -> io::Result<()> {
    match client {
        DraftClient::Ready(client) => super::composition::validate_position(client, offset),
        DraftClient::Pending { source, .. } => {
            source.validate_quic_key_exchange(offset == 0)?;
            crate::quic_client::validate(source, offset == 0)?;
            super::composition::validate_position_flags(source.protocol.is_direct(), offset)
        }
    }
}

pub(super) fn lower_chain(
    chain: ChainPlan<DraftClient>,
    pems: &HashMap<String, String>,
    limits: GlobalLimits,
) -> io::Result<ResolvedClientChain> {
    plan_ops::map_chain(chain, &mut |client| lower_client(client, pems, limits))
}

pub(super) fn lower_client(
    client: DraftClient,
    pems: &HashMap<String, String>,
    _limits: GlobalLimits,
) -> io::Result<ResolvedClientConfig> {
    match client {
        DraftClient::Ready(client) => Ok(client),
        DraftClient::Pending { source } => super::validate::resolve_client_config(source, pems),
    }
}

#[cfg(test)]
mod tests {
    thread_local! {
        pub(super) static CLONED_NODES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }
}
