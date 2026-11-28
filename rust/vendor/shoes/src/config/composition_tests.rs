use crate::config::create_server_configs;
use serde_json::{Value, json};

use crate::config::ResolvedClientConfig as ClientConfig;

fn selector(members: Value) -> Value {
    let members: Vec<_> = members
        .as_array()
        .unwrap()
        .iter()
        .map(|member| {
            if member.get("chain").is_some() {
                member.clone()
            } else {
                json!({"chain":[member]})
            }
        })
        .collect();
    json!({"client_group":"out", "type":"selector",
        "client_chains":members})
}

fn proxy(name: &str) -> Value {
    json!({"name":name, "address":"192.0.2.10:80", "protocol":{"type":"http"}})
}

fn server(chain: Value) -> Value {
    json!({"address":"127.0.0.1:0", "protocol":{"type":"socks"},
        "rules":[{"mask":"0.0.0.0/0", "action":"allow", "client_chain":chain}]})
}

fn validate(values: Value) -> std::io::Result<crate::config::ValidatedConfigs> {
    create_server_configs(serde_json::from_value(values).unwrap())
}

#[test]
fn composition_validation_preserves_fixed_and_variable_prefixes() {
    use crate::config::{ResolvedClientChain, ResolvedClientHop, composition};
    use crate::option_util::OneOrSome;

    let validate = |pools: Vec<Vec<ClientConfig>>| {
        let hops = pools
            .into_iter()
            .map(|clients| {
                composition::pool_choice(
                    clients
                        .into_iter()
                        .map(|client| ResolvedClientChain {
                            hops: OneOrSome::One(ResolvedClientHop::Single(client)),
                        })
                        .collect(),
                )
            })
            .collect();
        composition::validate(&OneOrSome::Some(hops))
    };
    let proxy: ClientConfig = crate::config::test_support::from_json(proxy("proxy")).unwrap();
    let protocol = json!({"type":"naive", "username":"user", "password":"secret"});
    for protocol in [protocol.clone(), json!({"type":"tls", "protocol":protocol})] {
        let naive: ClientConfig = crate::config::test_support::from_json(json!({
            "address":"192.0.2.20:443", "protocol":protocol
        }))
        .unwrap();
        validate(vec![vec![proxy.clone()], vec![naive.clone()]]).unwrap();
        validate(vec![
            vec![naive.clone(), proxy.clone()],
            vec![proxy.clone()],
        ])
        .unwrap();
        for hops in [
            vec![vec![proxy.clone(), proxy.clone()], vec![naive.clone()]],
            vec![
                vec![proxy.clone(), proxy.clone()],
                vec![proxy.clone()],
                vec![naive],
            ],
        ] {
            validate(hops).unwrap();
        }
    }
}



#[test]
fn naive_choice_entries_and_shared_variable_suffixes_are_supported() {
    let naive = json!({"address":"192.0.2.20:443",
        "protocol":{"type":"naive", "username":"user", "password":"secret"}});
    let groups = vec![
        json!({"client_group":"inner", "client_chains":[
            {"chain":[naive]}, {"chain":[proxy("prefix"), naive]}
        ]}),
        json!({"client_group":"outer", "client_chains":[
            {"chain":["inner"]}, {"chain":[proxy("other")]}
        ]}),
    ];
    for route in [
        json!("outer"),
        json!(["outer", naive]),
        json!([{"pool":[proxy("a"), proxy("b")]}, "outer"]),
    ] {
        let mut configs = groups.clone();
        configs.push(server(route));
        validate(json!(configs)).unwrap();
    }
    validate(json!([{"client_group":"out", "client_chains":[
        {"chain":[proxy("fixed")]},
        {"chain":[{"pool":[proxy("a"), proxy("b")]}, naive]}
    ]}]))
    .unwrap();
}





#[test]
fn naive_acceptance_covers_prefixes_wrappers_and_dns() {
    let naive = json!({"type":"naive", "username":"user", "password":"secret"});
    for protocol in [
        naive.clone(),
        json!({"type":"tls", "verify":false, "protocol":naive.clone()}),
        json!({"type":"ws", "protocol":naive.clone()}),
        json!({"type":"reality", "public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "sni_hostname":"example.com", "protocol":naive.clone()}),
    ] {
        let hop = json!({"name":"naive", "address":"192.0.2.20:443", "protocol":protocol});
        let connector = crate::tcp::proxy_connector_impl::create_proxy_connector(
            crate::config::test_support::from_json(hop.clone()).unwrap(),
            std::sync::Arc::new(crate::resolver::NativeResolver::new()),
        )
        .unwrap()
        .unwrap();
        assert!(connector.needs_carrier_dialer());
        validate(json!([
            selector(json!([proxy("a"), proxy("b")])),
            server(json!(["out", hop.clone()]))
        ]))
        .unwrap();
        validate(json!([
            selector(json!([hop.clone()])),
            server(json!([{"pool":[proxy("a"), proxy("b")]}, "out"]))
        ]))
        .unwrap();
        validate(
            json!([selector(json!([proxy("a"), proxy("b")])),
            {"dns_group":"dns", "dns_servers":[{"url":"tcp://192.0.2.53", "client_chain":{"chain":["out", hop]}}]}])
        ).unwrap();
    }
}





#[test]
fn naive_allows_fixed_and_shared_variable_prefixes() {
    let naive = json!({"name":"naive", "address":"192.0.2.20:443",
        "protocol":{"type":"naive", "username":"user", "password":"secret"}});
    validate(json!([
        selector(json!([proxy("a")])),
        server(json!(["out", naive.clone()]))
    ]))
    .unwrap();
    validate(json!([
        selector(json!([naive.clone(), proxy("a")])),
        server(json!("out"))
    ]))
    .unwrap();
    validate(json!([
        selector(json!([proxy("a"), proxy("b")])),
        server(json!([naive.clone(), "out"]))
    ]))
    .unwrap();
    validate(json!([server(
        json!([{"pool":[proxy("a"), proxy("b")]}, naive])
    )]))
    .unwrap();
}



#[test]
fn selector_routes_do_not_enumerate_pool_products() {
    validate(json!([
        selector(json!([proxy("a"), proxy("b")])),
        server(json!(vec!["out"; 12]))
    ]))
    .unwrap();
}

#[test]
fn physical_hop_limit_accepts_sixty_four_flat_hops_but_not_sixty_five() {
    let hop = json!({"address":"192.0.2.10:80", "protocol":{"type":"http"}});
    validate(json!([server(json!(vec![hop.clone(); 64]))])).unwrap();
    let error = validate(json!([server(json!(vec![hop; 65]))]))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("64 hops"), "{error}");
}

#[test]
fn physical_hop_limit_uses_the_longest_alternative_plus_the_suffix() {
    let hop = json!({"address":"192.0.2.10:80", "protocol":{"type":"http"}});
    let group = selector(json!([
        {"name":"short", "chain":vec![hop.clone(); 31]},
        {"name":"long", "chain":vec![hop.clone(); 32]}
    ]));
    for suffix in [32, 33] {
        let mut route = vec![json!("out")];
        route.extend(vec![hop.clone(); suffix]);
        let result = validate(json!([group, server(json!(route))]));
        if suffix == 32 {
            result.unwrap();
        } else {
            let error = result.err().unwrap().to_string();
            assert!(error.contains("64 hops"), "{error}");
        }
    }
}
