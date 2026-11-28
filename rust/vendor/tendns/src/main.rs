use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use hickory_proto::rr::RecordType;
use tendns::{
    cloudflare::{Change, Cloudflare},
    config::Config,
    names::{canonical_name, validate_label},
    protocol::{self, Entry, Publication, Secret, Value},
    resolver::{Clock, SystemClock},
};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(long, global = true, default_value = "tendns.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve DNS over UDP/TCP and configured HTTP/HTTPS listeners.
    Serve,
    /// Generate an encrypted TXT value without making network requests.
    Txt(TxtArgs),
    /// Generate a random base64url discovery key for the TOML configuration.
    Keygen,
    /// Add or replace private entries in Cloudflare TXT using CLOUDFLARE_API_TOKEN.
    CloudflareSet(CloudflareSetArgs),
    /// Remove a private hostname's record type from Cloudflare TXT.
    CloudflareRemove(CloudflareRemoveArgs),
}

#[derive(Args)]
struct CloudflareSetArgs {
    /// Hostname to resolve, including the label that will be encrypted.
    #[arg(long)]
    name: String,
    /// Publish at this hostname instead of hiding its first label in the parent TXT.
    #[arg(long)]
    direct: bool,
    #[command(flatten)]
    value: SetValueArgs,
    /// Refresh the whole encrypted publication's validity; defaults to the config.
    #[arg(long)]
    valid_for: Option<String>,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct SetValueArgs {
    #[arg(long, action = clap::ArgAction::Append)]
    a: Vec<Ipv4Addr>,
    #[arg(long, action = clap::ArgAction::Append)]
    aaaa: Vec<Ipv6Addr>,
    #[arg(long)]
    cname: Option<String>,
}

#[derive(Args)]
struct CloudflareRemoveArgs {
    #[arg(long)]
    name: String,
    /// Remove entries at the exact hostname instead of its parent TXT.
    #[arg(long)]
    direct: bool,
    #[arg(long = "type", value_enum, ignore_case = true)]
    kind: EntryType,
}

#[derive(Clone, Copy, ValueEnum)]
#[value(rename_all = "UPPER")]
enum EntryType {
    A,
    Aaaa,
    Cname,
}

#[derive(Args)]
struct TxtArgs {
    /// Public TXT owner name; authenticated and bound to this publication.
    #[arg(long)]
    name: String,
    /// Optional hidden single-label prefix for --a, --aaaa, and --cname.
    #[arg(long, default_value = "")]
    subdomain: String,
    #[arg(long, action = clap::ArgAction::Append)]
    a: Vec<Ipv4Addr>,
    #[arg(long, action = clap::ArgAction::Append)]
    aaaa: Vec<Ipv6Addr>,
    #[arg(long)]
    cname: Option<String>,
    /// Repeatable LABEL:TYPE:VALUE entry; use @ for the TXT owner.
    #[arg(long = "entry", value_name = "LABEL:TYPE:VALUE")]
    entries: Vec<String>,
    /// Validity duration, for example 24h or 7days; defaults to the config.
    #[arg(long)]
    valid_for: Option<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Serve => {
            let config = Config::load(&cli.config)?;
            tendns::server::serve(config).await?;
        }
        Command::Txt(args) => {
            let config = Config::load(&cli.config)?;
            println!("{}", generate_txt(&config, args)?);
        }
        Command::Keygen => println!("{}", Secret::generate()?),
        Command::CloudflareSet(args) => {
            let config = Config::load(&cli.config)?;
            let name = canonical_name(&args.name)?;
            let mut values = Vec::new();
            values.extend(args.value.a.into_iter().map(Value::A));
            values.extend(args.value.aaaa.into_iter().map(Value::Aaaa));
            if let Some(target) = args.value.cname {
                values.push(Value::Cname(canonical_name(&target)?));
            }
            let valid_for = validity(&config, args.valid_for)?;
            let outcome = Cloudflare::from_env()?
                .change(
                    &config,
                    &name,
                    args.direct,
                    Change::Set { values, valid_for },
                )
                .await?;
            println!("{} encrypted TXT at {}", outcome.action, outcome.owner);
        }
        Command::CloudflareRemove(args) => {
            let config = Config::load(&cli.config)?;
            let name = canonical_name(&args.name)?;
            let kind = match args.kind {
                EntryType::A => RecordType::A,
                EntryType::Aaaa => RecordType::AAAA,
                EntryType::Cname => RecordType::CNAME,
            };
            let outcome = Cloudflare::from_env()?
                .change(&config, &name, args.direct, Change::Remove { kind })
                .await?;
            println!("{} encrypted TXT at {}", outcome.action, outcome.owner);
        }
    }
    Ok(())
}

fn generate_txt(config: &Config, args: TxtArgs) -> Result<String> {
    let owner = canonical_name(&args.name)?;
    let discovery = config
        .discovery_for(&owner)
        .context("TXT owner is not within a configured discovery domain")?;
    let subdomain = args.subdomain.to_ascii_lowercase();
    if !subdomain.is_empty() {
        validate_label(&subdomain)?;
    }
    let mut entries = Vec::new();
    for ip in args.a {
        entries.push(Entry {
            subdomain: subdomain.clone(),
            value: Value::A(ip),
        });
    }
    for ip in args.aaaa {
        entries.push(Entry {
            subdomain: subdomain.clone(),
            value: Value::Aaaa(ip),
        });
    }
    if let Some(target) = args.cname {
        entries.push(Entry {
            subdomain,
            value: Value::Cname(canonical_name(&target)?),
        });
    }
    for entry in args.entries {
        entries.push(parse_entry(&entry)?);
    }
    let validity = validity(config, args.valid_for)?;
    let issued_at = SystemClock.now()?;
    let expires_at = issued_at
        .checked_add(validity.as_secs())
        .context("expiry overflows timestamp")?;
    let publication = Publication {
        issued_at,
        expires_at,
        entries,
    };
    protocol::encrypt(&publication, &discovery.key, &owner)
}

fn validity(config: &Config, value: Option<String>) -> Result<Duration> {
    let validity = match value {
        Some(value) => humantime::parse_duration(&value).context("invalid --valid-for duration")?,
        None => config.valid_for,
    };
    ensure!(
        validity.as_secs() > 0,
        "validity must be at least one second"
    );
    Ok(validity)
}

fn parse_entry(text: &str) -> Result<Entry> {
    let mut parts = text.splitn(3, ':');
    let label = parts.next().context("missing entry label")?;
    let kind = parts.next().context("entry must be LABEL:TYPE:VALUE")?;
    let value = parts.next().context("entry must be LABEL:TYPE:VALUE")?;
    let subdomain = if label == "@" {
        String::new()
    } else {
        validate_label(label)?;
        label.to_ascii_lowercase()
    };
    let value = match kind.to_ascii_uppercase().as_str() {
        "A" => Value::A(value.parse().context("invalid A address")?),
        "AAAA" => Value::Aaaa(value.parse().context("invalid AAAA address")?),
        "CNAME" => Value::Cname(canonical_name(value)?),
        _ => bail!("entry type must be A, AAAA, or CNAME"),
    };
    Ok(Entry { subdomain, value })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_syntax_handles_ipv6_and_relative_labels() {
        assert_eq!(
            parse_entry("NAS:AAAA:2001:db8::1").unwrap(),
            Entry {
                subdomain: "nas".into(),
                value: Value::Aaaa("2001:db8::1".parse().unwrap())
            }
        );
        assert_eq!(parse_entry("@:A:192.0.2.1").unwrap().subdomain, "");
        for entry in ["a.b:A:192.0.2.1", "nas:MX:x", "A:192.0.2.1", ":A:192.0.2.1"] {
            assert!(parse_entry(entry).is_err());
        }
    }

    #[test]
    fn cloudflare_commands_require_one_record_type() {
        for flags in [
            vec!["--a", "192.0.2.1", "--a", "192.0.2.2"],
            vec!["--aaaa", "2001:db8::1"],
            vec!["--cname", "target.net", "--direct"],
        ] {
            let mut args = vec!["tendns", "cloudflare-set", "--name", "nas.example.com"];
            args.extend(flags);
            assert!(Cli::try_parse_from(args).is_ok());
        }
        for flags in [
            vec![],
            vec!["--a", "192.0.2.1", "--aaaa", "2001:db8::1"],
            vec!["--a", "192.0.2.1", "--cname", "target.net"],
        ] {
            let mut args = vec!["tendns", "cloudflare-set", "--name", "nas.example.com"];
            args.extend(flags);
            assert!(Cli::try_parse_from(args).is_err());
        }
        for kind in ["A", "AAAA", "CNAME", "aaaa"] {
            assert!(
                Cli::try_parse_from([
                    "tendns",
                    "cloudflare-remove",
                    "--name",
                    "nas.example.com",
                    "--type",
                    kind
                ])
                .is_ok()
            );
        }
        assert!(
            Cli::try_parse_from([
                "tendns",
                "cloudflare-remove",
                "--name",
                "nas.example.com",
                "--type",
                "TXT"
            ])
            .is_err()
        );
    }
}
