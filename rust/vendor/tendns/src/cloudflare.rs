use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use hickory_proto::{
    op::{Message, OpCode},
    rr::{Name, RData, Record, RecordType, rdata::TXT},
};
use reqwest::{Client, ClientBuilder, Method, RequestBuilder, header, redirect};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    config::Config,
    names::{canonical_name, canonical_wire},
    policy::Discovery,
    protocol::{self, Entry, Publication, Value},
    resolver::{Clock, SystemClock, collect_publications},
};

const API_URL: &str = "https://api.cloudflare.com/client/v4/";
const MAX_RESPONSE: usize = 1024 * 1024;
const MAX_PAGES: u32 = 100;

pub struct Cloudflare {
    client: Client,
    base: Url,
}

pub enum Change {
    Set {
        values: Vec<Value>,
        valid_for: Duration,
    },
    Remove {
        kind: RecordType,
    },
}

#[derive(Debug)]
pub struct Outcome {
    pub owner: Name,
    pub action: &'static str,
}

#[derive(Deserialize)]
struct ApiResponse<T> {
    success: bool,
    result: Option<T>,
    result_info: Option<PageInfo>,
}

#[derive(Deserialize)]
struct PageInfo {
    page: u32,
    total_pages: u32,
}

#[derive(Deserialize)]
struct Zone {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct DnsRecord {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    content: String,
    ttl: u32,
}

#[derive(Deserialize)]
struct DeletedRecord {
    id: String,
}

#[derive(Serialize)]
struct WriteRecord<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    name: String,
    content: &'a str,
    ttl: u32,
}

impl Cloudflare {
    pub fn from_env() -> Result<Self> {
        let token = Zeroizing::new(std::env::var("CLOUDFLARE_API_TOKEN").map_err(|_| {
            anyhow::anyhow!(
                "set CLOUDFLARE_API_TOKEN to a token with Zone Read and DNS Write permissions"
            )
        })?);
        Self::new(&token)
    }

    pub fn new(token: &str) -> Result<Self> {
        let client = Self::client_builder(token)?
            .build()
            .context("cannot initialize Cloudflare HTTPS client")?;
        Ok(Self {
            client,
            base: Url::parse(API_URL).expect("literal API URL"),
        })
    }

    fn client_builder(token: &str) -> Result<ClientBuilder> {
        ensure!(
            !token.is_empty() && !token.bytes().any(|b| b.is_ascii_whitespace()),
            "CLOUDFLARE_API_TOKEN must be nonempty and contain no whitespace"
        );
        let bearer = Zeroizing::new(format!("Bearer {token}"));
        let mut authorization = header::HeaderValue::from_str(&bearer)
            .map_err(|_| anyhow::anyhow!("invalid CLOUDFLARE_API_TOKEN"))?;
        authorization.set_sensitive(true);
        let mut headers = header::HeaderMap::new();
        headers.insert(header::AUTHORIZATION, authorization);
        Ok(Client::builder()
            .default_headers(headers)
            .https_only(true)
            .redirect(redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30)))
    }

    pub async fn change(
        &self,
        config: &Config,
        name: &Name,
        direct: bool,
        change: Change,
    ) -> Result<Outcome> {
        let discovery = config
            .discovery_for(name)
            .context("hostname is not within a configured discovery domain")?;
        let (owner, subdomain) = publication_location(name, discovery, direct)?;
        if let Change::Set { values, valid_for } = &change {
            validate_values(values)?;
            ensure!(
                valid_for.as_secs() > 0,
                "validity must be at least one second"
            );
            ensure!(
                config.policy.ttl() == 1 || (60..=86_400).contains(&config.policy.ttl()),
                "Cloudflare TTL must be 1 (Auto) or 60-86400 seconds"
            );
        }
        if let Change::Remove { kind } = &change {
            ensure!(
                matches!(kind, RecordType::A | RecordType::AAAA | RecordType::CNAME),
                "entry type must be A, AAAA, or CNAME"
            );
        }
        let zone = self.find_zone(&owner).await?;
        if direct && matches!(change, Change::Set { .. }) {
            let parent = name.base_name();
            if discovery.domain.zone_of(&parent) {
                let parent_zone = self.find_zone(&parent).await.context(
                    "cannot inspect parent TXT; --direct requires an accessible Cloudflare parent zone",
                )?;
                ensure!(
                    self.records(&parent_zone.id, &parent, "CNAME")
                        .await?
                        .is_empty(),
                    "parent TXT lookup follows a public CNAME; cannot use --direct"
                );
                let records = self.records(&parent_zone.id, &parent, "TXT").await?;
                let mut response = Message::response(0, OpCode::Query);
                for record in records {
                    let value = txt_bytes(&record.content).context(
                        "parent TXT has invalid content; repair it before using --direct",
                    )?;
                    response.answers.push(Record::from_rdata(
                        parent.clone(),
                        record.ttl,
                        RData::TXT(TXT::from_bytes(value.chunks(255).collect())),
                    ));
                }
                let (publication, _) = collect_publications(
                    &response,
                    &parent,
                    discovery,
                    SystemClock.now()?,
                    config.policy.ttl(),
                )
                .context("parent TXT cannot currently resolve; repair it before using --direct")?;
                let label = child_label(name)?;
                if let Some(publication) = publication {
                    ensure!(
                        !publication
                            .entries
                            .iter()
                            .any(|entry| entry.subdomain == label),
                        "a private parent entry shadows this hostname; remove it before using --direct"
                    );
                }
            }
        }
        let records = self.records(&zone.id, &owner, "TXT").await?;
        let mut private = private_publications(&records, &owner, discovery)?;
        ensure!(
            private.len() <= 1,
            "multiple encrypted TXT records at this owner; consolidate them before editing"
        );
        let existing = private.pop();
        let (record, mut publication) = match existing {
            Some((record, publication)) => (Some(record), publication),
            None => (
                None,
                Publication {
                    issued_at: 0,
                    expires_at: 1,
                    entries: Vec::new(),
                },
            ),
        };
        let ttl = match change {
            Change::Set { values, valid_for } => {
                let kind = value_type(&values[0]);
                publication.entries.retain(|entry| {
                    entry.subdomain != subdomain || value_type(&entry.value) != kind
                });
                for value in values {
                    let entry = Entry {
                        subdomain: subdomain.clone(),
                        value,
                    };
                    if !publication.entries.contains(&entry) {
                        publication.entries.push(entry);
                    }
                }
                publication.issued_at = SystemClock.now()?;
                publication.expires_at = publication
                    .issued_at
                    .checked_add(valid_for.as_secs())
                    .context("expiry overflows timestamp")?;
                config.policy.ttl()
            }
            Change::Remove { kind } => {
                let before = publication.entries.len();
                publication.entries.retain(|entry| {
                    entry.subdomain != subdomain || value_type(&entry.value) != kind
                });
                ensure!(
                    publication.entries.len() != before,
                    "private entry does not exist at the selected TXT owner"
                );
                let record = record.context("private TXT record does not exist")?;
                if publication.entries.is_empty() {
                    let path = format!("zones/{}/dns_records/{}", zone.id, record.id);
                    let deleted: ApiResponse<DeletedRecord> =
                        self.send(self.client.delete(self.endpoint(&path)?)).await?;
                    ensure!(
                        deleted
                            .result
                            .context("missing Cloudflare deletion result")?
                            .id
                            == record.id,
                        "unexpected Cloudflare deletion result"
                    );
                    return Ok(Outcome {
                        owner,
                        action: "deleted",
                    });
                }
                record.ttl
            }
        };
        let value = protocol::encrypt(&publication, &discovery.key, &owner)?;
        let content = txt_content(&value, &owner)?;
        let count = records.len() + usize::from(record.is_none());
        ensure!(
            count <= 16,
            "TXT owner would exceed the resolver's 16-record limit"
        );
        let total = records
            .iter()
            .filter(|r| record.is_none_or(|existing| existing.id != r.id))
            .map(|r| r.content.len())
            .sum::<usize>()
            + content.len();
        ensure!(
            total <= 8192,
            "TXT owner would exceed Cloudflare's combined content limit"
        );
        let body = WriteRecord {
            kind: "TXT",
            name: api_name(&owner),
            content: &content,
            ttl,
        };
        let (method, path, action) = match record {
            Some(record) => (
                Method::PATCH,
                format!("zones/{}/dns_records/{}", zone.id, record.id),
                "updated",
            ),
            None => (
                Method::POST,
                format!("zones/{}/dns_records", zone.id),
                "created",
            ),
        };
        let result: ApiResponse<DnsRecord> = self
            .send(
                self.client
                    .request(method, self.endpoint(&path)?)
                    .json(&body),
            )
            .await?;
        let result = result.result.context("missing Cloudflare write result")?;
        validate_record(&result, &owner, "TXT")?;
        ensure!(
            record.is_none_or(|old| old.id == result.id)
                && txt_bytes(&result.content).is_ok_and(|bytes| bytes == value.as_bytes()),
            "unexpected Cloudflare write result; check publication status before retrying"
        );
        Ok(Outcome { owner, action })
    }

    fn endpoint(&self, path: &str) -> Result<Url> {
        Ok(self.base.join(path)?)
    }

    async fn send<T: DeserializeOwned>(&self, request: RequestBuilder) -> Result<ApiResponse<T>> {
        let mut response = request.send().await
            .map_err(|_| anyhow::anyhow!("Cloudflare request failed; check connectivity and publication status before retrying"))?;
        ensure!(
            response.status().is_success(),
            "Cloudflare API returned HTTP {}; no automatic retry",
            response.status()
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("cannot read Cloudflare response"))?
        {
            ensure!(
                bytes.len() + chunk.len() <= MAX_RESPONSE,
                "Cloudflare response exceeds size limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        // API diagnostics can echo request data; never include the response body in errors.
        let envelope: ApiResponse<T> = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid Cloudflare API response"))?;
        ensure!(
            envelope.success,
            "Cloudflare API reported failure; check token permissions and record limits"
        );
        Ok(envelope)
    }

    async fn list<T: DeserializeOwned>(
        &self,
        path: &str,
        filters: &[(&str, String)],
    ) -> Result<Vec<T>> {
        let mut result = Vec::new();
        for page in 1..=MAX_PAGES {
            let response: ApiResponse<Vec<T>> = self
                .send(
                    self.client
                        .get(self.endpoint(path)?)
                        .query(filters)
                        .query(&[("page", page), ("per_page", 50)]),
                )
                .await?;
            let info = response
                .result_info
                .context("missing Cloudflare pagination metadata")?;
            ensure!(
                info.page == page && info.total_pages <= MAX_PAGES,
                "invalid or excessive Cloudflare pagination"
            );
            let entries = response.result.context("missing Cloudflare list result")?;
            ensure!(
                info.total_pages != 0 || entries.is_empty(),
                "inconsistent Cloudflare pagination"
            );
            result.extend(entries);
            if page >= info.total_pages {
                return Ok(result);
            }
        }
        bail!("Cloudflare pagination exceeds limit")
    }

    async fn find_zone(&self, owner: &Name) -> Result<Zone> {
        let mut candidate = owner.clone();
        while !candidate.is_root() {
            let mut zones: Vec<Zone> = self
                .list(
                    "zones",
                    &[("name", api_name(&candidate)), ("match", "all".into())],
                )
                .await?;
            ensure!(
                zones.len() <= 1,
                "multiple Cloudflare zones match the owner"
            );
            if let Some(zone) = zones.pop() {
                ensure!(
                    canonical_name(&zone.name)? == candidate,
                    "Cloudflare returned an unexpected zone"
                );
                validate_id(&zone.id)?;
                return Ok(zone);
            }
            candidate = candidate.base_name();
        }
        bail!("no accessible Cloudflare zone contains the TXT owner; check Zone Read permission")
    }

    async fn records(&self, zone: &str, owner: &Name, kind: &str) -> Result<Vec<DnsRecord>> {
        let records: Vec<DnsRecord> = self
            .list(
                &format!("zones/{zone}/dns_records"),
                &[
                    ("type", kind.into()),
                    ("name.exact", api_name(owner)),
                    ("match", "all".into()),
                ],
            )
            .await?;
        for record in &records {
            validate_record(record, owner, kind)?;
        }
        Ok(records)
    }
}

fn publication_location(
    name: &Name,
    discovery: &Discovery,
    direct: bool,
) -> Result<(Name, String)> {
    if direct {
        return Ok((name.clone(), String::new()));
    }
    let parent = name.base_name();
    ensure!(
        discovery.domain.zone_of(&parent),
        "parent TXT would cross the configured discovery domain; use --direct for this hostname"
    );
    Ok((parent, child_label(name)?))
}

fn child_label(name: &Name) -> Result<String> {
    Ok(
        std::str::from_utf8(name.iter().next().context("missing child label")?)?
            .to_ascii_lowercase(),
    )
}

fn api_name(name: &Name) -> String {
    name.to_ascii().trim_end_matches('.').to_owned()
}

fn validate_id(id: &str) -> Result<()> {
    ensure!(
        id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid Cloudflare resource identifier"
    );
    Ok(())
}

fn validate_record(record: &DnsRecord, owner: &Name, kind: &str) -> Result<()> {
    validate_id(&record.id)?;
    ensure!(
        record.kind == kind && canonical_name(&record.name)? == *owner,
        "Cloudflare returned an unexpected DNS record"
    );
    Ok(())
}

fn value_type(value: &Value) -> RecordType {
    match value {
        Value::A(_) => RecordType::A,
        Value::Aaaa(_) => RecordType::AAAA,
        Value::Cname(_) => RecordType::CNAME,
    }
}

fn validate_values(values: &[Value]) -> Result<()> {
    let first = values.first().context("provide at least one entry value")?;
    ensure!(
        values
            .iter()
            .all(|value| value_type(value) == value_type(first)),
        "set one entry type at a time"
    );
    ensure!(
        !matches!(first, Value::Cname(_)) || values.len() == 1,
        "CNAME requires exactly one target"
    );
    Ok(())
}

fn txt_bytes(content: &str) -> Result<Vec<u8>> {
    // Cloudflare accepts literal text as well as DNS-quoted character strings.
    // Hickory 0.26's zone lexer misdecodes decimal escapes, so decode these bytes here.
    let mut bytes = content.trim().bytes().peekable();
    if bytes.peek() != Some(&b'"') {
        return Ok(content.as_bytes().to_vec());
    }
    let mut value = Vec::new();
    while bytes.peek().is_some() {
        ensure!(bytes.next() == Some(b'"'), "invalid quoted Cloudflare TXT");
        loop {
            let byte = bytes.next().context("unterminated Cloudflare TXT string")?;
            match byte {
                b'"' => break,
                b'\\' => {
                    let escaped = bytes.next().context("truncated Cloudflare TXT escape")?;
                    if escaped.is_ascii_digit() {
                        let mut decimal = u16::from(escaped - b'0');
                        for _ in 0..2 {
                            let digit = bytes
                                .next()
                                .filter(u8::is_ascii_digit)
                                .context("invalid Cloudflare TXT decimal escape")?;
                            decimal = decimal * 10 + u16::from(digit - b'0');
                        }
                        value.push(
                            u8::try_from(decimal).context("Cloudflare TXT escape exceeds 255")?,
                        );
                    } else {
                        value.push(escaped);
                    }
                }
                byte => value.push(byte),
            }
        }
        while bytes.peek().is_some_and(u8::is_ascii_whitespace) {
            bytes.next();
        }
    }
    Ok(value)
}

fn private_publications<'a>(
    records: &'a [DnsRecord],
    owner: &Name,
    discovery: &Discovery,
) -> Result<Vec<(&'a DnsRecord, Publication)>> {
    let mut private = Vec::new();
    for record in records {
        let value = txt_bytes(&record.content)?;
        if protocol::is_encrypted_txt(&value) {
            let publication = protocol::decrypt_for_update(&value, &discovery.key, owner)
                .context("cannot authenticate existing encrypted TXT; no changes made")?;
            private.push((record, publication));
        }
    }
    Ok(private)
}

fn txt_content(value: &str, owner: &Name) -> Result<String> {
    let wire_size = canonical_wire(owner).len() + 10 + value.len() + value.len().div_ceil(255);
    ensure!(
        wire_size <= 4096,
        "encrypted TXT exceeds Cloudflare's 4096-byte record limit"
    );
    Ok(value
        .as_bytes()
        .chunks(255)
        .map(|chunk| {
            format!(
                "\"{}\"",
                std::str::from_utf8(chunk).expect("base64url ASCII")
            )
        })
        .collect::<Vec<_>>()
        .join(" "))
}

#[cfg(test)]
mod tests;
