# tendns

A Rust library and DNS forwarder for encrypted TXT discovery and hexadecimal IPv4
names. The standalone binary supports UDP/TCP and HTTP/HTTPS listeners and DoH
upstreams. Built on Hickory DNS. Licensed under MIT.

## Library

```toml
[dependencies]
tendns = { version = "0.2", default-features = false }
```

The library-only build contains the protocol, validated `Policy`, `Resolver`, and
`Exchange` transport interface. It does not include the CLI, TOML parser, DNS/HTTP
servers, Cloudflare client, or built-in network forwarder. The default `cli`
feature enables all standalone functionality, including `cargo install tendns`.

Construct a `Policy` from `Discovery` domain/key pairs, hex zones, a TTL cap, and a
publication-cache capacity. Domain canonicalization, overlap validation, and
most-specific key selection are shared with the standalone server. Configuration
formats and secret storage remain the embedding application's responsibility.
See the [API documentation](https://docs.rs/tendns) for a construction example.

Implement `Exchange` using your existing raw DNS transport, then create a resolver
with `Resolver::new(Arc<Policy>, Arc<dyn Exchange>)`. The transport must validate
response association and perform UDP truncation fallback. Internal TXT fetches
must bypass the tendns wrapper to avoid recursion. Create one resolver per
upstream policy: do not share cached publications between split-horizon upstreams.

- `Policy::claims` identifies protected/hex names before choosing local versus
  ordinary native resolution. It checks only the supplied name, without expanding
  search domains or NSS aliases. Unrelated names need not change their OS/NSS path.
- `Resolver::answer_with_deadline` answers DNS messages using one absolute Tokio
  deadline across cache waits, parent/direct lookups, and CNAME following. The
  same deadline reaches `Exchange::exchange_with_deadline`; override that method
  when the underlying transport already supports deadlines. Packet-serving
  callers should use `resolver::validate_request` first.
- `Resolver::lookup_ip` follows private CNAMEs and selects address families using
  `IpStrategy`. Its async fallback receives only names outside the configured
  namespaces and the same deadline, preserving the application's native resolver.
  Private misses, authentication failures, and expired publications never invoke
  that fallback.
  Expiry is checked again after a public CNAME target resolves. `LookupError`
  distinguishes NXDOMAIN-like `NotFound` from family-specific `NoData` results.

Deadlines enforced by the resolver and the default `Exchange` implementation
return errors identifiable with `error.is::<tendns::TimeoutError>()`, whether the
deadline has already elapsed or expires during the operation. Custom transports
may also return their own error types.

For strict namespace protection, pass absolute names and prevent the fallback
from searching or aliasing into protected namespaces. Unclaimed relative names
are passed through unchanged: a native search list could expand `nas` into
`nas.example.com` and resolve it outside tendns. Native NSS alias expansion is
likewise opaque to the library.

Do not wrap address results in a fixed-lifetime cache: it could outlive authenticated
expiry. The resolver already caches publications with TTL/expiry checks. Recreate
the policy/resolver when keys change. Admission limits and destination filtering
(such as rejecting fake-IP ranges) belong to the embedding application.

The Rust library API changed in 0.2: `Resolver::new` takes `Arc<Policy>` instead of
the server's `Arc<Config>`. Standalone TOML, CLI commands, and the `td1` wire format
are unchanged.

## Build and run

Requires Rust 1.99.1 or newer and a C toolchain for AWS-LC.

```sh
CARGO_BUILD_JOBS=1 cargo build --release
target/release/tendns keygen
target/release/tendns --config tendns.toml serve
```

Use `tendns.example.toml` as the configuration reference. Set a fresh generated
key for each discovery domain. The example binds UDP and TCP on `0.0.0.0:5300`.
Port 53 may require elevated binding privileges. Keeping the listener internal
is the operator's responsibility. UDP/TCP DNS has no authentication; HTTP/HTTPS
listeners support bearer tokens.

Use port 53 for clients whose resolver configuration cannot specify a port.
For a quick check of the example's listener:

```sh
dig @127.0.0.1 -p 5300 c0000201.hex.example.net A
dig @127.0.0.1 -p 5300 example.net A +tcp
```

Protect configuration files containing keys with appropriate filesystem
permissions, such as mode `0600`. `tendns.toml` is ignored by Git. Keys are
32 random bytes represented as unpadded base64url, not passwords.

## Listeners and DoH

Listeners use typed TOML entries. This replaces the earlier `listen = [...]`
format. With no `listeners` specified, the default is UDP/TCP on `0.0.0.0:5300`.
An explicit list can contain only HTTP/HTTPS listeners, without ordinary DNS.

```toml
[[listeners]]
type = "dns"
address = "0.0.0.0:5300"

[[listeners]]
type = "http"
address = "0.0.0.0:8053"
path = "/dns-query"
auth_tokens = ["replace-with-a-random-token"]

[[listeners]]
type = "https"
address = "0.0.0.0:8443"
path = "/dns-query"
http2 = true
cert = "server.crt"
key = "server.key"
auth_tokens = ["another-random-token"]
auth_token_file = "tokens.txt"
```

HTTPS requires a PEM certificate chain and an unencrypted PEM private key
(PKCS#8, PKCS#1, or SEC1). Certificates, keys, and token files load **once at
startup**; restart to rotate them. Relative file paths resolve beside the TOML file.
Invalid or unreadable configured files fail startup before listeners are advertised.

Authentication is independent per HTTP/HTTPS listener. `auth_tokens` and
`auth_token_file` are optional and additive: any token from either source is
accepted through `Authorization: Bearer TOKEN`. Files contain one token per line;
LF and CRLF are accepted and empty lines ignored. Tokens are case-sensitive,
contain no whitespace, and use the bearer-token alphabet (letters, digits,
`-._~+/`, and optional trailing `=`). Limits: 1024 tokens per listener, 1024 bytes
per token, 1 MiB per file. `tendns keygen` can generate suitable random tokens;
generate separate values rather than reusing discovery encryption keys.

An empty combined token list disables authentication and prints a warning for
that listener. Missing or invalid credentials produce HTTP 401 with a Bearer
challenge. DNS listeners reject auth fields. Protect token files like private
keys. Plain HTTP exposes queries, answers, and bearer tokens: use HTTPS outside
trusted networks. Authentication does not make an HTTP connection encrypted.

Each HTTP/HTTPS listener has an optional `path`, defaulting to `/dns-query`.
For example, `path = "/private/resolve"` moves both binary and JSON queries to
that endpoint. It must start with `/` and contain no query string, fragment, or
whitespace. Matching is exact, case-sensitive, and does not decode percent escapes
or redirect trailing slashes. DNS listeners reject `path`.

Plain HTTP serves HTTP/1.1 only. HTTPS serves HTTP/1.1 and, by default, HTTP/2
negotiated through ALPN. Set `http2 = false` on an HTTPS listener to disable
HTTP/2; HTTP and DNS listeners reject this setting. All listeners share the
existing resolver, cache, and global query concurrency/deadline limits:

- **Binary (RFC 8484):** GET `?dns=BASE64URL` with an unpadded DNS wire message,
  or POST a DNS wire message with `Content-Type: application/dns-message`.
- **JSON (common, non-standard DNS JSON format):** GET
  `?name=example.com&type=A`, with symbolic or numeric `type` (default `A`).
  Optional `do` and `cd` accept `true`/`false` or `1`/`0`.
- `Accept: application/dns-message` or `application/dns-json` selects the response
  format; quality weights and wildcards are supported. Without `Accept`, `name`
  queries default to JSON and wire queries to binary. JSON POST is not supported.
- JSON includes `Status`, DNS flags, `Question`, `Answer`, `Authority`, and
  `Additional`; record data uses DNS presentation syntax, including RFC 3597
  generic `\# length hex` for SVCB, HTTPS, NULL, and unknown types. DNS failures
  are HTTP 200 with their DNS status. Malformed HTTP queries use HTTP error statuses.

```sh
curl --cacert server.crt \
  -H "Authorization: Bearer $DNS_TOKEN" \
  -H 'Accept: application/dns-json' \
  'https://localhost:8443/dns-query?name=c0000201.hex.example.net&type=A'
```

Responses use `Cache-Control: no-store` to avoid shared HTTP caches retaining
private answers; DNS TTLs still apply. Request URIs are limited to 8 KiB, binary
POST bodies to 65535 bytes, and body reads to `request_timeout` (1s-24h). HTTP connections
and in-flight HTTP requests are each bounded by `max_inflight` per listener.
Connections are rotated after five minutes, with a short graceful-close window.
No CORS access or client-subnet parameter support is enabled.

## Releases

The `release-*` branch builds and tests the same source as the `v*` release tag.
Dependencies use broad manifest constraints; `Cargo.lock` fixes the exact
release graph, and CI builds with `--locked`. Binary releases are distributed
through GitHub; the library and installable CLI are packaged for crates.io.

The release workflow packages and smoke-tests eight binaries: Linux x86_64
(GNU and musl), Linux aarch64 (GNU and musl), Linux armv7 (GNU and musl), and
macOS x86_64 and aarch64. Each archive contains `tendns`, this README, `LICENSE`, and
`tendns.example.toml`; the release includes `SHA256SUMS` and build-provenance
attestations. A tag creates a draft release after all builds pass. The draft is
published only after reviewing the artifacts.

## Generate TXT values

The `txt` command is offline: it loads the same config as the server, selects
the most-specific discovery domain containing `--name`, and prints one encrypted
TXT value. No running server, DNS lookup, or provider API is needed.
The examples below assume `tendns` is on PATH; otherwise use `target/release/tendns`.

```sh
tendns --config tendns.toml txt --name home.example.com \
  --a 192.0.2.1 --aaaa 2001:db8::1 --valid-for 24h
```

Publish the output as TXT at exactly `home.example.com`. A client using tendns
can then query `home.example.com` for A or AAAA. `--a` and `--aaaa` are repeatable.
The configured `valid_for` supplies the default validity when the flag is absent.

For a hidden child name:

```sh
tendns --config tendns.toml txt --name example.com \
  --subdomain nas --a 192.0.2.10
```

Publish at `example.com`, not `nas.example.com`. The server answers A queries
for `nas.example.com` using that parent record without querying the child name
upstream when the parent entry is present and valid.

For multiple names in one publication:

```sh
tendns --config tendns.toml txt --name example.com \
  --entry '@:A:192.0.2.1' \
  --entry 'nas:AAAA:2001:db8::1' \
  --entry 'www:CNAME:target.example.net.'
```

`--entry` is repeatable and uses `LABEL:TYPE:VALUE`; `@` selects the public TXT
owner. Labels contain at most 63 ASCII letters/digits/hyphens, not dots.
Internationalized names must use Punycode. `--cname target.example.net` is a
shortcut for an alias at the owner or the current `--subdomain`. An alias cannot
coexist with another entry at the same resulting hostname.

The value begins `td1.` and uses AES-256-GCM-SIV with a fresh random IV and an
authentication tag. It is bound to the public TXT owner: moving it to a different
name will not work. The CLI prints only the value on stdout; errors use stderr.
Values longer than 255 bytes must be split into adjacent character-strings
within **one** TXT record, with no inserted spaces in the data. Do not publish
the fragments as separate records. The server concatenates strings per RR.

## Publish with Cloudflare

`cloudflare-set` and `cloudflare-remove` use the same TOML discovery keys and a
native HTTPS client. Set `CLOUDFLARE_API_TOKEN` to a token with **Zone Read** and
**DNS Write** permissions, scoped to the relevant zones. The commands discover
the most-specific accessible Cloudflare zone containing the TXT owner. No zone
ID, provider credentials in TOML, or external `curl` executable is required.

```sh
tendns --config tendns.toml cloudflare-set --name nas.example.com --a 192.0.2.10
tendns --config tendns.toml cloudflare-set --name nas.example.com --aaaa 2001:db8::10
tendns --config tendns.toml cloudflare-set --name www.example.com --cname target.example.net
tendns --config tendns.toml cloudflare-remove --name nas.example.com --type A
```

Here `--name` is the **hostname clients resolve**, unlike `txt --name`, which
specifies the public TXT owner. By default these commands edit TXT at the
immediate parent (`example.com`) and keep the child label (`nas` or `www`)
encrypted. `--direct` edits TXT at the exact hostname with an empty hidden label.
At a configured discovery domain's apex, `--direct` is required: publishing in
its parent would cross the key boundary. A direct set is refused when an existing
parent entry shadows it or the parent TXT lookup would fail validation.

Set reuses the owner's existing `td1` TXT: decrypt, edit the array, re-encrypt,
and PATCH the same Cloudflare record. It creates a TXT record only when none
contains an encrypted publication. Other TXT records and Cloudflare comments/tags
are left untouched; hidden labels are never written into provider metadata.

Entries are keyed by hostname and type. A missing type is appended; setting an
existing type replaces all its values while preserving other types and hostnames.
`--a` and `--aaaa` are repeatable for multiple addresses, but one invocation sets
only one type. CNAME/address conflicts are errors, not implicit deletions.
Remove deletes all values of the selected hostname/type, preserving the original
publication timestamps and DNS TTL; it deletes the TXT record only if empty.
An absent entry is reported as an error. Placement is not migrated automatically:
removing a hidden entry can expose a previously shadowed direct entry.

**Set refreshes validity for every entry in that encrypted TXT**, including
unchanged entries. Use `--valid-for` to override the configured duration. Expired
but authenticated publications can be refreshed; unreadable ciphertext and
multiple encrypted records at one owner are refused without changes. Consolidate
multiple publications manually before managing that owner with these commands.
Set applies the configured `ttl`, which must be 60–86400 seconds or `1` for
Cloudflare Auto (normally 300 seconds). Values are split into quoted TXT strings;
provider size limits and the resolver's record limits are checked before writing.

Run only one writer per TXT owner. Cloudflare does not provide a documented
conditional update for this read-modify-write operation; concurrent commands can
lose updates. Redirects and automatic retries are disabled. After a timeout or
other uncertain write result, check the provider state before retrying. These
commands do not schedule renewals or detect address changes.

## Lookup behavior

For a discovery query such as `a.example.com`, tendns first checks TXT at its
immediate parent for a hidden `a` entry, then checks TXT at the queried name for
an entry without a subdomain. Parent entries win, including when they lack the
requested address family. Only one hidden label is supported. Parent lookup
does not cross the selected discovery domain's boundary.

A timeout, invalid ciphertext, unsupported encrypted version, or expired
publication is an error, not permission to try the child. Confirmed absence
does permit a direct TXT lookup, which exposes the queried name upstream. For
both locations, absence produces NXDOMAIN; an existing name without the
requested type produces NODATA. There is no fallback to plaintext A/AAAA inside
a discovery domain. CNAME targets are followed with loop/depth bounds.
An owner containing only hidden children, and the hex-zone apex, return NODATA
rather than NXDOMAIN so downstream caches do not suppress their children.

Multiple encrypted TXT values contribute independent entries. Duplicate entries
are deduplicated; CNAME/address conflicts at the same hostname are errors.
Publish independent `td1.` values as separate TXT records, not strings within one RR.
Timestamps validate freshness, not replacement order. Replace or remove old TXT
values explicitly when updating. An invalid or expired encrypted value fails the
lookup, including when other values are valid: it might contain the hidden label
being queried. Publication is operator-triggered; regenerate and republish before expiry,
including when addresses are unchanged.

For a configured hex zone, `c0000201.hex.example.net` resolves to `192.0.2.1`.
Exactly one eight-character ASCII hexadecimal label is accepted, including
uppercase. All IPv4 addresses are permitted, including private and loopback
addresses. AAAA and other unsupported types return NODATA; invalid names within
the zone return NXDOMAIN. Hex and discovery zones cannot overlap.

Names outside configured zones are forwarded. Plain upstreams use UDP with TCP
fallback. DoH uses certificate-verified HTTPS/HTTP2 with explicit bootstrap IPs,
so starting the proxy does not depend on the system DNS resolver. Upstreams are
tried in configured order. Plain fallback exists only when explicitly configured.
Transfers, updates, TSIG, and multi-question requests are not supported.

Discovery caching is bounded and never extends the source TTL or authenticated
expiry. Concurrent requests for the same cached owner share a fetch. Generic
forwarding uses upstream caches rather than adding another response cache.
Synthetic answers do not assert DNSSEC validation. Operators using downstream
DNSSEC validation must configure the local namespaces accordingly.

## Security limits

Internal clients receive plaintext addresses through ordinary DNS. Anyone with
the configured key can decrypt and create publications for its domain. Public
TXT owners, query patterns, ciphertext sizes, and update timing remain visible.
Hex labels directly disclose the encoded address. Service authentication and
network access control remain separate from discovery.

There is no persistent replay state. Authentic older values may be accepted
until expiry; a reasonably correct clock is required. SIV is a safety net against
accidental nonce reuse, not replay protection. Removing a TXT record does not
erase addresses clients already learned. Configuration keys are separate from
provider API credentials. Only the Cloudflare publishing commands need a provider
token, read from `CLOUDFLARE_API_TOKEN`; the DNS server does not.

## Check

```sh
CARGO_BUILD_JOBS=1 cargo test --all-targets
CARGO_BUILD_JOBS=1 cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

Tests use local DNS and HTTPS fixtures; they do not require a public resolver.
The server exits gracefully on SIGINT or SIGTERM.
