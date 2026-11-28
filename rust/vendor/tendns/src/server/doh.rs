use std::{convert::Infallible, fs::File, io::Read, path::Path, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use aerobox_primitives::{constant_time, digest};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use hickory_proto::{
    op::{Edns, Message, Query},
    rr::{Name, RData, Record, RecordType},
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable},
};
use http::{HeaderMap, Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::{Semaphore, watch},
    task::JoinSet,
};
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

use super::Handler;
use crate::config::Listener;

const MAX_DNS: usize = 65_535;
const MAX_URI: usize = 8192;
const BINARY: &str = "application/dns-message";
const JSON: &str = "application/dns-json";
type HttpResponse = Response<Full<Bytes>>;

pub(super) struct BoundListener {
    socket: TcpListener,
    tls: Option<TlsAcceptor>,
    options: Arc<HttpOptions>,
}

struct HttpOptions {
    path: String,
    http2: bool,
    auth: Auth,
}

impl BoundListener {
    pub(super) async fn bind(config: &Listener) -> Result<Self> {
        let (path, http2, auth_tokens, auth_token_file, tls) = match config {
            Listener::Https {
                path,
                http2,
                cert,
                key,
                auth_tokens,
                auth_token_file,
                ..
            } => {
                let certificates = CertificateDer::pem_file_iter(cert)
                    .context("cannot read HTTPS certificate PEM")?
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .context("invalid HTTPS certificate PEM")?;
                let key = PrivateKeyDer::from_pem_file(key)
                    .context("cannot read HTTPS private key PEM")?;
                let mut tls = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certificates, key)
                    .context("invalid HTTPS certificate/key pair")?;
                tls.alpn_protocols = vec![b"http/1.1".to_vec()];
                if *http2 {
                    tls.alpn_protocols.insert(0, b"h2".to_vec());
                }
                (
                    path,
                    *http2,
                    auth_tokens,
                    auth_token_file,
                    Some(TlsAcceptor::from(Arc::new(tls))),
                )
            }
            Listener::Http {
                path,
                auth_tokens,
                auth_token_file,
                ..
            } => (path, false, auth_tokens, auth_token_file, None),
            Listener::Dns { .. } => unreachable!("HTTP listeners only"),
        };
        let options = Arc::new(HttpOptions {
            path: path.clone(),
            http2,
            auth: Auth::load(auth_tokens, auth_token_file.as_deref())?,
        });
        let socket = TcpListener::bind(config.address())
            .await
            .context("cannot bind DoH listener")?;
        Ok(Self {
            socket,
            tls,
            options,
        })
    }

    pub(super) fn unauthenticated(&self) -> bool {
        self.options.auth.0.is_empty()
    }

    pub(super) async fn run(
        self,
        handler: Handler,
        max_inflight: usize,
        timeout: Duration,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let connections = Arc::new(Semaphore::new(max_inflight));
        let requests = Arc::new(Semaphore::new(max_inflight));
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    if result.is_err() {
                        eprintln!("warning: DoH connection task failed");
                    }
                }
                accepted = self.socket.accept() => {
                    let (socket, _) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            eprintln!("warning: DoH accept failed: {error}");
                            tokio::select! {
                                _ = shutdown.changed() => break,
                                _ = tokio::time::sleep(Duration::from_millis(100)) => {},
                            }
                            continue;
                        }
                    };
                    let Ok(permit) = connections.clone().try_acquire_owned() else { continue; };
                    let tls = self.tls.clone();
                    let handler = handler.clone();
                    let options = self.options.clone();
                    let requests = requests.clone();
                    let mut shutdown = shutdown.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Some(tls) = tls {
                            let handshake = tokio::select! {
                                _ = shutdown.changed() => return,
                                result = tokio::time::timeout(timeout, tls.accept(socket)) => result,
                            };
                            if let Ok(Ok(stream)) = handshake {
                                connection(stream, handler, options, requests, timeout, shutdown).await;
                            }
                        } else {
                            connection(socket, handler, options, requests, timeout, shutdown).await;
                        }
                    });
                }
            }
        }
        while let Some(result) = tasks.join_next().await {
            if result.is_err() {
                eprintln!("warning: DoH connection task failed");
            }
        }
        Ok(())
    }
}

async fn connection<S>(
    stream: S,
    handler: Handler,
    options: Arc<HttpOptions>,
    permits: Arc<Semaphore>,
    timeout: Duration,
    mut shutdown: watch::Receiver<bool>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let http2 = options.http2;
    let service = service_fn(move |request| {
        let handler = handler.clone();
        let options = options.clone();
        let permits = permits.clone();
        async move {
            let response = match permits.try_acquire_owned() {
                Ok(_permit) => respond(request, &handler, &options, timeout).await,
                Err(_) => error(StatusCode::SERVICE_UNAVAILABLE),
            };
            Ok::<_, Infallible>(response)
        }
    });
    let mut builder = auto::Builder::new(TokioExecutor::new());
    if !http2 {
        builder = builder.http1_only();
    }
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(timeout)
        .max_buf_size(16 * 1024);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(128)
        .max_header_list_size(16 * 1024)
        .keep_alive_interval(timeout)
        .keep_alive_timeout(timeout);
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    // Also bound connections stalled before protocol detection or HTTP/2 setup.
    tokio::select! {
        _ = &mut connection => {},
        _ = tokio::time::sleep(Duration::from_secs(300)) => {
            connection.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(Duration::from_secs(4), connection).await;
        }
        _ = shutdown.changed() => {
            connection.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(Duration::from_secs(4), connection).await;
        }
    }
}

struct Auth(Vec<digest::Digest>);

impl Auth {
    fn load(inline: &[Zeroizing<String>], path: Option<&Path>) -> Result<Self> {
        let mut auth = Self(Vec::new());
        for token in inline {
            auth.add(token)?;
        }
        if let Some(path) = path {
            let mut content = Zeroizing::new(String::new());
            File::open(path)
                .context("cannot open DoH auth token file")?
                .take(1024 * 1024 + 1)
                .read_to_string(&mut content)
                .context("cannot read DoH auth token file")?;
            ensure!(
                content.len() <= 1024 * 1024,
                "DoH auth token file exceeds 1 MiB"
            );
            for token in content.lines().filter(|line| !line.is_empty()) {
                auth.add(token)?;
            }
        }
        Ok(auth)
    }

    fn add(&mut self, token: &str) -> Result<()> {
        ensure!(
            valid_token(token),
            "invalid DoH bearer token; expected 1-1024 token characters without whitespace"
        );
        ensure!(
            self.0.len() < 1024,
            "too many DoH auth tokens (maximum 1024)"
        );
        self.0
            .push(digest::digest(&digest::SHA256, token.as_bytes()));
        Ok(())
    }

    fn accepts(&self, headers: &HeaderMap) -> bool {
        if self.0.is_empty() {
            return true;
        }
        let mut values = headers.get_all(header::AUTHORIZATION).iter();
        let Some(value) = values.next() else {
            return false;
        };
        if values.next().is_some() {
            return false;
        }
        let Ok(value) = value.to_str() else {
            return false;
        };
        let Some((scheme, token)) = value.split_once(' ') else {
            return false;
        };
        let token = token.trim_start_matches(' ');
        if !scheme.eq_ignore_ascii_case("Bearer") || !valid_token(token) {
            return false;
        }
        let supplied = digest::digest(&digest::SHA256, token.as_bytes());
        self.0.iter().fold(false, |matched, expected| {
            matched
                | constant_time::verify_slices_are_equal(supplied.as_ref(), expected.as_ref())
                    .is_ok()
        })
    }
}

fn valid_token(token: &str) -> bool {
    let unpadded = token.trim_end_matches('=');
    !unpadded.is_empty()
        && token.len() <= 1024
        && unpadded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/".contains(&byte))
}

async fn respond(
    request: Request<Incoming>,
    handler: &Handler,
    options: &HttpOptions,
    timeout: Duration,
) -> HttpResponse {
    if !options.auth.accepts(request.headers()) {
        let mut response = error(StatusCode::UNAUTHORIZED);
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Bearer realm=\"dns\""),
        );
        return response;
    }
    match query(request, &options.path, timeout).await {
        Ok((message, format)) => {
            let answer = handler.resolve(message).await;
            let bytes = match format {
                Format::Binary => answer.to_vec().ok(),
                Format::Json => json_answer(&answer)
                    .ok()
                    .and_then(|answer| serde_json::to_vec(&answer).ok()),
            };
            match bytes {
                Some(bytes) => response(StatusCode::OK, format.media_type(), bytes),
                None => error(StatusCode::INTERNAL_SERVER_ERROR),
            }
        }
        Err(status) => error(status),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Binary,
    Json,
}

impl Format {
    fn media_type(self) -> &'static str {
        match self {
            Self::Binary => BINARY,
            Self::Json => JSON,
        }
    }
}

async fn query(
    request: Request<Incoming>,
    path: &str,
    timeout: Duration,
) -> Result<(Message, Format), StatusCode> {
    if request.uri().path() != path {
        return Err(StatusCode::NOT_FOUND);
    }
    if request.uri().to_string().len() > MAX_URI {
        return Err(StatusCode::URI_TOO_LONG);
    }
    if request.method() != Method::GET && request.method() != Method::POST {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    let mut params = std::collections::HashMap::new();
    for (key, value) in url::form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes())
    {
        if params
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let default = if request.method() == Method::GET && params.contains_key("name") {
        Format::Json
    } else {
        Format::Binary
    };
    let format = negotiate(request.headers(), default)?;
    let message = if request.method() == Method::POST {
        if !params.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        if request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_none_or(|value| {
                !value
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case(BINARY)
            })
        {
            return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        if request.headers().contains_key(header::CONTENT_ENCODING) {
            return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        let mut body = request.into_body();
        let bytes = tokio::time::timeout(timeout, async {
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
                if let Some(data) = frame.data_ref() {
                    if bytes.len() + data.len() > MAX_DNS {
                        return Err(StatusCode::PAYLOAD_TOO_LARGE);
                    }
                    bytes.extend_from_slice(data);
                }
            }
            Ok(bytes)
        })
        .await
        .map_err(|_| StatusCode::REQUEST_TIMEOUT)??;
        binary_query(&bytes)?
    } else if let Some(encoded) = params.get("dns") {
        if params.len() != 1 {
            return Err(StatusCode::BAD_REQUEST);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        binary_query(&bytes)?
    } else {
        json_query(&params)?
    };
    if message.metadata.message_type != hickory_proto::op::MessageType::Query {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok((message, format))
}

fn binary_query(bytes: &[u8]) -> Result<Message, StatusCode> {
    let mut decoder = BinDecoder::new(bytes);
    let message = Message::read(&mut decoder).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !decoder.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(message)
}

fn json_query(params: &std::collections::HashMap<String, String>) -> Result<Message, StatusCode> {
    if params.keys().any(|key| {
        !matches!(
            key.as_str(),
            "name" | "type" | "do" | "cd" | "random_padding"
        )
    }) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let name = params
        .get("name")
        .filter(|name| !name.is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let mut name = Name::from_utf8(name)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_lowercase();
    name.set_fqdn(true);
    let kind = params.get("type").map(String::as_str).unwrap_or("A");
    let kind = match kind.parse::<u16>() {
        Ok(number) => RecordType::from(number),
        Err(_) => kind
            .to_ascii_uppercase()
            .parse()
            .map_err(|_| StatusCode::BAD_REQUEST)?,
    };
    let boolean = |key| match params.get(key).map(String::as_str) {
        None | Some("false" | "0") => Ok(false),
        Some("true" | "1") => Ok(true),
        _ => Err(StatusCode::BAD_REQUEST),
    };
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.metadata.checking_disabled = boolean("cd")?;
    query.queries.push(Query::query(name, kind));
    let mut edns = Edns::new();
    edns.set_dnssec_ok(boolean("do")?).set_max_payload(1232);
    query.edns = Some(edns);
    Ok(query)
}

fn negotiate(headers: &HeaderMap, default: Format) -> Result<Format, StatusCode> {
    if !headers.contains_key(header::ACCEPT) {
        return Ok(default);
    }
    let mut scores = [None::<(u8, f32)>; 2];
    for value in headers.get_all(header::ACCEPT) {
        for range in value
            .to_str()
            .map_err(|_| StatusCode::NOT_ACCEPTABLE)?
            .split(',')
        {
            let mut parts = range.trim().split(';');
            let media = parts.next().unwrap_or("").trim().to_ascii_lowercase();
            let mut quality = 1.0;
            for parameter in parts {
                if let Some((name, value)) = parameter.trim().split_once('=')
                    && name.eq_ignore_ascii_case("q")
                {
                    quality = value
                        .trim()
                        .parse::<f32>()
                        .map_err(|_| StatusCode::NOT_ACCEPTABLE)?;
                    if !(0.0..=1.0).contains(&quality) {
                        return Err(StatusCode::NOT_ACCEPTABLE);
                    }
                }
            }
            for (index, format) in [Format::Binary, Format::Json].iter().enumerate() {
                let specificity = if media == format.media_type() {
                    2
                } else if media == "application/*" {
                    1
                } else if media == "*/*" {
                    0
                } else {
                    continue;
                };
                if scores[index]
                    .is_none_or(|(old, q)| specificity > old || (specificity == old && quality > q))
                {
                    scores[index] = Some((specificity, quality));
                }
            }
        }
    }
    let binary = scores[0].map_or(0.0, |(_, q)| q);
    let json = scores[1].map_or(0.0, |(_, q)| q);
    if binary == 0.0 && json == 0.0 {
        return Err(StatusCode::NOT_ACCEPTABLE);
    }
    if binary > json {
        Ok(Format::Binary)
    } else if json > binary {
        Ok(Format::Json)
    } else {
        Ok(default)
    }
}

fn json_answer(message: &Message) -> Result<Value> {
    let records = |records: &[Record]| {
        records
            .iter()
            .map(|record| {
                Ok(json!({
                    "name": record.name.to_ascii(),
                    "type": u16::from(record.data.record_type()),
                    "TTL": record.ttl,
                    "data": json_record_data(&record.data)?,
                }))
            })
            .collect::<Result<Vec<_>>>()
    };
    let flags = &message.metadata;
    Ok(json!({
        "Status": u16::from(flags.response_code), "TC": flags.truncation,
        "RD": flags.recursion_desired, "RA": flags.recursion_available,
        "AD": flags.authentic_data, "CD": flags.checking_disabled,
        "Question": message.queries.iter().map(|query| json!({"name": query.name().to_ascii(), "type": u16::from(query.query_type())})).collect::<Vec<_>>(),
        "Answer": records(&message.answers)?, "Authority": records(&message.authorities)?,
        "Additional": records(&message.additionals)?,
    }))
}

fn json_record_data(data: &RData) -> Result<String> {
    // Hickory's character-string Display implementations can lose bytes and boundaries.
    Ok(match data {
        RData::TXT(txt) => txt
            .txt_data
            .iter()
            .map(|chunk| quoted_bytes(chunk))
            .collect::<Vec<_>>()
            .join(" "),
        RData::HINFO(hinfo) => {
            format!("{} {}", quoted_bytes(&hinfo.cpu), quoted_bytes(&hinfo.os))
        }
        RData::NAPTR(naptr) => format!(
            "{} {} {} {} {} {}",
            naptr.order,
            naptr.preference,
            quoted_bytes(&naptr.flags),
            quoted_bytes(&naptr.services),
            quoted_bytes(&naptr.regexp),
            naptr.replacement.to_ascii(),
        ),
        RData::CAA(caa) => format!("{} {} {}", caa.flags(), caa.tag, quoted_bytes(&caa.value)),
        // Use RFC 3597 where Hickory lacks a lossless presentation formatter.
        RData::SVCB(_)
        | RData::HTTPS(_)
        | RData::NULL(_)
        | RData::Unknown { .. }
        | RData::OPT(_) => {
            use std::fmt::Write;

            let bytes = data.to_bytes()?;
            let mut text = format!("\\# {}", bytes.len());
            if !bytes.is_empty() {
                text.push(' ');
                for byte in bytes {
                    write!(text, "{byte:02x}")?;
                }
            }
            text
        }
        _ => data.to_string(),
    })
}

fn quoted_bytes(bytes: &[u8]) -> String {
    let mut quoted = String::from("\"");
    for &byte in bytes {
        match byte {
            b'"' | b'\\' => {
                quoted.push('\\');
                quoted.push(char::from(byte));
            }
            32..=126 => quoted.push(char::from(byte)),
            _ => quoted.push_str(&format!("\\{byte:03}")),
        }
    }
    quoted.push('"');
    quoted
}

fn response(
    status: StatusCode,
    content_type: &'static str,
    bytes: impl Into<Bytes>,
) -> HttpResponse {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::VARY, "Accept")
        .header("x-content-type-options", "nosniff")
        .body(Full::new(bytes.into()))
        .expect("static HTTP response headers")
}

fn error(status: StatusCode) -> HttpResponse {
    let mut result = response(
        status,
        "text/plain; charset=utf-8",
        status.canonical_reason().unwrap_or("Error"),
    );
    if status == StatusCode::METHOD_NOT_ALLOWED {
        result
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("GET, POST"));
    }
    result
}

#[cfg(test)]
mod tests;
