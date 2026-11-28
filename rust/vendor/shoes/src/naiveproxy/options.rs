use std::{collections::BTreeMap,io};
use serde::{Deserialize,Serialize};

#[derive(Clone,Deserialize,Serialize)]
#[serde(untagged)]
pub enum HeaderValues {One(String),Many(Vec<String>)}
impl HeaderValues {
    pub fn values(&self)->&[String] {match self {Self::One(value)=>std::slice::from_ref(value),Self::Many(values)=>values}}
}
#[derive(Clone,Default,Deserialize,Serialize)]
#[serde(transparent)]
pub struct Headers(pub BTreeMap<String,HeaderValues>);
impl std::fmt::Debug for Headers {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.debug_list().entries(self.0.keys()).finish()}}
impl Headers {
    pub fn is_empty(&self)->bool {self.0.is_empty()}
    pub fn validate(&self)->io::Result<()> {self.parsed().map(|_|())}
    pub fn parsed(&self)->io::Result<http::HeaderMap> {
        let mut headers=http::HeaderMap::new();let mut size=0usize;
        for (key,values) in &self.0 {
            let name=http::header::HeaderName::from_bytes(key.as_bytes()).map_err(|_|invalid("invalid HTTP header name"))?;
            if matches!(name.as_str(),"content-length"|"transfer-encoding"|"connection"|"upgrade"|"proxy-connection") || key.starts_with('-') {
                return Err(invalid("framing and internal HTTP headers cannot be overridden"));
            }
            for value in values.values() {
                size=size.saturating_add(key.len()+value.len()+4);if size>16*1024 {return Err(invalid("extra headers exceed 16 KiB"));}
                let mut value=http::HeaderValue::from_str(value).map_err(|_|invalid("invalid HTTP header value"))?;
                if matches!(name.as_str(),"authorization"|"proxy-authorization"|"cookie") {value.set_sensitive(true);}
                headers.append(name.clone(),value);
            }
        }
        Ok(headers)
    }
}
fn concurrency()->usize{1}
fn window()->u32{256*1024}
fn invalid(message:&str)->io::Error {io::Error::new(io::ErrorKind::InvalidInput,message)}

#[derive(Debug,Clone,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    #[serde(default)] pub quic:bool,
    #[serde(default)] pub quic_congestion_control: crate::config::quic_client::CongestionControl,
    #[serde(default,skip_serializing_if="Headers::is_empty")] pub extra_headers:Headers,
    #[serde(default="concurrency")] pub insecure_concurrency:usize,
    #[serde(default="window")] pub stream_receive_window:u32,
    #[serde(default="window")] pub session_receive_window:u32,
    #[serde(default,skip_serializing_if="Option::is_none")] pub udp_over_tcp:Option<u8>,
}
impl Default for Options {
    fn default()->Self{Self{quic:false,quic_congestion_control:Default::default(),extra_headers:Headers::default(),insecure_concurrency:1,stream_receive_window:window(),session_receive_window:window(),udp_over_tcp:None}}
}
impl Options {
    pub fn validate(&self)->io::Result<()> {
        self.extra_headers.validate()?;
        if self.insecure_concurrency==0{return Err(invalid("Naive concurrency must be positive"));}
        // H2 flow-control credit is signed 31-bit. The fixed Android Cronet
        // options reader also accepts only signed 31-bit QUIC window values.
        if self.stream_receive_window>i32::MAX as u32 || self.session_receive_window>i32::MAX as u32 {
            return Err(invalid("Naive receive windows must not exceed 2147483647 bytes"));
        }
        if self.udp_over_tcp.is_some_and(|v|!matches!(v,1|2)){return Err(invalid("UoT version must be 1 or 2"));}
        Ok(())
    }
    // Grow only when real sessions are opened; a large configured concurrency
    // must never cause a proportional allocation during configuration parsing.
    pub(super) fn session_cache_capacity(&self)->usize {self.insecure_concurrency.max(16)}
}
