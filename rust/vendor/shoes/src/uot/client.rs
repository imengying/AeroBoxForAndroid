//! Protocol-independent UoT v1/v2 client decorator.
use std::{io, pin::Pin, sync::Arc, task::{Context, Poll}};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncWriteExt, ReadBuf};
use crate::{address::{Address, NetLocation, ResolvedLocation}, async_stream::*, tcp::tcp_handler::{ClientTransport, TcpClientHandler, TcpClientSetupResult}};
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config<P> { #[serde(default="version")] pub version: u8, pub protocol: Box<P> }
fn version()->u8 {2}
impl<P> Config<P> {
    pub fn validate(&self)->io::Result<()> { if matches!(self.version,1|2) {Ok(())} else {Err(io::Error::new(io::ErrorKind::InvalidInput,"UoT version must be 1 or 2"))} }
    pub(crate) fn map<T>(self, f:impl FnOnce(P)->T)->Config<T> {Config {version:self.version,protocol:Box::new(f(*self.protocol))}}
}
#[derive(Debug)]
pub struct Handler {version:u8, inner:Box<dyn TcpClientHandler>}
impl Handler {
    pub fn new(version:u8,inner:Box<dyn TcpClientHandler>)->io::Result<Self> {Config{version,protocol:Box::new(())}.validate()?;Ok(Self{version,inner})}
    fn magic(&self)->ResolvedLocation {ResolvedLocation::new(NetLocation::new(Address::Hostname(if self.version==1 {super::UOT_V1_MAGIC_ADDRESS} else {super::UOT_V2_MAGIC_ADDRESS}.into()),0))}
    async fn frame(&self, result:TcpClientSetupResult, target:ResolvedLocation)->io::Result<Box<dyn AsyncMessageStream>> {frame(self.version,result,target).await}
}
pub(crate) async fn frame(version:u8, result:TcpClientSetupResult, target:ResolvedLocation)->io::Result<Box<dyn AsyncMessageStream>> {
        let mut stream=result.client_stream;
        if let Some(bytes)=result.early_data { if !bytes.is_empty() {return Err(io::Error::new(io::ErrorKind::InvalidData,"unexpected data before UoT request"));} }
        if version==2 {
            stream.write_u8(1).await?;stream.write_all(&crate::socks_handler::write_location_to_vec(target.location())?).await?;stream.flush().await?;
            Ok(Box::new(super::UotV2Stream::new(stream)))
        } else {Ok(Box::new(FixedTarget{inner:super::UotV1ServerStream::new_uot(stream),target:target.into_location(),eof:false}))}
}
#[async_trait]
impl TcpClientHandler for Handler {
    fn has_session_pool(&self)->bool {self.inner.has_session_pool()}
    fn supports_udp_over_tcp(&self)->bool {true}
    fn validate_alpn(&self,alpn:Option<&[u8]>)->io::Result<()> {self.inner.validate_alpn(alpn)}
    async fn prepare_target(&self,target:ResolvedLocation,resolver:&Arc<dyn crate::resolver::Resolver>)->io::Result<ResolvedLocation>{self.inner.prepare_target(target,resolver).await}
    async fn connect_client_tcp(&self,t:ClientTransport<'_>,target:ResolvedLocation)->io::Result<TcpClientSetupResult>{self.inner.connect_client_tcp(t,target).await}
    async fn setup_client_tcp_stream(&self,s:Box<dyn AsyncStream>,target:ResolvedLocation)->io::Result<TcpClientSetupResult>{self.inner.setup_client_tcp_stream(s,target).await}
    async fn connect_client_udp(&self,t:ClientTransport<'_>,target:ResolvedLocation)->io::Result<Box<dyn AsyncMessageStream>> {self.frame(self.inner.connect_client_tcp(t,self.magic()).await?,target).await}
    async fn setup_client_udp_bidirectional(&self,s:Box<dyn AsyncStream>,target:ResolvedLocation)->io::Result<Box<dyn AsyncMessageStream>> {self.frame(self.inner.setup_client_tcp_stream(s,self.magic()).await?,target).await}
}
struct FixedTarget<S> {inner:super::UotV1ServerStream<S>,target:NetLocation,eof:bool}
impl<S:AsyncStream> AsyncReadMessage for FixedTarget<S> {
    fn read_message_eof_on_empty(&self)->bool{self.eof}
    fn poll_read_message(self:Pin<&mut Self>,cx:&mut Context<'_>,out:&mut ReadBuf<'_>)->Poll<io::Result<()>> {
        let me=self.get_mut();
        let target=std::task::ready!(Pin::new(&mut me.inner).poll_read_targeted_message(cx,out))?;
        if target==NetLocation::UNSPECIFIED && out.filled().is_empty(){me.eof=true;return Poll::Ready(Ok(()));}
        if target.port()!=me.target.port() || (!matches!(me.target.address(),Address::Hostname(_)) && target.address()!=me.target.address()) {return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData,"UoT reply has unexpected source")));}
        Poll::Ready(Ok(()))
    }
}
impl<S:AsyncStream> AsyncWriteMessage for FixedTarget<S> {fn poll_write_message(self:Pin<&mut Self>,cx:&mut Context<'_>,data:&[u8])->Poll<io::Result<()>> {let me=self.get_mut();Pin::new(&mut me.inner).poll_write_sourced_message(cx,data,&me.target)}}
impl<S:AsyncStream> AsyncFlushMessage for FixedTarget<S> {fn poll_flush_message(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>> {Pin::new(&mut self.get_mut().inner).poll_flush_message(cx)}}
impl<S:AsyncStream> AsyncShutdownMessage for FixedTarget<S> {fn poll_shutdown_message(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>> {Pin::new(&mut self.get_mut().inner).poll_shutdown_message(cx)}}
impl<S:AsyncStream> AsyncPing for FixedTarget<S> {fn supports_ping(&self)->bool{self.inner.supports_ping()} fn poll_write_ping(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<bool>> {Pin::new(&mut self.get_mut().inner).poll_write_ping(cx)}}
impl<S:AsyncStream> AsyncMessageStream for FixedTarget<S>{}

#[cfg(test)] mod client_tests;
