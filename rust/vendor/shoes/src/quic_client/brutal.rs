//! Hysteria's negotiated fixed-rate controller, with a five-second loss window.
//! Packet pacing is supplied explicitly to Quinn instead of approximated from CWND.
use std::{any::Any,sync::Arc,time::{Duration,Instant}};
use quinn::congestion::{Controller,ControllerFactory};
use quinn_proto::RttEstimator;

#[derive(Debug)]
pub(super) struct Config(pub u64);
impl ControllerFactory for Config {
    fn build(self:Arc<Self>, now:Instant, mtu:u16)->Box<dyn Controller> {
        Box::new(Brutal{bps:self.0.max(1),epoch:now,mtu,rtt:Duration::ZERO,slots:Default::default(),ack_rate:1.0})
    }
}
#[derive(Clone,Default)]
struct Slot {second:u64,acks:u64,losses:u64}
#[derive(Clone)]
struct Brutal {bps:u64,epoch:Instant,mtu:u16,rtt:Duration,slots:[Slot;5],ack_rate:f64}
impl Brutal {
    fn record(&mut self,now:Instant,acks:u64,losses:u64) {
        let second=now.saturating_duration_since(self.epoch).as_secs();
        let slot=&mut self.slots[(second%5) as usize];
        if slot.second!=second {*slot=Slot{second,..Default::default()};}
        slot.acks=slot.acks.saturating_add(acks);slot.losses=slot.losses.saturating_add(losses);
        let (acks,losses)=self.slots.iter().filter(|s|s.second>=second.saturating_sub(5)).fold((0u64,0u64),|(a,l),s|(a.saturating_add(s.acks),l.saturating_add(s.losses)));
        let total=acks.saturating_add(losses);
        self.ack_rate=if total<50 {1.0} else {(acks as f64/total as f64).max(0.8)};
    }
}
impl Controller for Brutal {
    fn pacing_rate_bytes(&self)->Option<u64>{Some((self.bps as f64/self.ack_rate) as u64)}
    fn on_ack(&mut self,now:Instant,_sent:Instant,_bytes:u64,_limited:bool,rtt:&RttEstimator) {self.rtt=rtt.get();self.record(now,1,0);}
    fn on_packets_lost(&mut self,now:Instant,packets:u64) {self.record(now,0,packets);}
    fn on_congestion_event(&mut self,_:Instant,_:Instant,_:bool,_:u64) {}
    fn on_mtu_update(&mut self,mtu:u16){self.mtu=mtu;}
    fn window(&self)->u64 {if self.rtt.is_zero(){10240u64.max(2*u64::from(self.mtu))}else{((2.0*self.bps as f64*self.rtt.as_secs_f64()/self.ack_rate) as u64).max(2*u64::from(self.mtu))}}
    fn clone_box(&self)->Box<dyn Controller>{Box::new(self.clone())}
    fn initial_window(&self)->u64{10240u64.max(2*u64::from(self.mtu))}
    fn into_any(self:Box<Self>)->Box<dyn Any>{self}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_rate_loss_compensation_is_bounded_and_expires() {
        let now=Instant::now();let controller=Arc::new(Config(1_000_000)).build(now,1200);
        let mut controller=controller.into_any().downcast::<Brutal>().unwrap();
        controller.rtt=Duration::from_millis(100);
        for _ in 0..40 {controller.record(now,1,0);}
        assert_eq!(controller.pacing_rate_bytes(),Some(1_000_000));assert_eq!(controller.window(),200_000);
        controller.on_packets_lost(now,10);
        assert_eq!(controller.pacing_rate_bytes(),Some(1_250_000));assert_eq!(controller.window(),250_000);
        controller.on_packets_lost(now,1000);assert_eq!(controller.pacing_rate_bytes(),Some(1_250_000));
        controller.record(now+Duration::from_secs(6),1,0);
        assert_eq!(controller.pacing_rate_bytes(),Some(1_000_000));
        controller.on_mtu_update(9000);assert!(controller.window()>=18000);
        assert_eq!(controller.clone_box().pacing_rate_bytes(),controller.pacing_rate_bytes());
    }
}
