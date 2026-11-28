//! Explicit independent TLS 1.3 key shares for browser profiles.
use alloc::{boxed::Box, vec::Vec};

use super::hs::ClientHelloInput;
use crate::crypto::ActiveKeyExchange;
use crate::{Error, ProtocolVersion};

pub(super) fn validate(input: &ClientHelloInput) -> Result<(), Error> {
    let config = &input.config;
    let groups = &config.initial_key_share_groups;
    if groups.len() > 8 {
        return Err(Error::General(
            "at most eight initial key shares are supported".into(),
        ));
    }
    for (index, group) in groups.iter().enumerate() {
        if groups[..index].contains(group)
            || config
                .find_kx_group(*group, ProtocolVersion::TLSv1_3)
                .is_none()
        {
            return Err(Error::General(
                "duplicate or unsupported initial key share group".into(),
            ));
        }
    }
    if !groups.is_empty()
        && !config
            .versions
            .contains(ProtocolVersion::TLSv1_3)
    {
        return Err(Error::General("initial key shares require TLS 1.3".into()));
    }
    Ok(())
}

pub(super) fn start_additional(input: &mut ClientHelloInput) -> Result<(), Error> {
    input.additional_key_shares = input
        .config
        .initial_key_share_groups
        .iter()
        .skip(1)
        .map(|group| {
            input
                .config
                .find_kx_group(*group, ProtocolVersion::TLSv1_3)
                .ok_or_else(|| Error::General("initial key share group unavailable".into()))?
                .start()
        })
        .collect::<Result<Vec<Box<dyn ActiveKeyExchange>>, Error>>()?;
    Ok(())
}
