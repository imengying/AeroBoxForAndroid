pub use self::{
    decoder::{decode_stateless, Decoded, DecoderError},
    encoder::{encode_stateless, EncoderError},
    field::HeaderField,
};

pub(crate) mod block;
pub(crate) mod critical;
mod dynamic;
mod field;
mod parse_error;
pub(crate) mod receive;
mod static_;
pub(crate) mod stream;
mod vas;

mod decoder;
mod encoder;

mod prefix_int;
mod prefix_string;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub enum Error {
    Encoder(EncoderError),
    Decoder(DecoderError),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Encoder(e) => write!(f, "Encoder {}", e),
            Error::Decoder(e) => write!(f, "Decoder {}", e),
        }
    }
}
