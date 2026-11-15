use std::io::{ErrorKind, Read, Write};

use bincode::config::{self, Config};
use bincode::error::DecodeError;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{ProtocolError, Result};

pub const MAX_MESSAGE_LEN: usize = 1024 * 1024;

fn config() -> impl Config {
    config::standard()
        .with_big_endian()
        .with_fixed_int_encoding()
        .with_limit::<MAX_MESSAGE_LEN>()
}

pub fn write_message<T: Serialize>(writer: &mut impl Write, message: &T) -> Result<()> {
    let bytes = bincode::serde::encode_to_vec(message, config())?;
    if bytes.len() > MAX_MESSAGE_LEN {
        return Err(ProtocolError::MessageTooLarge {
            len: bytes.len(),
            max: MAX_MESSAGE_LEN,
        });
    }
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

pub fn read_message<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T> {
    bincode::serde::decode_from_std_read(reader, config()).map_err(|error| match error {
        DecodeError::Io { inner, .. } if inner.kind() == ErrorKind::UnexpectedEof => {
            ProtocolError::ConnectionClosed
        }
        other => ProtocolError::Decode(other),
    })
}
