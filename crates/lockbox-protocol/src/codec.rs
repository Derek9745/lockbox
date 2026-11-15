use std::io::{Read, Write};

use postcard::Error as PostcardError;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{ProtocolError, Result};

pub const MAX_MESSAGE_LEN: usize = 1024 * 1024;

const SCRATCH_LEN: usize = 4096;

pub fn write_message<T: Serialize>(writer: &mut impl Write, message: &T) -> Result<()> {
    let bytes = postcard::to_stdvec(message).map_err(ProtocolError::Encode)?;
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
    let mut limited = reader.take(MAX_MESSAGE_LEN as u64);
    let mut scratch = [0u8; SCRATCH_LEN];
    let result = postcard::from_io((&mut limited, &mut scratch[..])).map(|(message, _)| message);
    match result {
        Ok(message) => Ok(message),
        Err(PostcardError::DeserializeUnexpectedEnd) if limited.limit() == 0 => {
            Err(ProtocolError::MessageLimitExceeded {
                max: MAX_MESSAGE_LEN,
            })
        }
        Err(PostcardError::DeserializeUnexpectedEnd) => Err(ProtocolError::ConnectionClosed),
        Err(error) => Err(ProtocolError::Decode(error)),
    }
}
