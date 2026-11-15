use serde::{Deserialize, Serialize};

use crate::error::{ProtocolError, Result};

pub const CHUNK_LEN: usize = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<u8>")]
pub struct Chunk(Vec<u8>);

impl Chunk {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        Self::try_from(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl TryFrom<Vec<u8>> for Chunk {
    type Error = ProtocolError;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > CHUNK_LEN {
            return Err(ProtocolError::ChunkTooLarge {
                len: bytes.len(),
                max: CHUNK_LEN,
            });
        }
        Ok(Self(bytes))
    }
}
