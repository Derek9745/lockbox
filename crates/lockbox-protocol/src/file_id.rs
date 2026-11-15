use std::fmt;
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::error::ProtocolError;

pub const FILE_ID_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileId([u8; FILE_ID_LEN]);

impl FileId {
    pub fn random() -> Self {
        let mut bytes = [0u8; FILE_ID_LEN];
        rand::fill(&mut bytes[..]);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; FILE_ID_LEN] {
        &self.0
    }
}

impl From<[u8; FILE_ID_LEN]> for FileId {
    fn from(bytes: [u8; FILE_ID_LEN]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for FileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl FromStr for FileId {
    type Err = ProtocolError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| ProtocolError::InvalidFileId)?;
        let bytes =
            <[u8; FILE_ID_LEN]>::try_from(bytes).map_err(|_| ProtocolError::InvalidFileId)?;
        Ok(Self(bytes))
    }
}
