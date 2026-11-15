use serde::{Deserialize, Serialize};

use crate::file_id::{FILE_ID_LEN, FileId};

pub const CHALLENGE_TTL_SECS: u64 = 60;
pub const CHALLENGE_NONCE_LEN: usize = 32;
pub const SIGNING_BYTES_LEN: usize = 1 + FILE_ID_LEN + CHALLENGE_NONCE_LEN + 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Purpose {
    Fetch,
    Delete,
}

impl Purpose {
    fn as_byte(self) -> u8 {
        match self {
            Purpose::Fetch => 1,
            Purpose::Delete => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    file_id: FileId,
    purpose: Purpose,
    nonce: [u8; CHALLENGE_NONCE_LEN],
    issued_at: u64,
}

impl Challenge {
    pub fn new(file_id: FileId, purpose: Purpose, issued_at: u64) -> Self {
        let mut nonce = [0u8; CHALLENGE_NONCE_LEN];
        rand::fill(&mut nonce[..]);
        Self {
            file_id,
            purpose,
            nonce,
            issued_at,
        }
    }

    pub fn file_id(&self) -> FileId {
        self.file_id
    }

    pub fn purpose(&self) -> Purpose {
        self.purpose
    }

    pub fn nonce(&self) -> &[u8; CHALLENGE_NONCE_LEN] {
        &self.nonce
    }

    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub fn is_live_at(&self, now: u64) -> bool {
        now >= self.issued_at && now - self.issued_at < CHALLENGE_TTL_SECS
    }

    pub fn signing_bytes(&self) -> [u8; SIGNING_BYTES_LEN] {
        let mut bytes = [0u8; SIGNING_BYTES_LEN];
        bytes[0] = self.purpose.as_byte();
        bytes[1..1 + FILE_ID_LEN].copy_from_slice(self.file_id.as_bytes());
        bytes[1 + FILE_ID_LEN..1 + FILE_ID_LEN + CHALLENGE_NONCE_LEN].copy_from_slice(&self.nonce);
        bytes[1 + FILE_ID_LEN + CHALLENGE_NONCE_LEN..]
            .copy_from_slice(&self.issued_at.to_be_bytes());
        bytes
    }
}
