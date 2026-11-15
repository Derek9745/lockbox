use serde::{Deserialize, Serialize};

use crate::challenge::{CHALLENGE_NONCE_LEN, Challenge};
use crate::chunk::Chunk;
use crate::crypto::envelope::{EnvelopeHeader, MIN_CIPHERTEXT_LEN};
use crate::crypto::{Signature, VerifyingKey};
use crate::error::{ProtocolError, Result};
use crate::file_id::FileId;

pub const MAX_CIPHERTEXT_LEN: u64 = 64 * 1024 * 1024;
pub const MAX_LIFETIME_SECS: u64 = 300;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHeader {
    pub envelope: EnvelopeHeader,
    pub ciphertext_len: u64,
    pub expires_at: u64,
}

impl FileHeader {
    pub fn validate(&self) -> Result<()> {
        self.envelope.validate()?;
        let min = MIN_CIPHERTEXT_LEN as u64;
        if self.ciphertext_len < min || self.ciphertext_len > MAX_CIPHERTEXT_LEN {
            return Err(ProtocolError::CiphertextLenOutOfRange {
                len: self.ciphertext_len,
                min,
                max: MAX_CIPHERTEXT_LEN,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRequest {
    pub file_id: FileId,
    pub nonce: [u8; CHALLENGE_NONCE_LEN],
    pub public_key: VerifyingKey,
    pub signature: Signature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum ErrorCode {
    #[error("the request was malformed")]
    InvalidRequest,

    #[error("that message was not expected now")]
    UnexpectedMessage,

    #[error("the request was denied")]
    Denied,

    #[error("the file is too large")]
    TooLarge,

    #[error("the server failed")]
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    BeginUpload,
    BeginFetch {
        file_id: FileId,
    },
    BeginDelete {
        file_id: FileId,
    },
    Upload {
        proof: SignedRequest,
        header: FileHeader,
    },
    UploadChunk(Chunk),
    Fetch(SignedRequest),
    Delete(SignedRequest),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Challenge(Challenge),
    ReadyForUpload,
    Uploaded { file_id: FileId, expires_at: u64 },
    FetchReady(FileHeader),
    Chunk(Chunk),
    Deleted,
    Error(ErrorCode),
}
