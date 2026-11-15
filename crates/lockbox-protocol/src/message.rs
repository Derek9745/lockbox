use serde::{Deserialize, Serialize};

use crate::challenge::{CHALLENGE_NONCE_LEN, Challenge, Purpose};
use crate::chunk::Chunk;
use crate::crypto::envelope::{EnvelopeHeader, MIN_CIPHERTEXT_LEN};
use crate::crypto::sign::{sign, verify};
use crate::crypto::{Signature, SigningKey, VerifyingKey};
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

impl SignedRequest {
    pub fn answer(challenge: &Challenge, key: &SigningKey) -> Self {
        Self {
            file_id: challenge.file_id(),
            nonce: *challenge.nonce(),
            public_key: key.verifying_key(),
            signature: sign(&challenge.signing_bytes(), key),
        }
    }

    pub fn check(&self, challenge: &Challenge, purpose: Purpose, now: u64) -> Result<()> {
        if self.file_id != challenge.file_id()
            || self.nonce != *challenge.nonce()
            || purpose != challenge.purpose()
        {
            return Err(ProtocolError::ChallengeMismatch);
        }
        if !challenge.is_live_at(now) {
            return Err(ProtocolError::ChallengeExpired);
        }
        verify(
            &challenge.signing_bytes(),
            &self.signature,
            &self.public_key,
        )?;
        Ok(())
    }
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
