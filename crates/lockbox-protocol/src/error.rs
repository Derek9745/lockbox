#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("could not encode message: {0}")]
    Encode(postcard::Error),

    #[error("could not decode message: {0}")]
    Decode(postcard::Error),

    #[error("message of {len} bytes exceeds the limit of {max}")]
    MessageTooLarge { len: usize, max: usize },

    #[error("incoming message exceeds the limit of {max} bytes")]
    MessageLimitExceeded { max: usize },

    #[error("connection closed")]
    ConnectionClosed,

    #[error("invalid file id")]
    InvalidFileId,

    #[error("chunk of {len} bytes exceeds the limit of {max}")]
    ChunkTooLarge { len: usize, max: usize },

    #[error("ciphertext length {len} is outside {min}..={max}")]
    CiphertextLenOutOfRange { len: u64, min: u64, max: u64 },

    #[error("cryptographic check failed: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),

    #[error("the answer does not match the challenge")]
    ChallengeMismatch,

    #[error("the challenge has expired")]
    ChallengeExpired,
}

pub type Result<T> = std::result::Result<T, ProtocolError>;
