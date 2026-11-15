use bincode::error::{DecodeError, EncodeError};

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("could not encode message: {0}")]
    Encode(#[from] EncodeError),

    #[error("could not decode message: {0}")]
    Decode(DecodeError),

    #[error("message of {len} bytes exceeds the limit of {max}")]
    MessageTooLarge { len: usize, max: usize },

    #[error("connection closed")]
    ConnectionClosed,

    #[error("invalid file id")]
    InvalidFileId,
}

pub type Result<T> = std::result::Result<T, ProtocolError>;
