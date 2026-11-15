use std::io::{Read, Write};

use crate::chunk::{CHUNK_LEN, Chunk};
use crate::codec::{read_message, write_message};
use crate::error::{ProtocolError, Result};
use crate::message::{Request, Response};

pub fn send_upload(writer: &mut impl Write, ciphertext: &[u8]) -> Result<()> {
    for piece in ciphertext.chunks(CHUNK_LEN) {
        let chunk = Chunk::new(piece.to_vec())?;
        write_message(writer, &Request::UploadChunk(chunk))?;
    }
    Ok(())
}

pub fn send_fetch(writer: &mut impl Write, ciphertext: &[u8]) -> Result<()> {
    for piece in ciphertext.chunks(CHUNK_LEN) {
        let chunk = Chunk::new(piece.to_vec())?;
        write_message(writer, &Response::Chunk(chunk))?;
    }
    Ok(())
}

pub fn receive_upload(
    reader: &mut impl Read,
    sink: &mut impl Write,
    expected_len: u64,
) -> Result<()> {
    let mut remaining = expected_len;
    while remaining > 0 {
        match read_message(reader)? {
            Request::UploadChunk(chunk) => remaining = store(&chunk, sink, remaining)?,
            _ => return Err(ProtocolError::UnexpectedMessage),
        }
    }
    Ok(())
}

pub fn receive_fetch(
    reader: &mut impl Read,
    sink: &mut impl Write,
    expected_len: u64,
) -> Result<()> {
    let mut remaining = expected_len;
    while remaining > 0 {
        match read_message(reader)? {
            Response::Chunk(chunk) => remaining = store(&chunk, sink, remaining)?,
            Response::Error(code) => return Err(ProtocolError::Remote(code)),
            _ => return Err(ProtocolError::UnexpectedMessage),
        }
    }
    Ok(())
}

fn store(chunk: &Chunk, sink: &mut impl Write, remaining: u64) -> Result<u64> {
    let bytes = chunk.as_bytes();
    if bytes.is_empty() {
        return Err(ProtocolError::EmptyChunk);
    }
    if bytes.len() as u64 > remaining {
        return Err(ProtocolError::TransferOverflow);
    }
    sink.write_all(bytes)?;
    Ok(remaining - bytes.len() as u64)
}
