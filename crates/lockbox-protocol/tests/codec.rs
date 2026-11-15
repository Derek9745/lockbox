use std::io::{self, Cursor, Read};

use bincode::error::DecodeError;
use lockbox_protocol::ProtocolError;
use lockbox_protocol::codec::{MAX_MESSAGE_LEN, read_message, write_message};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
enum Message {
    Ping,
    Number(u32),
    Chunk { data: Vec<u8> },
    Name(String),
}

fn encode(message: &Message) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_message(&mut bytes, message).unwrap();
    bytes
}

fn decode(bytes: &[u8]) -> Result<Message, ProtocolError> {
    read_message(&mut Cursor::new(bytes))
}

struct OneByteAtATime<'a>(&'a [u8]);

impl Read for OneByteAtATime<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match (self.0.split_first(), buf.first_mut()) {
            (Some((&byte, rest)), Some(slot)) => {
                *slot = byte;
                self.0 = rest;
                Ok(1)
            }
            _ => Ok(0),
        }
    }
}

#[test]
fn every_kind_of_message_round_trips() {
    let messages = [
        Message::Ping,
        Message::Number(0xDEAD_BEEF),
        Message::Chunk { data: vec![] },
        Message::Chunk {
            data: (0..=255).collect(),
        },
        Message::Name("lockbox".to_string()),
    ];
    for message in messages {
        assert_eq!(decode(&encode(&message)).unwrap(), message);
    }
}

#[test]
fn the_wire_layout_is_big_endian_with_fixed_width_numbers() {
    assert_eq!(encode(&Message::Ping), [0, 0, 0, 0]);
    assert_eq!(
        encode(&Message::Number(0x0102_0304)),
        [0, 0, 0, 1, 1, 2, 3, 4]
    );
    assert_eq!(
        encode(&Message::Chunk { data: vec![9, 8] }),
        [0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 9, 8]
    );
}

#[test]
fn several_messages_are_read_in_order_from_one_stream() {
    let sent = [
        Message::Number(1),
        Message::Chunk {
            data: vec![1, 2, 3],
        },
        Message::Ping,
        Message::Name("last".to_string()),
    ];
    let mut bytes = Vec::new();
    for message in &sent {
        write_message(&mut bytes, message).unwrap();
    }
    let mut reader = Cursor::new(bytes);
    for expected in sent {
        assert_eq!(read_message::<Message>(&mut reader).unwrap(), expected);
    }
    assert!(matches!(
        read_message::<Message>(&mut reader),
        Err(ProtocolError::ConnectionClosed)
    ));
}

#[test]
fn an_empty_stream_means_the_connection_closed() {
    assert!(matches!(decode(&[]), Err(ProtocolError::ConnectionClosed)));
}

#[test]
fn a_stream_cut_inside_a_message_means_the_connection_closed() {
    let bytes = encode(&Message::Chunk { data: vec![5; 20] });
    for length in 0..bytes.len() {
        assert!(
            matches!(
                decode(&bytes[..length]),
                Err(ProtocolError::ConnectionClosed)
            ),
            "length {length}"
        );
    }
}

#[test]
fn an_unknown_message_kind_is_a_decode_error() {
    assert!(matches!(
        decode(&[0, 0, 0, 99]),
        Err(ProtocolError::Decode(_))
    ));
}

#[test]
fn invalid_text_is_a_decode_error() {
    let mut bytes = vec![0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 2];
    bytes.extend([0xFF, 0xFE]);
    assert!(matches!(decode(&bytes), Err(ProtocolError::Decode(_))));
}

#[test]
fn a_message_over_the_limit_is_rejected_when_writing_and_nothing_is_written() {
    let message = Message::Chunk {
        data: vec![0; MAX_MESSAGE_LEN],
    };
    let mut out = Vec::new();
    let error = write_message(&mut out, &message).unwrap_err();
    assert!(matches!(
        error,
        ProtocolError::MessageTooLarge { len, max }
            if len > MAX_MESSAGE_LEN && max == MAX_MESSAGE_LEN
    ));
    assert!(out.is_empty());
}

#[test]
fn a_message_over_the_limit_is_rejected_when_reading() {
    let message = Message::Chunk {
        data: vec![0; 2 * MAX_MESSAGE_LEN],
    };
    let bytes = bincode::serde::encode_to_vec(
        &message,
        bincode::config::standard()
            .with_big_endian()
            .with_fixed_int_encoding(),
    )
    .unwrap();
    assert!(matches!(
        decode(&bytes),
        Err(ProtocolError::Decode(DecodeError::LimitExceeded))
    ));
}

#[test]
fn a_huge_claimed_length_does_not_allocate_it() {
    let mut bytes = vec![0, 0, 0, 2];
    bytes.extend(u64::MAX.to_be_bytes());
    assert!(matches!(
        decode(&bytes),
        Err(ProtocolError::ConnectionClosed)
    ));
}

#[test]
fn a_reader_that_returns_one_byte_at_a_time_still_works() {
    let message = Message::Chunk {
        data: vec![3; 1000],
    };
    let bytes = encode(&message);
    let read: Message = read_message(&mut OneByteAtATime(&bytes)).unwrap();
    assert_eq!(read, message);
}

#[test]
fn a_failing_writer_reports_an_io_error() {
    struct Broken;
    impl io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert!(matches!(
        write_message(&mut Broken, &Message::Ping),
        Err(ProtocolError::Io(_))
    ));
}
