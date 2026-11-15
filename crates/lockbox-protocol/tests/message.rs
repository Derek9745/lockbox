use std::io::Cursor;

use lockbox_protocol::challenge::CHALLENGE_NONCE_LEN;
use lockbox_protocol::chunk::CHUNK_LEN;
use lockbox_protocol::codec::{MAX_MESSAGE_LEN, read_message, write_message};
use lockbox_protocol::crypto::envelope::{Envelope, EnvelopeHeader, MAX_RECIPIENTS};
use lockbox_protocol::crypto::keys::generate_keypair;
use lockbox_protocol::crypto::sign::sign;
use lockbox_protocol::crypto::{CryptoError, SigningKey, VerifyingKey};
use lockbox_protocol::message::{MAX_CIPHERTEXT_LEN, MAX_LIFETIME_SECS};
use lockbox_protocol::{
    Challenge, Chunk, ErrorCode, FileHeader, FileId, ProtocolError, Purpose, Request, Response,
    SignedRequest,
};

fn encode<T: serde::Serialize>(message: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_message(&mut bytes, message).unwrap();
    bytes
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtocolError> {
    read_message(&mut Cursor::new(bytes))
}

fn envelope_header(recipients: usize) -> EnvelopeHeader {
    let keys: Vec<VerifyingKey> = (0..recipients)
        .map(|_| generate_keypair().verifying_key())
        .collect();
    Envelope::encrypt_to_recipients(b"x", &keys)
        .unwrap()
        .into_parts()
        .0
}

fn file_header(recipients: usize) -> FileHeader {
    FileHeader {
        envelope: envelope_header(recipients),
        ciphertext_len: 4096,
        expires_at: 1_700_000_300,
    }
}

fn signed_request(key: &SigningKey) -> SignedRequest {
    let challenge = Challenge::new(FileId::random(), Purpose::Fetch, 10);
    SignedRequest {
        file_id: challenge.file_id(),
        nonce: *challenge.nonce(),
        public_key: key.verifying_key(),
        signature: sign(&challenge.signing_bytes(), key),
    }
}

fn all_requests() -> Vec<Request> {
    let key = generate_keypair();
    vec![
        Request::BeginUpload,
        Request::BeginFetch {
            file_id: FileId::random(),
        },
        Request::BeginDelete {
            file_id: FileId::random(),
        },
        Request::Upload {
            proof: signed_request(&key),
            header: file_header(3),
        },
        Request::UploadChunk(Chunk::new(vec![1, 2, 3]).unwrap()),
        Request::Fetch(signed_request(&key)),
        Request::Delete(signed_request(&key)),
    ]
}

fn all_responses() -> Vec<Response> {
    vec![
        Response::Challenge(Challenge::new(FileId::random(), Purpose::Upload, 77)),
        Response::ReadyForUpload,
        Response::Uploaded {
            file_id: FileId::random(),
            expires_at: 1_700_000_300,
        },
        Response::FetchReady(file_header(2)),
        Response::Chunk(Chunk::new(vec![9; 100]).unwrap()),
        Response::Deleted,
        Response::Error(ErrorCode::Denied),
    ]
}

#[test]
fn every_request_round_trips() {
    for request in all_requests() {
        assert_eq!(decode::<Request>(&encode(&request)).unwrap(), request);
    }
}

#[test]
fn every_response_round_trips() {
    for response in all_responses() {
        assert_eq!(decode::<Response>(&encode(&response)).unwrap(), response);
    }
}

#[test]
fn every_error_code_round_trips_and_has_text() {
    for code in [
        ErrorCode::InvalidRequest,
        ErrorCode::UnexpectedMessage,
        ErrorCode::Denied,
        ErrorCode::TooLarge,
        ErrorCode::Internal,
    ] {
        assert_eq!(decode::<ErrorCode>(&encode(&code)).unwrap(), code);
        assert!(!code.to_string().is_empty());
    }
}

#[test]
fn the_request_kind_is_the_first_byte_in_a_fixed_order() {
    let kinds: Vec<u8> = all_requests()
        .iter()
        .map(|request| encode(request)[0])
        .collect();
    assert_eq!(kinds, [0, 1, 2, 3, 4, 5, 6]);
}

#[test]
fn the_response_kind_is_the_first_byte_in_a_fixed_order() {
    let kinds: Vec<u8> = all_responses()
        .iter()
        .map(|response| encode(response)[0])
        .collect();
    assert_eq!(kinds, [0, 1, 2, 3, 4, 5, 6]);
}

#[test]
fn a_begin_request_is_its_kind_and_the_file_id() {
    let id = FileId::random();
    let mut expected = vec![1];
    expected.extend_from_slice(id.as_bytes());
    assert_eq!(encode(&Request::BeginFetch { file_id: id }), expected);
    expected[0] = 2;
    assert_eq!(encode(&Request::BeginDelete { file_id: id }), expected);
}

#[test]
fn an_unknown_kind_is_rejected() {
    assert!(matches!(
        decode::<Request>(&[7]),
        Err(ProtocolError::Decode(_))
    ));
    assert!(matches!(
        decode::<Response>(&[7]),
        Err(ProtocolError::Decode(_))
    ));
}

#[test]
fn an_oversize_chunk_inside_a_request_is_rejected() {
    let mut bytes = vec![4];
    bytes.extend(postcard::to_stdvec(&vec![0u8; CHUNK_LEN + 1]).unwrap());
    assert!(matches!(
        decode::<Request>(&bytes),
        Err(ProtocolError::Decode(_))
    ));
}

#[test]
fn the_largest_upload_request_fits_in_a_message() {
    let key = generate_keypair();
    let request = Request::Upload {
        proof: signed_request(&key),
        header: file_header(MAX_RECIPIENTS),
    };
    let bytes = encode(&request);
    assert!(bytes.len() < MAX_MESSAGE_LEN / 10, "{} bytes", bytes.len());
    assert_eq!(decode::<Request>(&bytes).unwrap(), request);
}

#[test]
fn the_largest_fetch_response_fits_in_a_message() {
    let response = Response::FetchReady(file_header(MAX_RECIPIENTS));
    let bytes = encode(&response);
    assert!(bytes.len() < MAX_MESSAGE_LEN / 10, "{} bytes", bytes.len());
    assert_eq!(decode::<Response>(&bytes).unwrap(), response);
}

#[test]
fn a_full_chunk_response_fits_in_a_message() {
    let response = Response::Chunk(Chunk::new(vec![5; CHUNK_LEN]).unwrap());
    let bytes = encode(&response);
    assert!(bytes.len() < MAX_MESSAGE_LEN / 2);
    assert_eq!(decode::<Response>(&bytes).unwrap(), response);
}

#[test]
fn the_nonce_in_a_signed_request_is_32_bytes() {
    assert_eq!(CHALLENGE_NONCE_LEN, 32);
    let key = generate_keypair();
    assert_eq!(signed_request(&key).nonce.len(), CHALLENGE_NONCE_LEN);
}

#[test]
fn the_server_caps_lifetime_at_five_minutes() {
    assert_eq!(MAX_LIFETIME_SECS, 300);
}

#[test]
fn a_valid_file_header_passes_validation() {
    assert!(file_header(3).validate().is_ok());
    assert!(file_header(MAX_RECIPIENTS).validate().is_ok());
}

#[test]
fn the_ciphertext_length_must_be_within_bounds() {
    let mut header = file_header(1);
    for (len, ok) in [
        (0, false),
        (15, false),
        (16, true),
        (MAX_CIPHERTEXT_LEN, true),
        (MAX_CIPHERTEXT_LEN + 1, false),
        (u64::MAX, false),
    ] {
        header.ciphertext_len = len;
        let result = header.validate();
        assert_eq!(result.is_ok(), ok, "length {len}");
        if !ok {
            assert!(matches!(
                result,
                Err(ProtocolError::CiphertextLenOutOfRange { len: reported, .. }) if reported == len
            ));
        }
    }
}

const NONCE_AT: usize = 1;
const COUNT_AT: usize = NONCE_AT + 24;
const ENTRIES_AT: usize = COUNT_AT + 1;
const SEALED_LEN_AT: usize = ENTRIES_AT + 33 + 32 + 24;

fn header_with_bytes(bytes: &[u8]) -> FileHeader {
    FileHeader {
        envelope: decode(bytes).unwrap(),
        ciphertext_len: 4096,
        expires_at: 0,
    }
}

fn one_recipient_bytes() -> Vec<u8> {
    let bytes = postcard::to_stdvec(&envelope_header(1)).unwrap();
    assert_eq!(bytes.len(), ENTRIES_AT + 33 + 32 + 24 + 1 + 48);
    assert_eq!(bytes[COUNT_AT], 1);
    assert_eq!(bytes[SEALED_LEN_AT], 48);
    bytes
}

#[test]
fn an_unknown_envelope_version_is_rejected() {
    let mut bytes = one_recipient_bytes();
    bytes[0] = 9;
    assert!(matches!(
        header_with_bytes(&bytes).validate(),
        Err(ProtocolError::Crypto(CryptoError::UnsupportedVersion(9)))
    ));
}

#[test]
fn zero_recipients_are_rejected() {
    let mut bytes = one_recipient_bytes();
    bytes.truncate(ENTRIES_AT);
    bytes[COUNT_AT] = 0;
    assert!(matches!(
        header_with_bytes(&bytes).validate(),
        Err(ProtocolError::Crypto(CryptoError::MalformedEnvelope))
    ));
}

#[test]
fn too_many_recipients_are_rejected() {
    let one = one_recipient_bytes();
    let entry = one[ENTRIES_AT..].to_vec();
    for count in [MAX_RECIPIENTS + 1, 100] {
        let mut bytes = one[..ENTRIES_AT].to_vec();
        bytes[COUNT_AT] = count as u8;
        for _ in 0..count {
            bytes.extend_from_slice(&entry);
        }
        assert!(
            matches!(
                header_with_bytes(&bytes).validate(),
                Err(ProtocolError::Crypto(CryptoError::MalformedEnvelope))
            ),
            "{count} recipients"
        );
    }
}

#[test]
fn a_sealed_key_of_the_wrong_length_is_rejected() {
    let shorter = {
        let mut bytes = one_recipient_bytes();
        bytes[SEALED_LEN_AT] = 47;
        bytes.pop();
        bytes
    };
    let longer = {
        let mut bytes = one_recipient_bytes();
        bytes[SEALED_LEN_AT] = 49;
        bytes.push(0);
        bytes
    };
    for bytes in [shorter, longer] {
        assert!(matches!(
            header_with_bytes(&bytes).validate(),
            Err(ProtocolError::Crypto(CryptoError::MalformedEnvelope))
        ));
    }
}
