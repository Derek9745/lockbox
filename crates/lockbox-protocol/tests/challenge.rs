use std::collections::HashSet;
use std::io::Cursor;

use lockbox_protocol::challenge::{CHALLENGE_NONCE_LEN, CHALLENGE_TTL_SECS, SIGNING_BYTES_LEN};
use lockbox_protocol::codec::{read_message, write_message};
use lockbox_protocol::crypto::keys::generate_keypair;
use lockbox_protocol::crypto::sign::{sign, verify};
use lockbox_protocol::{Challenge, FileId, ProtocolError, Purpose};

const WIRE_LEN: usize = 16 + 4 + CHALLENGE_NONCE_LEN + 8;
const PURPOSE_AT: usize = 16;
const NONCE_AT: usize = 20;
const ISSUED_AT_AT: usize = 52;

fn encode(challenge: &Challenge) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_message(&mut bytes, challenge).unwrap();
    bytes
}

fn decode(bytes: &[u8]) -> Result<Challenge, ProtocolError> {
    read_message(&mut Cursor::new(bytes))
}

#[test]
fn a_challenge_keeps_what_it_was_made_with() {
    let id = FileId::random();
    let challenge = Challenge::new(id, Purpose::Delete, 1_700_000_000);
    assert_eq!(challenge.file_id(), id);
    assert_eq!(challenge.purpose(), Purpose::Delete);
    assert_eq!(challenge.issued_at(), 1_700_000_000);
}

#[test]
fn every_challenge_has_its_own_nonce() {
    let id = FileId::random();
    let nonces: HashSet<[u8; CHALLENGE_NONCE_LEN]> = (0..1000)
        .map(|_| *Challenge::new(id, Purpose::Fetch, 0).nonce())
        .collect();
    assert_eq!(nonces.len(), 1000);
}

#[test]
fn a_challenge_is_live_for_exactly_its_lifetime() {
    let challenge = Challenge::new(FileId::random(), Purpose::Fetch, 1000);
    assert!(challenge.is_live_at(1000));
    assert!(challenge.is_live_at(1000 + CHALLENGE_TTL_SECS - 1));
    assert!(!challenge.is_live_at(1000 + CHALLENGE_TTL_SECS));
    assert!(!challenge.is_live_at(1000 + CHALLENGE_TTL_SECS + 1));
    assert!(!challenge.is_live_at(u64::MAX));
}

#[test]
fn a_challenge_is_not_live_before_it_was_issued() {
    let challenge = Challenge::new(FileId::random(), Purpose::Fetch, 1000);
    assert!(!challenge.is_live_at(999));
    assert!(!challenge.is_live_at(0));
}

#[test]
fn liveness_does_not_overflow_near_the_end_of_time() {
    let challenge = Challenge::new(FileId::random(), Purpose::Fetch, u64::MAX);
    assert!(challenge.is_live_at(u64::MAX));
    assert!(!challenge.is_live_at(0));
}

#[test]
fn the_signing_bytes_have_a_fixed_layout() {
    let id = FileId::from(std::array::from_fn(|i| 0x10 + i as u8));
    let fetch = Challenge::new(id, Purpose::Fetch, 0x0102_0304_0506_0708);
    let delete = Challenge::new(id, Purpose::Delete, 0x0102_0304_0506_0708);

    let bytes = fetch.signing_bytes();
    assert_eq!(bytes.len(), SIGNING_BYTES_LEN);
    assert_eq!(bytes[0], 1);
    assert_eq!(&bytes[1..17], id.as_bytes());
    assert_eq!(&bytes[17..49], fetch.nonce());
    assert_eq!(&bytes[49..], [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(delete.signing_bytes()[0], 2);
}

#[test]
fn on_the_wire_a_challenge_is_a_fixed_size() {
    let challenge = Challenge::new(FileId::random(), Purpose::Fetch, 5);
    let bytes = encode(&challenge);
    assert_eq!(bytes.len(), WIRE_LEN);
    assert_eq!(decode(&bytes).unwrap(), challenge);
}

#[test]
fn an_unknown_purpose_is_rejected() {
    let mut bytes = encode(&Challenge::new(FileId::random(), Purpose::Fetch, 5));
    bytes[PURPOSE_AT..NONCE_AT].copy_from_slice(&2u32.to_be_bytes());
    assert!(matches!(decode(&bytes), Err(ProtocolError::Decode(_))));
}

#[test]
fn a_signature_over_a_challenge_verifies() {
    let key = generate_keypair();
    let challenge = Challenge::new(FileId::random(), Purpose::Fetch, 77);
    let signature = sign(&challenge.signing_bytes(), &key);
    assert!(verify(&challenge.signing_bytes(), &signature, &key.verifying_key()).is_ok());
}

#[test]
fn changing_any_field_breaks_the_signature() {
    let key = generate_keypair();
    let challenge = Challenge::new(FileId::random(), Purpose::Fetch, 77);
    let signature = sign(&challenge.signing_bytes(), &key);
    let wire = encode(&challenge);

    let mut tampered = Vec::new();
    for range in [
        0..16,
        PURPOSE_AT..NONCE_AT,
        NONCE_AT..ISSUED_AT_AT,
        ISSUED_AT_AT..WIRE_LEN,
    ] {
        let mut bytes = wire.clone();
        let last = range.end - 1;
        bytes[last] ^= 0x01;
        tampered.push(bytes);
    }
    let mut delete_instead = wire.clone();
    delete_instead[PURPOSE_AT..NONCE_AT].copy_from_slice(&1u32.to_be_bytes());
    tampered.push(delete_instead);

    for bytes in tampered {
        let other = decode(&bytes).unwrap();
        assert_ne!(other, challenge);
        assert_ne!(other.signing_bytes(), challenge.signing_bytes());
        assert!(verify(&other.signing_bytes(), &signature, &key.verifying_key()).is_err());
    }
}

#[test]
fn a_signature_from_another_key_does_not_verify() {
    let challenge = Challenge::new(FileId::random(), Purpose::Fetch, 77);
    let signature = sign(&challenge.signing_bytes(), &generate_keypair());
    assert!(
        verify(
            &challenge.signing_bytes(),
            &signature,
            &generate_keypair().verifying_key()
        )
        .is_err()
    );
}
