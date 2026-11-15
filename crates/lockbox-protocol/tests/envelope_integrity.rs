use lockbox_protocol::crypto::envelope::{Envelope, EnvelopeHeader, MAX_RECIPIENTS};
use lockbox_protocol::crypto::keys::generate_keypair;
use lockbox_protocol::crypto::{SigningKey, VerifyingKey};

const VERSION_LEN: usize = 1;
const NONCE_LEN: usize = 24;
const ENTRIES_AT: usize = VERSION_LEN + NONCE_LEN + 1;
const ENTRY_LEN: usize = 33 + 32 + 24 + 1 + 48;
const SEALED_AT: usize = 33 + 32 + 24 + 1;

fn recipients(count: usize) -> (Vec<SigningKey>, Vec<VerifyingKey>) {
    let secrets: Vec<SigningKey> = (0..count).map(|_| generate_keypair()).collect();
    let publics = secrets.iter().map(SigningKey::verifying_key).collect();
    (secrets, publics)
}

fn split(message: &[u8], publics: &[VerifyingKey]) -> (Vec<u8>, Vec<u8>) {
    let (header, ciphertext) = Envelope::encrypt_to_recipients(message, publics)
        .unwrap()
        .into_parts();
    (postcard::to_stdvec(&header).unwrap(), ciphertext)
}

fn open(header: &[u8], ciphertext: &[u8], key: &SigningKey) -> Option<Vec<u8>> {
    let header: EnvelopeHeader = postcard::from_bytes(header).ok()?;
    let (header, ciphertext) = Envelope::from_parts(header, ciphertext.to_vec())
        .ok()?
        .into_parts();
    header
        .for_recipient(&key.verifying_key())?
        .decrypt(key, &ciphertext)
        .ok()
}

#[test]
fn an_envelope_opens_after_its_parts_are_encoded_and_decoded() {
    let (secrets, publics) = recipients(3);
    let (header, ciphertext) = split(b"over the wire", &publics);
    for secret in &secrets {
        assert_eq!(
            open(&header, &ciphertext, secret).unwrap(),
            b"over the wire"
        );
    }
}

#[test]
fn the_maximum_number_of_recipients_can_all_open_it() {
    let (secrets, publics) = recipients(MAX_RECIPIENTS);
    let (header, ciphertext) = split(b"full", &publics);
    assert_eq!(header.len(), ENTRIES_AT + MAX_RECIPIENTS * ENTRY_LEN);
    for secret in [
        &secrets[0],
        &secrets[MAX_RECIPIENTS / 2],
        &secrets[MAX_RECIPIENTS - 1],
    ] {
        assert_eq!(open(&header, &ciphertext, secret).unwrap(), b"full");
    }
}

#[test]
fn changing_any_byte_of_a_single_recipient_envelope_is_detected() {
    let (secrets, publics) = recipients(1);
    let (header, ciphertext) = split(b"integrity matters", &publics);
    for index in 0..header.len() {
        for mask in [0x01u8, 0x80] {
            let mut tampered = header.clone();
            tampered[index] ^= mask;
            assert!(
                open(&tampered, &ciphertext, &secrets[0]).is_none(),
                "header byte {index} with mask {mask:#04x} was not detected"
            );
        }
    }
    for index in 0..ciphertext.len() {
        for mask in [0x01u8, 0x80] {
            let mut tampered = ciphertext.clone();
            tampered[index] ^= mask;
            assert!(
                open(&header, &tampered, &secrets[0]).is_none(),
                "ciphertext byte {index} with mask {mask:#04x} was not detected"
            );
        }
    }
}

#[test]
fn changing_a_byte_never_makes_anyone_read_a_different_message() {
    let (secrets, publics) = recipients(3);
    let message = b"integrity matters";
    let (header, ciphertext) = split(message, &publics);
    for index in 0..header.len() {
        let mut tampered = header.clone();
        tampered[index] ^= 0x01;
        for secret in &secrets {
            if let Some(plaintext) = open(&tampered, &ciphertext, secret) {
                assert_eq!(
                    plaintext, message,
                    "header byte {index} changed the message"
                );
            }
        }
    }
}

#[test]
fn damaging_one_entry_only_affects_its_own_recipient() {
    let (secrets, publics) = recipients(3);
    let (header, ciphertext) = split(b"independent", &publics);
    let mut tampered = header.clone();
    tampered[ENTRIES_AT + ENTRY_LEN + SEALED_AT + 5] ^= 0x01;
    assert_eq!(
        open(&tampered, &ciphertext, &secrets[0]).unwrap(),
        b"independent"
    );
    assert!(open(&tampered, &ciphertext, &secrets[1]).is_none());
    assert_eq!(
        open(&tampered, &ciphertext, &secrets[2]).unwrap(),
        b"independent"
    );
}

#[test]
fn every_truncated_header_is_rejected() {
    let (secrets, publics) = recipients(2);
    let (header, ciphertext) = split(b"cut me short", &publics);
    for length in 0..header.len() {
        assert!(
            open(&header[..length], &ciphertext, &secrets[0]).is_none(),
            "length {length} was accepted"
        );
    }
}

#[test]
fn every_truncated_ciphertext_is_rejected() {
    let (secrets, publics) = recipients(1);
    let (header, ciphertext) = split(b"cut me short", &publics);
    for length in 0..ciphertext.len() {
        assert!(
            open(&header, &ciphertext[..length], &secrets[0]).is_none(),
            "length {length} was accepted"
        );
    }
}

#[test]
fn an_entry_moved_to_another_envelope_does_not_open() {
    let (secrets_a, publics_a) = recipients(1);
    let (_, publics_b) = recipients(1);
    let (header_a, ciphertext_a) = split(b"first", &publics_a);
    let (header_b, _) = split(b"second", &publics_b);
    let mut spliced = header_a.clone();
    spliced[ENTRIES_AT..ENTRIES_AT + ENTRY_LEN]
        .copy_from_slice(&header_b[ENTRIES_AT..ENTRIES_AT + ENTRY_LEN]);
    assert!(open(&spliced, &ciphertext_a, &secrets_a[0]).is_none());
    assert_eq!(
        open(&header_a, &ciphertext_a, &secrets_a[0]).unwrap(),
        b"first"
    );
}

#[test]
fn a_header_from_another_file_does_not_open_this_ciphertext() {
    let (secrets, publics) = recipients(1);
    let (header_a, ciphertext_a) = split(b"first", &publics);
    let (header_b, ciphertext_b) = split(b"second", &publics);
    assert!(open(&header_a, &ciphertext_b, &secrets[0]).is_none());
    assert!(open(&header_b, &ciphertext_a, &secrets[0]).is_none());
}
