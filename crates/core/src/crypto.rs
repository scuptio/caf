//! Encryption primitives for sealed `.caf` artifacts (see
//! `doc/spec/container-format.md` §7).
//!
//! Key hierarchy:
//!
//! - one random (or convergently derived) 32-byte **content key** per artifact;
//! - the content key is wrapped per recipient into the **keybox** section:
//!   P-256 ECDH against an ephemeral keypair, then a domain-separated SHA-256
//!   KDF, then AES-256-GCM (`p256-ecdh-sha256`); stanzas are anonymous — no
//!   recipient key id is stored;
//! - sections use per-section **sub-keys** derived from the content key, so
//!   chunk nonces are plain counters (`00 00 00 00 || u64 BE chunk index`)
//!   without cross-section nonce reuse.
//!
//! All derivation goes through one KDF over uniformly random 32-byte inputs:
//! `KDF(label, ikm) = SHA-256("CAF-KDF-1" || 0x00 || label || 0x00 || ikm)`.

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};

use crate::hex;

/// Byte length of a content key (AES-256).
pub const CONTENT_KEY_LEN: usize = 32;
/// AES-GCM tag length appended to every ciphertext chunk.
pub const AEAD_TAG_LEN: usize = 16;
/// AES-GCM nonce length.
pub const NONCE_LEN: usize = 12;
/// Byte length of one keybox stanza: an uncompressed P-256 ephemeral public
/// point (65 B), the wrap nonce (12 B), and the wrapped content key
/// (32 B + 16 B tag). Stanzas are fixed-width and anonymous.
pub const STANZA_LEN: usize = 65 + NONCE_LEN + CONTENT_KEY_LEN + AEAD_TAG_LEN;

/// AEAD algorithm id stored in the envelope's `encryption` block.
pub const AEAD_ID: &str = "aes-256-gcm";
/// Key-wrap algorithm id stored in the envelope's `encryption` block.
pub const WRAP_ID: &str = "p256-ecdh-sha256";
/// Padding profile id stored in the envelope's `encryption` block.
pub const PADDING_ID: &str = "pow2";
/// Minimum padded payload length (one 4 KiB block), so empty/tiny payloads do
/// not stand out.
pub const PADDING_MIN: u64 = 4096;

/// `KDF(label, ikm) = SHA-256("CAF-KDF-1" || 0x00 || label || 0x00 || ikm)`.
/// Sound for uniformly random, independent IKMs (content keys, ECDH shared
/// secrets); not a password KDF.
pub fn kdf(label: &str, ikm: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"CAF-KDF-1");
    h.update([0x00]);
    h.update(label.as_bytes());
    h.update([0x00]);
    h.update(ikm);
    h.finalize().into()
}

/// Derive the per-section sub-key: `KDF("section", content_key || label)` with
/// `label` one of `"private"`, `"component/<i>"`, `"payload"`.
pub fn section_key(content_key: &[u8; 32], label: &str) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(CONTENT_KEY_LEN + label.len());
    ikm.extend_from_slice(content_key);
    ikm.extend_from_slice(label.as_bytes());
    kdf("section", &ikm)
}

fn chunk_nonce(index: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..].copy_from_slice(&index.to_be_bytes());
    nonce
}

/// Encrypt chunk `index` of the section protected by `section_key`. The
/// ciphertext is `plaintext.len() + AEAD_TAG_LEN` bytes.
pub fn seal_chunk(section_key: &[u8; 32], index: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(section_key).context("aead key")?;
    cipher
        .encrypt(Nonce::from_slice(&chunk_nonce(index)), plaintext)
        .map_err(|_| anyhow::anyhow!("aead seal failed"))
}

/// Decrypt chunk `index`; the tag check authenticates the bytes.
pub fn open_chunk(section_key: &[u8; 32], index: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(section_key).context("aead key")?;
    cipher
        .decrypt(Nonce::from_slice(&chunk_nonce(index)), ciphertext)
        .map_err(|_| anyhow::anyhow!("aead open failed (wrong key or tampered bytes)"))
}

/// The padding profile: round `len` up to the next power of two, with a
/// 4 KiB floor. The payload blob's real length lives only in the encrypted
/// private manifest; publicly the blob occupies its padded length.
pub fn padded_len(len: u64) -> u64 {
    len.max(PADDING_MIN).next_power_of_two()
}

/// Convergent content key for reproducible builds: derived from the build
/// seed and the *plaintext* identity of the artifact, so identical inputs
/// yield identical ciphertext while any content change rotates the key.
pub fn convergent_content_key(seed: &[u8; 32], plaintext_identity: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(seed.len() + plaintext_identity.len());
    ikm.extend_from_slice(seed);
    ikm.extend_from_slice(plaintext_identity);
    kdf("content", &ikm)
}

/// Deterministic ephemeral secret for one recipient and content key
/// (convergent builds only). Binding the content key prevents reuse of the
/// wrapping key with nonce zero across different wrapped plaintexts.
/// Loops over a domain counter so the result always lands in the P-256 group.
pub fn convergent_ephemeral(
    seed: &[u8; 32],
    recipient: &PublicKey,
    content_key: &[u8; 32],
) -> Result<SecretKey> {
    let recipient_point = recipient.to_encoded_point(false);
    let recipient_bytes = recipient_point.as_bytes();
    for counter in 0u8..=u8::MAX {
        let mut ikm = Vec::with_capacity(seed.len() + recipient_bytes.len() + 1);
        ikm.extend_from_slice(seed);
        ikm.extend_from_slice(content_key);
        ikm.extend_from_slice(recipient_bytes);
        ikm.push(counter);
        if let Ok(secret) = SecretKey::from_slice(&kdf("keybox-eph", &ikm)) {
            return Ok(secret);
        }
    }
    bail!("no valid ephemeral scalar for recipient")
}

/// Wrap `content_key` for one recipient: ephemeral ECDH, KDF, AES-256-GCM.
/// Returns the fixed-width stanza bytes.
pub fn wrap_content_key(
    content_key: &[u8; 32],
    recipient: &PublicKey,
    ephemeral: &SecretKey,
) -> Result<[u8; STANZA_LEN]> {
    let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), recipient.as_affine());
    let wrap_key = kdf("keywrap", shared.raw_secret_bytes().as_slice());
    let wrapped = seal_chunk(&wrap_key, 0, content_key)?;
    let mut stanza = [0u8; STANZA_LEN];
    stanza[..65].copy_from_slice(ephemeral.public_key().to_encoded_point(false).as_bytes());
    stanza[65..77].copy_from_slice(&chunk_nonce(0));
    stanza[77..].copy_from_slice(&wrapped);
    Ok(stanza)
}

/// Try every stanza in a keybox section; returns the content key this
/// recipient can unwrap, or `None` when no stanza matches.
pub fn unwrap_keybox(keybox: &[u8], recipient: &SecretKey) -> Option<[u8; 32]> {
    for stanza in keybox_stanzas(keybox).ok()? {
        let Ok(ephemeral) = PublicKey::from_sec1_bytes(&stanza[..65]) else {
            continue;
        };
        let shared = diffie_hellman(recipient.to_nonzero_scalar(), ephemeral.as_affine());
        let wrap_key = kdf("keywrap", shared.raw_secret_bytes().as_slice());
        let nonce: [u8; NONCE_LEN] = stanza[65..77].try_into().ok()?;
        let cipher = Aes256Gcm::new_from_slice(&wrap_key).ok()?;
        if let Ok(key) = cipher.decrypt(Nonce::from_slice(&nonce), &stanza[77..]) {
            let key: [u8; 32] = key.try_into().ok()?;
            return Some(key);
        }
    }
    None
}

/// Serialize a keybox section: a `u32` stanza count followed by fixed-width
/// stanzas.
pub fn encode_keybox(stanzas: &[[u8; STANZA_LEN]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + stanzas.len() * STANZA_LEN);
    out.extend_from_slice(&(stanzas.len() as u32).to_le_bytes());
    for s in stanzas {
        out.extend_from_slice(s);
    }
    out
}

/// Parse a keybox section into its stanzas.
pub fn keybox_stanzas(keybox: &[u8]) -> Result<Vec<[u8; STANZA_LEN]>> {
    let count_bytes: [u8; 4] = keybox
        .get(0..4)
        .context("keybox truncated")?
        .try_into()
        .context("keybox count")?;
    let count = u32::from_le_bytes(count_bytes) as usize;
    let expected = 4usize
        .checked_add(
            count
                .checked_mul(STANZA_LEN)
                .context("keybox size overflow")?,
        )
        .context("keybox size overflow")?;
    if keybox.len() < expected {
        bail!(
            "keybox truncated: expected {expected} bytes, got {}",
            keybox.len()
        );
    }
    let mut stanzas = Vec::with_capacity(count);
    for i in 0..count {
        let at = 4 + i * STANZA_LEN;
        let mut stanza = [0u8; STANZA_LEN];
        stanza.copy_from_slice(&keybox[at..at + STANZA_LEN]);
        stanzas.push(stanza);
    }
    Ok(stanzas)
}

/// Parse a hex-encoded P-256 recipient public key (uncompressed SEC-1).
pub fn parse_recipient(hex_key: &str) -> Result<PublicKey> {
    let bytes = hex::decode(hex_key)?;
    PublicKey::from_sec1_bytes(&bytes).context("invalid P-256 recipient public key")
}

/// Parse a hex-encoded P-256 recipient secret key.
pub fn parse_recipient_secret(hex_key: &str) -> Result<SecretKey> {
    let bytes = hex::decode(hex_key)?;
    SecretKey::from_slice(&bytes).context("invalid P-256 recipient secret key")
}

/// Locate the keybox section of a sealed artifact and unwrap the content key
/// for `recipient`. Returns `Ok(None)` for unsealed artifacts or when no
/// stanza matches this recipient.
pub fn unwrap_artifact(bytes: &[u8], recipient: &SecretKey) -> Result<Option<[u8; 32]>> {
    use crate::layout;

    let header = layout::read_header(bytes)?;
    if header.flags & layout::FLAG_ENCRYPTED == 0 {
        return Ok(None);
    }
    let directory = layout::decode_directory(layout::slice(
        bytes,
        header.directory_offset,
        header.directory_len,
    )?)?;
    let keybox_entry = directory
        .iter()
        .find(|e| e.tag == layout::TAG_KEYBOX)
        .context("sealed artifact has no keybox entry")?;
    let keybox = layout::slice(bytes, keybox_entry.offset, keybox_entry.length)?;
    Ok(unwrap_keybox(keybox, recipient))
}
