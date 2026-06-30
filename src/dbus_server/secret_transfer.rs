use std::sync::LazyLock;

use aes::{
    cipher::{
        block_padding::Pkcs7, consts::U16, generic_array::GenericArray, BlockDecryptMut,
        BlockEncryptMut, KeyIvInit,
    },
    Aes128,
};
use hkdf::Hkdf;
use num::{bigint::RandBigInt, BigUint, FromPrimitive};
use rand::{prelude::*, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zbus::zvariant::{OwnedObjectPath, Type};

/// base for DH
static TWO: LazyLock<BigUint> = LazyLock::new(|| BigUint::from_u8(2).unwrap());

/// Second Oakley Prime - https://www.ietf.org/rfc/rfc2409.txt 6.2
const DH_SECOND_OAKLEY_PRIME_BE: [u8; 128] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// Big-endian byte length of the DH prime. Derived from the prime itself so the
/// two can never drift apart if the prime is ever swapped.
const DH_PRIME_BYTES: usize = DH_SECOND_OAKLEY_PRIME_BE.len();

static DH_SECOND_OAKLEY_PRIME: LazyLock<BigUint> =
    LazyLock::new(|| BigUint::from_bytes_be(&DH_SECOND_OAKLEY_PRIME_BE));

/// Big-endian byte encoding of `n`, left-padded with zeros to exactly `len` bytes.
/// `BigUint::to_bytes_be` strips leading zeros, so the raw output can be shorter
/// than the prime. DH shared secrets and public keys must be fed to peers at the
/// full prime length; zeros belong at the most-significant end. Panics if `n`
/// doesn't fit in `len` bytes — a crypto precondition we want to surface in
/// release builds, not only debug.
fn to_bytes_be_padded(n: &BigUint, len: usize) -> Vec<u8> {
    let bytes = n.to_bytes_be();
    assert!(bytes.len() <= len, "value wider than target length");
    let mut out = vec![0u8; len];
    out[len - bytes.len()..].copy_from_slice(&bytes);
    out
}

use crate::error::{Error, Result};

/// An encrypted secret
#[derive(Type, Debug, Deserialize, Serialize, PartialEq)]
pub struct Secret {
    pub session: OwnedObjectPath,
    pub parameters: Vec<u8>,
    pub value: Vec<u8>,
    pub content_type: String,
}

/// Common trait for all methods for transferring secrets
pub trait SessionTransfer {
    fn decrypt(&self, secret: Secret) -> Result<Vec<u8>>;
    fn encrypt(&self, value: Vec<u8>, session: OwnedObjectPath) -> Result<Secret>;
}

/// Plain-text transfer
pub struct PlainTextTransfer;
impl SessionTransfer for PlainTextTransfer {
    // passthrough

    fn decrypt(&self, secret: Secret) -> Result<Vec<u8>> {
        Ok(secret.value)
    }

    fn encrypt(&self, value: Vec<u8>, session: OwnedObjectPath) -> Result<Secret> {
        Ok(Secret {
            session,
            parameters: Vec::new(),
            value,
            content_type: "text/plain".to_string(),
        })
    }
}

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;

pub struct DhIetf1024Sha256Aes128CbcPkcs7Transfer {
    // our private key
    server_priv: BigUint,
    // shared aes key
    shared_key: GenericArray<u8, U16>,
}

impl DhIetf1024Sha256Aes128CbcPkcs7Transfer {
    pub fn new(client_pub_key: &[u8]) -> Result<Self> {
        // generate a private key
        // 128 byte privkey
        let priv_key = OsRng.gen_biguint(128 * 8);

        let dh_prime = &*DH_SECOND_OAKLEY_PRIME;

        let client_pub_key = BigUint::from_bytes_be(client_pub_key);

        // client pubkey ^ priv key % dh prime
        let shared_secret =
            to_bytes_be_padded(&client_pub_key.modpow(&priv_key, dh_prime), DH_PRIME_BYTES);

        // no salt
        let hk = Hkdf::<Sha256>::new(None, &shared_secret[..]);
        let mut okm = [0; 16];
        // empty info
        hk.expand(&[], &mut okm)
            .map_err(|_| Error::EncryptionError("Invalid length"))?;

        let aes_key = GenericArray::clone_from_slice(&okm);

        Ok(Self {
            server_priv: priv_key,
            shared_key: aes_key,
        })
    }

    /// Returns the big endian encoded public key, zero-padded to the prime length.
    pub fn get_pub_key(&self) -> Vec<u8> {
        // 2 ^ priv_key % dh_prime
        to_bytes_be_padded(
            &TWO.modpow(&self.server_priv, &DH_SECOND_OAKLEY_PRIME),
            DH_PRIME_BYTES,
        )
    }
}

impl SessionTransfer for DhIetf1024Sha256Aes128CbcPkcs7Transfer {
    fn decrypt(&self, secret: Secret) -> Result<Vec<u8>> {
        // client provides the IV
        let iv = GenericArray::from_slice(&secret.parameters[..]);

        Ok(Aes128CbcDec::new(&self.shared_key, &iv)
            .decrypt_padded_vec_mut::<Pkcs7>(&secret.value[..])
            .map_err(|_| Error::EncryptionError("AES Unpad Error"))?)
    }

    fn encrypt(&self, value: Vec<u8>, session: OwnedObjectPath) -> Result<Secret> {
        // we generate the IV
        let mut iv = [0; 16];
        OsRng.fill_bytes(&mut iv);

        let encrypted_secret = Aes128CbcEnc::new(&self.shared_key, GenericArray::from_slice(&iv))
            .encrypt_padded_vec_mut::<Pkcs7>(&value[..]);

        Ok(Secret {
            session,
            // send IV to client
            parameters: iv.to_vec(),
            value: encrypted_secret,
            content_type: "text/plain".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_preserves_full_width_value() {
        let n = BigUint::from_bytes_be(&[0xAAu8; DH_PRIME_BYTES]);
        assert_eq!(
            to_bytes_be_padded(&n, DH_PRIME_BYTES),
            vec![0xAA; DH_PRIME_BYTES]
        );
    }

    #[test]
    fn pad_left_pads_short_value() {
        // BigUint value 1 serializes to a single byte; it must end up in the
        // least-significant (last) byte, with zeros filling the top.
        let one = BigUint::from(1u8);
        let padded = to_bytes_be_padded(&one, DH_PRIME_BYTES);
        assert_eq!(padded.len(), DH_PRIME_BYTES);
        assert!(padded[..DH_PRIME_BYTES - 1].iter().all(|b| *b == 0));
        assert_eq!(padded[DH_PRIME_BYTES - 1], 1);
    }

    #[test]
    fn pad_handles_zero_high_byte() {
        // 1024-bit value with the top byte zero: to_bytes_be returns 127 bytes.
        let mut raw = [0u8; DH_PRIME_BYTES];
        raw[0] = 0x00;
        raw[1] = 0x7F;
        for b in raw.iter_mut().skip(2) {
            *b = 0x42;
        }
        let n = BigUint::from_bytes_be(&raw);
        assert_eq!(n.to_bytes_be().len(), DH_PRIME_BYTES - 1);
        let padded = to_bytes_be_padded(&n, DH_PRIME_BYTES);
        assert_eq!(padded.len(), DH_PRIME_BYTES);
        assert_eq!(padded, raw);
    }
}
