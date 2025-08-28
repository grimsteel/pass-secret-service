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
static DH_SECOND_OAKLEY_PRIME: LazyLock<BigUint> = LazyLock::new(|| {
    BigUint::from_bytes_be(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2,
        0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67,
        0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E,
        0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5,
        0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF,
        0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE,
        0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ])
});

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
        let mut shared_secret = client_pub_key.modpow(&priv_key, dh_prime).to_bytes_be();
        // pad to 128 bytes
        shared_secret.append(&mut vec![0; 128 - shared_secret.len()]);

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

    /// Returns the big endian encoded public key
    pub fn get_pub_key(&self) -> Vec<u8> {
        // 2 ^ priv_key % dh_prime
        (&*TWO)
            .modpow(&self.server_priv, &*DH_SECOND_OAKLEY_PRIME)
            .to_bytes_be()
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
