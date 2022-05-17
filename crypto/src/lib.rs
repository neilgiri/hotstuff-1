// Copyright(C) Facebook, Inc. and its affiliates.
use ed25519_dalek as dalek;
use ed25519_dalek::ed25519;
use ed25519_dalek::Signer as _;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::{de, ser, Deserialize, Serialize};
use std::array::TryFromSliceError;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;
//use bls_eth_rust::*;

#[cfg(test)]
#[path = "tests/crypto_tests.rs"]
pub mod crypto_tests;

pub type CryptoError = ed25519::Error;
pub static KEY_TYPE: u32 = 0; // 0 represents ED25519, 1 represents BLS


/// Represents a hash digest (32 bytes).
#[derive(Hash, PartialEq, Default, Eq, Clone, Deserialize, Serialize, Ord, PartialOrd)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(&self.0))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(&self.0).get(0..16).unwrap())
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Digest {
    type Error = TryFromSliceError;
    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        Ok(Digest(item.try_into()?))
    }
}

/// This trait is implemented by all messages that can be hashed.
pub trait Hash {
    fn digest(&self) -> Digest;
}

/// Represents a public key (in bytes).
#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct PublicKey(pub [u8; 48]);

impl PublicKey {
    pub fn encode_base64(&self) -> String {
        match KEY_TYPE {
            0 => base64::encode(&self.0[..32]),
            1 => base64::encode(&self.0[..]),
            _ => String::new(),
        }
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array: [u8; 48] = match KEY_TYPE {
            0 => bytes[..32]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?,
            1 => bytes[..]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?,
            _ => [0; 48],
        };

        /*let array = bytes[..32]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;*/
        Ok(Self(array))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64().get(0..16).unwrap())
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Represents a secret key (in bytes).
pub struct SecretKey([u8; 64]);

impl SecretKey {
    pub fn encode_base64(&self) -> String {
        match KEY_TYPE {
            0 => base64::encode(&self.0[..]),
            1 => base64::encode(&self.0[..32]),
            _ => String::new(),
        }
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;

        let array: [u8; 64] = match KEY_TYPE {
            0 => bytes[..]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?,
            1 => bytes[..32]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?,
            _ => [0; 64],
        };

        Ok(Self(array))

        /*let bytes = base64::decode(s)?;
        let array = bytes[..64]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self(array))*/
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|x| *x = 0);
    }
}

pub fn generate_production_keypair() -> (PublicKey, SecretKey) {
    generate_keypair(&mut OsRng)
}

pub fn generate_keypair<R>(csprng: &mut R) -> (PublicKey, SecretKey)
where
    R: CryptoRng + RngCore,
{
    match KEY_TYPE {
        0 => {
            let keypair = dalek::Keypair::generate(csprng);
            let mut pub_buf = [0; 48];
            pub_buf[..32].copy_from_slice(&keypair.public.to_bytes());
            let public = PublicKey(pub_buf);
            let secret = SecretKey(keypair.to_bytes());
            (public, secret)
        },

        1 => {
            let mut sec: bls_eth_rust::SecretKey = unsafe { bls_eth_rust::SecretKey::uninit() };
            sec.set_by_csprng();
            let pub_key: bls_eth_rust::PublicKey = sec.get_publickey();

            let public = PublicKey(pub_key.serialize().try_into().expect("incorrect public key length"));
            let secret = SecretKey(sec.serialize().try_into().expect("incorrect secret key length"));
            (public, secret)
        },

        _ => (PublicKey([0; 48]), SecretKey([0; 64])),
    }
}

/// Represents an ed25519/BLS signature.
#[derive(Clone, Debug)]
pub struct Signature {
    part1: [u8; 48],
    part2: [u8; 48], // BLS signatures are 96 bytes
}

impl Signature {
    pub fn new(digest: &Digest, secret: &SecretKey) -> Self {
        match KEY_TYPE {
            0 => {
                let keypair = dalek::Keypair::from_bytes(&secret.0).expect("Unable to load secret key");
                let sig = keypair.sign(&digest.0).to_bytes();
                let part1 = sig[..32].try_into().expect("Unexpected signature length");
                let part2 = sig[32..64].try_into().expect("Unexpected signature length");
                Signature { part1, part2 }
            },

            1 => {
                let mut secret_key: bls_eth_rust::SecretKey = unsafe { bls_eth_rust::SecretKey::uninit() };
                secret_key.deserialize(&secret.0);
                let sig = secret_key.sign(&digest.0).serialize();
                let part1 = sig[..48].try_into().expect("incorrect length");
                let part2 = sig[48..96].try_into().expect("incorrect length");
                Signature {part1, part2}
            },

            _ => Signature {part1: [0; 48], part2: [0; 48]}
        }
    }

    fn flatten(&self) -> [u8; 64] {
        [self.part1, self.part2]
            .concat()
            .try_into()
            .expect("Unexpected signature length")
    }

    pub fn verify(&self, digest: &Digest, public_key: &PublicKey) -> Result<(), CryptoError> {
        match KEY_TYPE {
            0 => {
                let signature = ed25519::signature::Signature::from_bytes(&self.flatten())?;
                let key = dalek::PublicKey::from_bytes(&public_key.0)?;
                key.verify_strict(&digest.0, &signature)
            },

            1 => {
                let mut signature: bls_eth_rust::Signature = unsafe { bls_eth_rust::Signature::uninit() };
                signature.deserialize(&self.flatten());
                let mut key: bls_eth_rust::PublicKey = unsafe { bls_eth_rust::PublicKey::uninit() };
                key.deserialize(&public_key.0);
                match signature.verify(&key, &digest.0) {
                    true => Ok(()),
                    false => Err(dalek::SignatureError::new()),
                }
            },

            _ => Err(dalek::SignatureError::new()),
        }
    }

    pub fn verify_batch<'a, I>(digest: &Digest, votes: I) -> Result<(), CryptoError>
    where
        I: IntoIterator<Item = &'a (PublicKey, Signature)>,
    {
        let mut messages: Vec<&[u8]> = Vec::new();

        match KEY_TYPE {
            0 => {
                let mut signatures: Vec<dalek::Signature> = Vec::new();
                let mut keys: Vec<dalek::PublicKey> = Vec::new();
                for (key, sig) in votes.into_iter() {
                    messages.push(&digest.0[..]);
                    signatures.push(ed25519::signature::Signature::from_bytes(&sig.flatten())?);
                    keys.push(dalek::PublicKey::from_bytes(&key.0)?);
                }
                dalek::verify_batch(&messages[..], &signatures[..], &keys[..])
            },

            1 => {
                let mut signatures: Vec<bls_eth_rust::Signature> = Vec::new();
                let mut keys: Vec<bls_eth_rust::PublicKey> = Vec::new();
                let mut agg_signature: bls_eth_rust::Signature = unsafe { bls_eth_rust::Signature::uninit() };


                for (key, sig) in votes.into_iter() {

                    let mut signature: bls_eth_rust::Signature = unsafe { bls_eth_rust::Signature::uninit() };
                    signature.deserialize(&sig.flatten());
                    let mut key_bls: bls_eth_rust::PublicKey = unsafe { bls_eth_rust::PublicKey::uninit() };
                    key_bls.deserialize(&key.0);

                    signatures.push(signature);
                    keys.push(key_bls);
                }

                agg_signature.aggregate(signatures.as_slice());
                match agg_signature.fast_aggregate_verify(keys.as_slice(), &digest.0[..]) {
                    true => Ok(()),
                    false => Err(dalek::SignatureError::new()),
                }
            },

            _ => Err(dalek::SignatureError::new()),

        }
    }
}

/// This service holds the node's private key. It takes digests as input and returns a signature
/// over the digest (through a oneshot channel).
#[derive(Clone)]
pub struct SignatureService {
    channel: Sender<(Digest, oneshot::Sender<Signature>)>,
}

impl SignatureService {
    pub fn new(secret: SecretKey) -> Self {
        let (tx, mut rx): (Sender<(_, oneshot::Sender<_>)>, _) = channel(100);
        tokio::spawn(async move {
            while let Some((digest, sender)) = rx.recv().await {
                let signature = Signature::new(&digest, &secret);
                let _ = sender.send(signature);
            }
        });
        Self { channel: tx }
    }

    pub async fn request_signature(&mut self, digest: Digest) -> Signature {
        let (sender, receiver): (oneshot::Sender<_>, oneshot::Receiver<_>) = oneshot::channel();
        if let Err(e) = self.channel.send((digest, sender)).await {
            panic!("Failed to send message Signature Service: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive signature from Signature Service")
    }
}
