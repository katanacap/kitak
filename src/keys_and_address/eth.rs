//! # Ethereum Key Pair and Address Generation
//!
//! This module provides functionality to generate Ethereum key pairs and their associated addresses.

use std::cell::RefCell;

use crate::BATCH_SIZE;
use crate::keys_and_address::{EthereumKeyPair, KeyPairGenerator};

use hex::encode;
use rand::{Rng, rngs::ThreadRng};
use secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

thread_local! {
    static THREAD_LOCAL_SECP256K1: Secp256k1<All> = Secp256k1::new();
    static THREAD_LOCAL_RNG: RefCell<ThreadRng> = RefCell::new(rand::rng());
}

/// Lookup table for fast hex encoding
const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";

impl KeyPairGenerator for EthereumKeyPair {
    /// Generates a random Ethereum key pair and its address.
    ///
    /// # Returns
    /// - An [EthereumKeyPair] struct containing the private key, public key, and address.
    #[inline(always)]
    fn generate_random() -> Self {
        THREAD_LOCAL_SECP256K1.with(|secp256k1| {
            THREAD_LOCAL_RNG.with(|rng| {
                let mut secret_bytes = [0u8; 32];
                rng.borrow_mut().fill_bytes(&mut secret_bytes);

                let secret_key =
                    SecretKey::from_byte_array(secret_bytes).expect("32 bytes, within curve order");
                let public_key = PublicKey::from_secret_key(secp256k1, &secret_key);

                // Derive the Ethereum address (Keccak256 hash of the public key, last 20 bytes)
                let public_key_bytes = public_key.serialize_uncompressed();
                let public_key_hash = Keccak256::digest(&public_key_bytes[1..]); // Skip the 0x04 prefix
                let address = encode(&public_key_hash[12..]); // Use the last 20 bytes

                EthereumKeyPair {
                    private_key: secret_key,
                    public_key,
                    address,
                }
            })
        })
    }

    /// Retrieves the Ethereum address as `String` reference.
    #[inline(always)]
    fn get_address(&self) -> &String {
        &self.address
    }

    /// Retrieves the Ethereum address in byte slice format.
    #[inline(always)]
    fn get_address_bytes(&self) -> &[u8] {
        self.address.as_bytes()
    }

    /// Optimized batch fill using incremental EC point addition + buffer reuse.
    ///
    /// Same strategy as Bitcoin: one full scalar multiplication per batch,
    /// then increment via EC point addition for subsequent keys.
    /// Also reuses String buffers and does inline hex encoding.
    fn fill_batch(batch_array: &mut [Self; BATCH_SIZE]) {
        THREAD_LOCAL_SECP256K1.with(|secp256k1| {
            THREAD_LOCAL_RNG.with(|rng| {
                let mut rng = rng.borrow_mut();
                let mut secret_bytes = [0u8; 32];
                rng.fill_bytes(&mut secret_bytes);

                let mut secret_key =
                    SecretKey::from_byte_array(secret_bytes).expect("32 bytes, within curve order");
                let mut public_key = PublicKey::from_secret_key(secp256k1, &secret_key);

                for slot in batch_array.iter_mut() {
                    let pk_bytes = public_key.serialize_uncompressed();
                    let pk_hash = Keccak256::digest(&pk_bytes[1..]);

                    slot.private_key = secret_key;
                    slot.public_key = public_key;

                    // Inline hex encoding into reused String buffer
                    slot.address.clear();
                    for &b in &pk_hash[12..] {
                        slot.address
                            .push(HEX_CHARS_LOWER[(b >> 4) as usize] as char);
                        slot.address
                            .push(HEX_CHARS_LOWER[(b & 0xf) as usize] as char);
                    }

                    // Increment: secret_key += 1, public_key += G
                    match secret_key.add_tweak(&Scalar::ONE) {
                        Ok(new_sk) => match public_key.add_exp_tweak(secp256k1, &Scalar::ONE) {
                            Ok(new_pk) => {
                                secret_key = new_sk;
                                public_key = new_pk;
                            }
                            Err(_) => {
                                rng.fill_bytes(&mut secret_bytes);
                                secret_key = SecretKey::from_byte_array(secret_bytes)
                                    .expect("32 bytes, within curve order");
                                public_key = PublicKey::from_secret_key(secp256k1, &secret_key);
                            }
                        },
                        Err(_) => {
                            rng.fill_bytes(&mut secret_bytes);
                            secret_key = SecretKey::from_byte_array(secret_bytes)
                                .expect("32 bytes, within curve order");
                            public_key = PublicKey::from_secret_key(secp256k1, &secret_key);
                        }
                    }
                }
            })
        });
    }
}

impl EthereumKeyPair {
    /// Constructs an EthereumKeyPair from raw components.
    /// Used by the specialized fast search path to build the keypair
    /// only for the winning match (avoids String allocation in the hot loop).
    pub(crate) fn from_raw_parts(
        private_key: SecretKey,
        public_key: PublicKey,
        search_hash: &[u8],
    ) -> Self {
        // Recompute address from secp256k1 public key to guarantee consistency
        let pk_bytes = public_key.serialize_uncompressed();
        let hash = Keccak256::digest(&pk_bytes[1..]);
        debug_assert_eq!(
            &hash[12..],
            &search_hash[12..],
            "SIMD keccak hash mismatch — search found wrong key"
        );
        let address = encode(&hash[12..]);
        EthereumKeyPair {
            private_key,
            public_key,
            address,
        }
    }

    /// Retrieves the private key as a hex-encoded str
    pub fn get_private_key_as_hex(&self) -> String {
        encode(self.private_key.secret_bytes())
    }

    /// Retrieves the private key as a hex-encoded `String` with the `0x` prefix.
    pub fn get_private_key_as_hex_with_prefix(&self) -> String {
        format!("0x{}", encode(self.private_key.secret_bytes()))
    }

    /// Retrieves the public key as a hex-encoded `String`.
    pub fn get_public_key_as_hex(&self) -> String {
        encode(self.public_key.serialize_uncompressed())
    }

    /// Retrieves the Ethereum address as a hex-encoded `String` with the `0x` prefix.
    pub fn get_address_with_prefix(&self) -> String {
        format!("0x{}", self.address)
    }

    /// Returns the private key reference as `secp256k1::SecretKey`.
    pub fn private_key(&self) -> &SecretKey {
        &self.private_key
    }

    /// Returns the public key reference as `secp256k1::PublicKey`.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;
    use sha3::{Digest, Keccak256};

    #[test]
    fn test_generate_random() {
        let secp = Secp256k1::new();

        // Generate a random Ethereum key pair and address
        let key_pair = EthereumKeyPair::generate_random();

        // Derive public key from private key
        let derived_public_key = PublicKey::from_secret_key(&secp, &key_pair.private_key);
        assert_eq!(key_pair.public_key, derived_public_key);

        // Derive Ethereum address from public key
        let public_key_bytes = derived_public_key.serialize_uncompressed();
        let public_key_hash = Keccak256::digest(&public_key_bytes[1..]); // Skip the 0x04 prefix
        let derived_address = encode(&public_key_hash[12..]); // Use the last 20 bytes

        assert_eq!(key_pair.address, derived_address);
    }

    #[test]
    fn test_get_public_key_as_hex() {
        let key_pair = EthereumKeyPair::generate_random();
        let public_key_hex = key_pair.get_public_key_as_hex();

        // Verify the public key hex matches the serialized public key
        let expected_hex = encode(key_pair.public_key.serialize_uncompressed());
        assert_eq!(public_key_hex, expected_hex);
    }
}
