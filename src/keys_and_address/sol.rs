//! # Solana Key Pair and Address Generation
//!
//! This module provides functionality to generate Solana key pairs and their associated addresses.
//! Uses `ed25519-dalek` directly instead of the heavy `solana-sdk`.

use std::cell::RefCell;

use crate::BATCH_SIZE;
use crate::keys_and_address::{KeyPairGenerator, SolanaKeyPair};

use ed25519_dalek::SigningKey;
use rand::Rng;
use rand::rngs::ThreadRng;

thread_local! {
    static THREAD_LOCAL_RNG: RefCell<ThreadRng> = RefCell::new(rand::rng());
}

impl KeyPairGenerator for SolanaKeyPair {
    /// Generates a random Solana key pair and its address.
    ///
    /// # Returns
    /// - A [SolanaKeyPair] struct containing the key pair and address.
    #[inline(always)]
    fn generate_random() -> Self {
        THREAD_LOCAL_RNG.with(|rng| {
            let mut seed = [0u8; 32];
            rng.borrow_mut().fill_bytes(&mut seed);
            let signing_key = SigningKey::from_bytes(&seed);
            let verifying_key = signing_key.verifying_key();
            let address = bs58::encode(verifying_key.as_bytes()).into_string();

            SolanaKeyPair {
                signing_key,
                address,
            }
        })
    }

    /// Retrieves the Solana address as a `String` reference.
    #[inline(always)]
    fn get_address(&self) -> &String {
        &self.address
    }

    /// Retrieves the Solana address in byte slice format.
    #[inline(always)]
    fn get_address_bytes(&self) -> &[u8] {
        self.address.as_bytes()
    }

    /// Optimized batch fill for Solana keypairs.
    ///
    /// - Accesses thread-local RNG once per batch
    /// - Reuses String buffers via `bs58::encode().onto()` (no intermediate allocation)
    fn fill_batch(batch_array: &mut [Self; BATCH_SIZE]) {
        THREAD_LOCAL_RNG.with(|rng| {
            let mut rng = rng.borrow_mut();
            let mut seed = [0u8; 32];

            for slot in batch_array.iter_mut() {
                rng.fill_bytes(&mut seed);
                let signing_key = SigningKey::from_bytes(&seed);
                let verifying_key = signing_key.verifying_key();

                // Reuse existing String buffer — bs58::encode().onto() writes directly
                slot.address.clear();
                let _ = bs58::encode(verifying_key.as_bytes()).onto(&mut slot.address);

                slot.signing_key = signing_key;
            }
        });
    }
}

impl SolanaKeyPair {
    /// Retrieves the signing key reference.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Retrieves the private key (seed) in Base58 encoding as a `String`.
    pub fn get_private_key_as_base58(&self) -> String {
        bs58::encode(self.signing_key.as_bytes()).into_string()
    }

    /// Retrieves the public key in Base58 encoding as `String` reference.
    pub fn get_public_key_as_base58(&self) -> &String {
        &self.address
    }

    /// Retrieves the full keypair bytes (64 bytes: secret + public) for compatibility.
    pub fn get_keypair_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(self.signing_key.as_bytes());
        bytes[32..].copy_from_slice(self.signing_key.verifying_key().as_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random() {
        let key_pair = SolanaKeyPair::generate_random();

        // Ensure the address matches the public key
        let expected_address =
            bs58::encode(key_pair.signing_key.verifying_key().as_bytes()).into_string();
        assert_eq!(*key_pair.get_address(), expected_address);
    }

    #[test]
    fn test_get_private_key_as_base58() {
        let key_pair = SolanaKeyPair::generate_random();
        let private_key_base58 = bs58::encode(key_pair.signing_key.as_bytes()).into_string();
        assert_eq!(key_pair.get_private_key_as_base58(), private_key_base58);
    }

    #[test]
    fn test_get_public_key_as_base58() {
        let key_pair = SolanaKeyPair::generate_random();
        let public_key_base58 =
            bs58::encode(key_pair.signing_key.verifying_key().as_bytes()).into_string();
        assert_eq!(*key_pair.get_public_key_as_base58(), public_key_base58);
    }

    #[test]
    fn test_unique_keypairs() {
        let key_pair_1 = SolanaKeyPair::generate_random();
        let key_pair_2 = SolanaKeyPair::generate_random();

        assert_ne!(key_pair_1.get_address(), key_pair_2.get_address());
        assert_ne!(
            key_pair_1.get_private_key_as_base58(),
            key_pair_2.get_private_key_as_base58()
        );
    }
}
