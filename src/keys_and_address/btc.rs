//! # Bitcoin Key Pair and Address Generation
//!
//! This module provides functionality to generate Bitcoin key pairs and their associated compressed addresses.

use std::cell::RefCell;
use std::fmt::Write;

use crate::BATCH_SIZE;
use crate::keys_and_address::{BitcoinKeyPair, KeyPairGenerator};

use bitcoin::Address;
use bitcoin::Network::Bitcoin;
use bitcoin::key::rand::rngs::ThreadRng;
use bitcoin::key::{PrivateKey, PublicKey};
use bitcoin::secp256k1::{All, Scalar, Secp256k1, rand};

thread_local! {
    static THREAD_LOCAL_SECP256K1: Secp256k1<All> = Secp256k1::new();
    static THREAD_LOCAL_RNG: RefCell<ThreadRng> = RefCell::new(rand::thread_rng());
}

impl KeyPairGenerator for BitcoinKeyPair {
    /// Generates a random Bitcoin key pair and its compressed address.
    ///
    /// # Returns
    /// - A [BitcoinKeyPair] struct containing the private key, public key, and address.
    #[inline(always)]
    fn generate_random() -> Self {
        THREAD_LOCAL_SECP256K1.with(|secp256k1| {
            THREAD_LOCAL_RNG.with(|rng| {
                let mut rng = rng.borrow_mut();
                let (secret_key, pk) = secp256k1.generate_keypair(&mut *rng);

                let private_key = PrivateKey::new(secret_key, Bitcoin);
                let public_key = PublicKey::new(pk);

                BitcoinKeyPair {
                    private_key,
                    public_key,
                    comp_address: Address::p2pkh(public_key, Bitcoin).to_string(),
                }
            })
        })
    }

    /// Retrieves the compressed Bitcoin address as `String` reference.
    #[inline(always)]
    fn get_address(&self) -> &String {
        &self.comp_address
    }

    /// Retrieves the compressed Bitcoin address in byte slice format.
    #[inline(always)]
    fn get_address_bytes(&self) -> &[u8] {
        self.comp_address.as_bytes()
    }

    /// Optimized batch fill using incremental EC point addition.
    ///
    /// Instead of generating a fresh random keypair for each slot (which requires
    /// a full scalar multiplication `k * G` each time), this method:
    /// 1. Generates ONE random keypair via full scalar multiplication.
    /// 2. For subsequent slots, increments the secret key by 1 and adds the
    ///    generator point G to the public key — a simple EC point addition
    ///    that is ~30-60x faster than full scalar multiplication.
    /// 3. Reuses existing String buffers (clear + write) to avoid heap
    ///    allocation/deallocation per keypair.
    /// 4. Accesses thread-local secp256k1 context and RNG once per batch
    ///    instead of once per keypair.
    fn fill_batch(batch_array: &mut [Self; BATCH_SIZE]) {
        THREAD_LOCAL_SECP256K1.with(|secp256k1| {
            THREAD_LOCAL_RNG.with(|rng| {
                let mut rng = rng.borrow_mut();
                let (mut secret_key, mut pk) = secp256k1.generate_keypair(&mut *rng);

                for slot in batch_array.iter_mut() {
                    slot.private_key = PrivateKey::new(secret_key, Bitcoin);
                    slot.public_key = PublicKey::new(pk);

                    // Reuse existing String buffer
                    slot.comp_address.clear();
                    let _ = write!(
                        slot.comp_address,
                        "{}",
                        Address::p2pkh(slot.public_key, Bitcoin)
                    );

                    // Increment: secret_key += 1, public_key += G
                    // This is ~30-60x faster than a full generate_keypair()
                    match secret_key.add_tweak(&Scalar::ONE) {
                        Ok(new_sk) => {
                            // add_exp_tweak(ONE) computes P + 1*G = P + G (point addition)
                            match pk.add_exp_tweak(secp256k1, &Scalar::ONE) {
                                Ok(new_pk) => {
                                    secret_key = new_sk;
                                    pk = new_pk;
                                }
                                Err(_) => {
                                    // Point at infinity (astronomically unlikely)
                                    let (sk, p) = secp256k1.generate_keypair(&mut *rng);
                                    secret_key = sk;
                                    pk = p;
                                }
                            }
                        }
                        Err(_) => {
                            // Wrapped around curve order (astronomically unlikely)
                            let (sk, p) = secp256k1.generate_keypair(&mut *rng);
                            secret_key = sk;
                            pk = p;
                        }
                    }
                }
            })
        });
    }
}

impl BitcoinKeyPair {
    /// Retrieves the [PrivateKey] reference of the [BitcoinKeyPair].
    pub fn get_private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Retrieves the [PublicKey] reference of the [BitcoinKeyPair].
    pub fn get_public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Retrieves the compressed address reference.
    pub fn get_comp_address(&self) -> &String {
        &self.comp_address
    }

    /// Retrieves the private key in Wallet Import Format (WIF) as a `String`.
    pub fn get_wif_private_key(&self) -> String {
        self.private_key.to_wif()
    }

    /// Retrieves the compressed public key as a `String`.
    pub fn get_comp_public_key(&self) -> String {
        self.public_key.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;
    use std::collections::HashSet;

    #[test]
    fn test_generate_random() {
        let secp = Secp256k1::new();

        // Generate a random key pair and address
        let keys_and_address = BitcoinKeyPair::generate_random();

        // Check if the private key can generate the same public key
        let derived_public_key = PublicKey::from_private_key(&secp, &keys_and_address.private_key);
        assert_eq!(keys_and_address.public_key, derived_public_key);

        // Check if the derived public key generates the same address
        let derived_address = Address::p2pkh(derived_public_key, Bitcoin).to_string();
        assert_eq!(keys_and_address.comp_address, derived_address);
    }

    #[test]
    fn test_fill_batch_key_address_consistency() {
        let secp = Secp256k1::new();
        let mut batch: [BitcoinKeyPair; BATCH_SIZE] = BitcoinKeyPair::generate_batch();
        BitcoinKeyPair::fill_batch(&mut batch);

        // Every keypair in the batch must have a consistent private_key -> public_key -> address
        for (i, kp) in batch.iter().enumerate() {
            let derived_pk = PublicKey::from_private_key(&secp, &kp.private_key);
            assert_eq!(kp.public_key, derived_pk, "batch[{i}]: public key mismatch");

            let derived_addr = Address::p2pkh(derived_pk, Bitcoin).to_string();
            assert_eq!(
                kp.comp_address, derived_addr,
                "batch[{i}]: address mismatch"
            );
        }
    }

    #[test]
    fn test_fill_batch_all_unique() {
        let mut batch: [BitcoinKeyPair; BATCH_SIZE] = BitcoinKeyPair::generate_batch();
        BitcoinKeyPair::fill_batch(&mut batch);

        let addresses: HashSet<&str> = batch.iter().map(|kp| kp.comp_address.as_str()).collect();
        assert_eq!(
            addresses.len(),
            BATCH_SIZE,
            "fill_batch produced duplicate addresses"
        );
    }

    #[test]
    fn test_fill_batch_reuses_buffers() {
        let mut batch: [BitcoinKeyPair; BATCH_SIZE] = BitcoinKeyPair::generate_batch();

        // Record the String buffer pointers before refill
        let ptrs_before: Vec<*const u8> = batch.iter().map(|kp| kp.comp_address.as_ptr()).collect();

        BitcoinKeyPair::fill_batch(&mut batch);

        // After fill_batch, the buffers should be reused (same heap pointer)
        // because clear() + write! reuses capacity
        let ptrs_after: Vec<*const u8> = batch.iter().map(|kp| kp.comp_address.as_ptr()).collect();

        let reused = ptrs_before
            .iter()
            .zip(ptrs_after.iter())
            .filter(|(a, b)| a == b)
            .count();

        // Most buffers should be reused (all, unless a resize was needed)
        assert!(
            reused > BATCH_SIZE / 2,
            "Expected most String buffers to be reused, but only {reused}/{BATCH_SIZE} were"
        );
    }

    #[test]
    fn test_fill_batch_multiple_rounds() {
        let secp = Secp256k1::new();
        let mut batch: [BitcoinKeyPair; BATCH_SIZE] = BitcoinKeyPair::generate_batch();

        // Run fill_batch multiple times to ensure no accumulation of errors
        for round in 0..5 {
            BitcoinKeyPair::fill_batch(&mut batch);

            // Spot-check first, middle, and last entries
            for &idx in &[0, BATCH_SIZE / 2, BATCH_SIZE - 1] {
                let kp = &batch[idx];
                let derived_pk = PublicKey::from_private_key(&secp, &kp.private_key);
                assert_eq!(
                    kp.public_key, derived_pk,
                    "round {round}, batch[{idx}]: public key mismatch"
                );
                let derived_addr = Address::p2pkh(derived_pk, Bitcoin).to_string();
                assert_eq!(
                    kp.comp_address, derived_addr,
                    "round {round}, batch[{idx}]: address mismatch"
                );
            }
        }
    }
}
