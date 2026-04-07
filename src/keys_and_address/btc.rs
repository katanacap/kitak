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
use bitcoin::secp256k1::{All, Secp256k1, rand};

#[cfg(feature = "ethereum")]
use k256::elliptic_curve::sec1::ToEncodedPoint;

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

    /// Optimized batch fill using k256 Montgomery batch inversion.
    ///
    /// Accumulates 256 points in projective (Jacobian) coordinates with NO
    /// modular inversions, then does ONE batch inversion for all 256 points.
    /// Falls back to incremental secp256k1 approach when ethereum feature is disabled.
    #[cfg(feature = "ethereum")]
    fn fill_batch(batch_array: &mut [Self; BATCH_SIZE]) {
        use k256::{AffinePoint, ProjectivePoint, Scalar as K256Scalar};

        let g = ProjectivePoint::GENERATOR;

        // Use bitcoin's re-exported rand (0.8) for RNG
        let mut scalar_bytes = [0u8; 32];
        THREAD_LOCAL_RNG.with(|rng| {
            use bitcoin::secp256k1::rand::RngCore;
            rng.borrow_mut().fill_bytes(&mut scalar_bytes);
        });
        let start_scalar =
            <K256Scalar as k256::elliptic_curve::ops::Reduce<k256::U256>>::reduce_bytes(
                &scalar_bytes.into(),
            );
        let start_point = ProjectivePoint::GENERATOR * start_scalar;

        // Phase 1: Generate projective points (NO inversions)
        let mut projective = [ProjectivePoint::IDENTITY; BATCH_SIZE];
        let mut affine = [AffinePoint::IDENTITY; BATCH_SIZE];
        let mut current = start_point;
        for slot in projective.iter_mut() {
            *slot = current;
            current += g;
        }

        // Phase 2: ONE Montgomery batch inversion
        k256::elliptic_curve::group::Curve::batch_normalize(&projective, &mut affine);

        // Phase 3: Convert to Bitcoin types and compute addresses
        for (i, slot) in batch_array.iter_mut().enumerate() {
            // Compressed pubkey from k256 affine point
            let compressed = affine[i].to_encoded_point(true);
            let secp_pk = bitcoin::secp256k1::PublicKey::from_slice(compressed.as_bytes()).unwrap();
            slot.public_key = PublicKey::new(secp_pk);

            // Secret key from scalar
            let offset = K256Scalar::from(i as u64);
            let secret_scalar = start_scalar + offset;
            let sk_bytes = secret_scalar.to_bytes();
            let secp_sk = bitcoin::secp256k1::SecretKey::from_slice(&sk_bytes).unwrap();
            slot.private_key = PrivateKey::new(secp_sk, Bitcoin);

            // Reuse String buffer for address
            slot.comp_address.clear();
            let _ = write!(
                slot.comp_address,
                "{}",
                Address::p2pkh(slot.public_key, Bitcoin)
            );
        }
    }

    /// Fallback fill_batch when k256 is not available (no ethereum feature).
    #[cfg(not(feature = "ethereum"))]
    fn fill_batch(batch_array: &mut [Self; BATCH_SIZE]) {
        use bitcoin::secp256k1::Scalar;

        THREAD_LOCAL_SECP256K1.with(|secp256k1| {
            THREAD_LOCAL_RNG.with(|rng| {
                let mut rng = rng.borrow_mut();
                let (mut secret_key, mut pk) = secp256k1.generate_keypair(&mut *rng);

                for slot in batch_array.iter_mut() {
                    slot.private_key = PrivateKey::new(secret_key, Bitcoin);
                    slot.public_key = PublicKey::new(pk);

                    slot.comp_address.clear();
                    let _ = write!(
                        slot.comp_address,
                        "{}",
                        Address::p2pkh(slot.public_key, Bitcoin)
                    );

                    match secret_key.add_tweak(&Scalar::ONE) {
                        Ok(new_sk) => match pk.add_exp_tweak(secp256k1, &Scalar::ONE) {
                            Ok(new_pk) => {
                                secret_key = new_sk;
                                pk = new_pk;
                            }
                            Err(_) => {
                                let (sk, p) = secp256k1.generate_keypair(&mut *rng);
                                secret_key = sk;
                                pk = p;
                            }
                        },
                        Err(_) => {
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
