//! # Specialized Ethereum Vanity Address Search — Maximum Performance
//!
//! A high-performance search path optimized specifically for Ethereum addresses.
//! Uses every known CPU optimization technique:
//!
//! - **Batch Z-coordinate inversion** (Montgomery's trick via `k256::ProjectivePoint::batch_normalize`)
//!   eliminates N-1 modular inversions per batch — the most expensive EC operation
//! - **Raw byte/nibble matching** — compares pattern directly against Keccak hash bytes,
//!   no hex encoding in the hot loop
//! - **tiny-keccak** — lightweight Keccak implementation, reused via reset
//! - **No allocations** in the hot loop — only the winning key gets String-encoded
//! - **Combined prefix+suffix** — checks both in a single pass

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Instant;

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand::Rng;

use crate::error::VanityError;
use crate::keys_and_address::EthereumKeyPair;

/// Batch size for the k256 projective point accumulation.
/// 256 fits in L1 cache on Apple M-series (~64KB). Larger batches cause cache thrashing.
const ETH_BATCH_SIZE: usize = 256;

/// Pre-computed raw byte pattern for matching against Keccak256 hash bytes.
#[derive(Clone, Debug)]
pub struct RawPattern {
    /// Full bytes to compare
    pub full_bytes: Vec<u8>,
    /// If the pattern has odd length, the trailing high nibble to check
    pub has_trailing_nibble: bool,
    /// The trailing nibble value (high 4 bits)
    pub trailing_nibble: u8,
}

impl RawPattern {
    /// Parse a hex pattern string into a RawPattern.
    pub fn from_hex(hex_str: &str) -> Result<Self, VanityError> {
        let hex_lower = hex_str.to_ascii_lowercase();

        if hex_lower.chars().any(|c| !c.is_ascii_hexdigit()) {
            return Err(VanityError::InputNotBase16);
        }

        let nibbles: Vec<u8> = hex_lower
            .bytes()
            .map(|b| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => unreachable!(),
            })
            .collect();

        let mut full_bytes = Vec::with_capacity(nibbles.len() / 2);
        let mut i = 0;
        while i + 1 < nibbles.len() {
            full_bytes.push((nibbles[i] << 4) | nibbles[i + 1]);
            i += 2;
        }

        let has_trailing_nibble = nibbles.len() % 2 == 1;
        let trailing_nibble = if has_trailing_nibble {
            nibbles[nibbles.len() - 1]
        } else {
            0
        };

        Ok(RawPattern {
            full_bytes,
            has_trailing_nibble,
            trailing_nibble,
        })
    }

    pub fn hex_len(&self) -> usize {
        self.full_bytes.len() * 2 + if self.has_trailing_nibble { 1 } else { 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.full_bytes.is_empty() && !self.has_trailing_nibble
    }
}

/// Check if the raw address bytes (hash[12..32]) match a prefix pattern.
#[inline(always)]
fn check_prefix(addr: &[u8], pattern: &RawPattern) -> bool {
    if pattern.is_empty() {
        return true;
    }

    let n = pattern.full_bytes.len();

    // Fast first-byte rejection: eliminates 255/256 candidates
    if n > 0 && unsafe { *addr.get_unchecked(0) } != pattern.full_bytes[0] {
        return false;
    }

    // Check remaining full bytes
    if n > 1 {
        for i in 1..n {
            if unsafe { *addr.get_unchecked(i) } != pattern.full_bytes[i] {
                return false;
            }
        }
    }

    // Check trailing nibble (odd-length pattern)
    if pattern.has_trailing_nibble
        && (unsafe { *addr.get_unchecked(n) } >> 4) != pattern.trailing_nibble
    {
        return false;
    }

    true
}

/// Check if the raw address bytes (hash[12..32]) match a suffix pattern.
#[inline(always)]
fn check_suffix(addr: &[u8], pattern: &RawPattern) -> bool {
    if pattern.is_empty() {
        return true;
    }

    let n = pattern.full_bytes.len();

    if pattern.has_trailing_nibble {
        let total_nibbles = n * 2 + 1;
        let byte_offset = 20 - total_nibbles.div_ceil(2);

        if (unsafe { *addr.get_unchecked(byte_offset) } & 0x0f) != pattern.trailing_nibble {
            return false;
        }

        for i in 0..n {
            if unsafe { *addr.get_unchecked(byte_offset + 1 + i) } != pattern.full_bytes[i] {
                return false;
            }
        }
    } else {
        let byte_offset = 20 - n;
        // Fast last-byte rejection
        if n > 0 && unsafe { *addr.get_unchecked(byte_offset + n - 1) } != pattern.full_bytes[n - 1]
        {
            return false;
        }
        for i in 0..n.saturating_sub(1) {
            if unsafe { *addr.get_unchecked(byte_offset + i) } != pattern.full_bytes[i] {
                return false;
            }
        }
    }

    true
}

/// Reconstruct secp256k1 SecretKey from batch start scalar + offset.
#[inline(always)]
fn reconstruct_sk(batch_start: Scalar, offset: usize) -> secp256k1::SecretKey {
    let secret_scalar = batch_start + Scalar::from(offset as u64);
    let secret_bytes = secret_scalar.to_bytes();
    secp256k1::SecretKey::from_byte_array(secret_bytes.into()).expect("valid secret key")
}

/// Specialized Ethereum vanity address search using batch normalization + raw byte matching.
///
/// This function uses `k256::ProjectivePoint` for batch EC operations with Montgomery
/// batch inversion, eliminating N-1 modular inversions per batch of N keys.
pub fn find_eth_vanity_raw(
    prefix: &str,
    suffix: &str,
    threads: usize,
) -> Result<EthereumKeyPair, VanityError> {
    let prefix_pattern = RawPattern::from_hex(prefix)?;
    let suffix_pattern = RawPattern::from_hex(suffix)?;

    if prefix_pattern.hex_len() + suffix_pattern.hex_len() > 40 {
        return Err(VanityError::RequestTooLong);
    }

    if prefix_pattern.is_empty() && suffix_pattern.is_empty() {
        use crate::keys_and_address::KeyPairGenerator;
        return Ok(EthereumKeyPair::generate_random());
    }

    let (sender, receiver) = mpsc::channel();
    let found_any = Arc::new(AtomicBool::new(false));
    let total_checked = Arc::new(AtomicU64::new(0));

    // Progress reporter thread
    {
        let found_any = Arc::clone(&found_any);
        let total_checked = Arc::clone(&total_checked);
        let prefix_display = prefix.to_string();
        let suffix_display = suffix.to_string();
        thread::spawn(move || {
            let start = Instant::now();
            let mut last_count = 0u64;
            let mut last_time = start;

            while !found_any.load(Ordering::Relaxed) {
                thread::sleep(std::time::Duration::from_secs(2));
                if found_any.load(Ordering::Relaxed) {
                    break;
                }

                let count = total_checked.load(Ordering::Relaxed);
                let elapsed = start.elapsed().as_secs_f64();
                let now = Instant::now();
                let interval = now.duration_since(last_time).as_secs_f64();
                let interval_keys = count - last_count;

                let speed = if interval > 0.0 {
                    interval_keys as f64 / interval
                } else {
                    0.0
                };
                let avg_speed = if elapsed > 0.0 {
                    count as f64 / elapsed
                } else {
                    0.0
                };

                let suffix_info = if suffix_display.is_empty() {
                    String::new()
                } else {
                    format!(" + suffix '{suffix_display}'")
                };

                eprint!(
                    "\r\x1b[K[{:.1}s] prefix '{}'{} | checked: {:.2}B | speed: {:.2}M keys/s (avg: {:.2}M keys/s)",
                    elapsed,
                    prefix_display,
                    suffix_info,
                    count as f64 / 1_000_000_000.0,
                    speed / 1_000_000.0,
                    avg_speed / 1_000_000.0,
                );

                last_count = count;
                last_time = now;
            }
            eprintln!(); // newline after progress
        });
    }

    for _ in 0..threads {
        let sender = sender.clone();
        let found_any = Arc::clone(&found_any);
        let total_checked = Arc::clone(&total_checked);
        let prefix_pat = prefix_pattern.clone();
        let suffix_pat = suffix_pattern.clone();

        thread::spawn(move || {
            let g = ProjectivePoint::GENERATOR;

            // Generate random starting scalar from random bytes
            let mut rng = rand::rng();
            let mut scalar_bytes = [0u8; 32];
            rng.fill_bytes(&mut scalar_bytes);
            let start_scalar =
                <Scalar as k256::elliptic_curve::ops::Reduce<k256::U256>>::reduce_bytes(
                    &scalar_bytes.into(),
                );
            let start_point = ProjectivePoint::GENERATOR * start_scalar;

            let mut batch_start_scalar = start_scalar;
            let mut batch_start_point = start_point;

            // Stack-allocated batch arrays — no heap indirection, better cache locality
            let mut projective_batch = [ProjectivePoint::IDENTITY; ETH_BATCH_SIZE];
            let mut affine_batch = [AffinePoint::IDENTITY; ETH_BATCH_SIZE];

            let batch_scalar_inc = Scalar::from(ETH_BATCH_SIZE as u64);

            loop {
                if found_any.load(Ordering::Relaxed) {
                    return;
                }

                // Phase 1: Generate ETH_BATCH_SIZE projective points (NO inversions)
                let mut current = batch_start_point;
                for slot in projective_batch.iter_mut() {
                    *slot = current;
                    current += g; // Projective add — no Z inversion!
                }

                // Phase 2: Batch normalize — ONE Montgomery inversion for entire batch
                k256::elliptic_curve::group::Curve::batch_normalize(
                    &projective_batch,
                    &mut affine_batch,
                );

                // Phase 3: Hash 2 keys at a time via NEON SIMD Keccak, then check
                let mut hash0 = [0u8; 32];
                let mut hash1 = [0u8; 32];
                let mut i = 0;
                while i + 1 < ETH_BATCH_SIZE {
                    let enc0 = affine_batch[i].to_encoded_point(false);
                    let enc1 = affine_batch[i + 1].to_encoded_point(false);

                    crate::vanity_addr_generator::keccak_simd::keccak256_x2(
                        unsafe { enc0.as_bytes().get_unchecked(1..65) },
                        unsafe { enc1.as_bytes().get_unchecked(1..65) },
                        &mut hash0,
                        &mut hash1,
                    );

                    // Check key 0
                    let addr0 = &hash0[12..32];
                    if check_prefix(addr0, &prefix_pat) && check_suffix(addr0, &suffix_pat) {
                        if !found_any.swap(true, Ordering::Relaxed) {
                            let sk = reconstruct_sk(batch_start_scalar, i);
                            let secp = secp256k1::Secp256k1::new();
                            let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
                            let _ = sender.send(EthereumKeyPair::from_raw_parts(sk, pk, &hash0));
                        }
                        return;
                    }
                    // Check key 1
                    let addr1 = &hash1[12..32];
                    if check_prefix(addr1, &prefix_pat) && check_suffix(addr1, &suffix_pat) {
                        if !found_any.swap(true, Ordering::Relaxed) {
                            let sk = reconstruct_sk(batch_start_scalar, i + 1);
                            let secp = secp256k1::Secp256k1::new();
                            let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
                            let _ = sender.send(EthereumKeyPair::from_raw_parts(sk, pk, &hash1));
                        }
                        return;
                    }
                    i += 2;
                }

                // Track progress
                total_checked.fetch_add(ETH_BATCH_SIZE as u64, Ordering::Relaxed);

                // Advance batch start
                batch_start_scalar += batch_scalar_inc;
                batch_start_point = current;
            }
        });
    }

    Ok(receiver
        .recv()
        .expect("Receiver closed before a matching address was found"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys_and_address::KeyPairGenerator;

    #[test]
    fn test_raw_pattern_even_length() {
        let pat = RawPattern::from_hex("1111").unwrap();
        assert_eq!(pat.full_bytes, vec![0x11, 0x11]);
        assert!(!pat.has_trailing_nibble);
        assert_eq!(pat.hex_len(), 4);
    }

    #[test]
    fn test_raw_pattern_odd_length() {
        let pat = RawPattern::from_hex("abc").unwrap();
        assert_eq!(pat.full_bytes, vec![0xab]);
        assert!(pat.has_trailing_nibble);
        assert_eq!(pat.trailing_nibble, 0x0c);
        assert_eq!(pat.hex_len(), 3);
    }

    #[test]
    fn test_raw_pattern_single_char() {
        let pat = RawPattern::from_hex("f").unwrap();
        assert!(pat.full_bytes.is_empty());
        assert!(pat.has_trailing_nibble);
        assert_eq!(pat.trailing_nibble, 0x0f);
    }

    #[test]
    fn test_raw_pattern_empty() {
        let pat = RawPattern::from_hex("").unwrap();
        assert!(pat.is_empty());
    }

    #[test]
    fn test_raw_pattern_invalid() {
        assert!(RawPattern::from_hex("xyz").is_err());
    }

    #[test]
    fn test_check_prefix_basic() {
        let addr = [
            0x11u8, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let pat = RawPattern::from_hex("1111").unwrap();
        assert!(check_prefix(&addr, &pat));

        let pat_bad = RawPattern::from_hex("1112").unwrap();
        assert!(!check_prefix(&addr, &pat_bad));
    }

    #[test]
    fn test_check_suffix_basic() {
        let mut addr = [0u8; 20];
        addr[18] = 0x11;
        addr[19] = 0x11;
        let pat = RawPattern::from_hex("1111").unwrap();
        assert!(check_suffix(&addr, &pat));
    }

    #[test]
    fn test_check_prefix_odd() {
        let addr = [
            0xab, 0xc7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let pat = RawPattern::from_hex("abc").unwrap();
        assert!(check_prefix(&addr, &pat));
    }

    #[test]
    fn test_find_eth_vanity_prefix_only() {
        let result = find_eth_vanity_raw("ab", "", 4);
        assert!(result.is_ok());
        let kp = result.unwrap();
        assert!(
            kp.get_address().starts_with("ab"),
            "Address {} should start with 'ab'",
            kp.get_address()
        );
    }

    #[test]
    fn test_find_eth_vanity_suffix_only() {
        let result = find_eth_vanity_raw("", "ab", 4);
        assert!(result.is_ok());
        let kp = result.unwrap();
        assert!(
            kp.get_address().ends_with("ab"),
            "Address {} should end with 'ab'",
            kp.get_address()
        );
    }

    #[test]
    fn test_find_eth_vanity_prefix_and_suffix() {
        let result = find_eth_vanity_raw("a", "1", 4);
        assert!(result.is_ok());
        let kp = result.unwrap();
        let addr = kp.get_address();
        assert!(
            addr.starts_with("a") && addr.ends_with("1"),
            "Address {} should start with 'a' and end with '1'",
            addr
        );
    }

    #[test]
    fn test_find_eth_vanity_correctness() {
        let result = find_eth_vanity_raw("aa", "", 4).unwrap();

        // Verify the keypair is cryptographically valid
        let secp = secp256k1::Secp256k1::new();
        let derived_pk = secp256k1::PublicKey::from_secret_key(&secp, result.private_key());
        assert_eq!(*result.public_key(), derived_pk);

        // Verify address derivation
        let pk_bytes = derived_pk.serialize_uncompressed();
        let mut hash = [0u8; 32];
        let mut hasher = tiny_keccak::Keccak::v256();
        tiny_keccak::Hasher::update(&mut hasher, &pk_bytes[1..]);
        tiny_keccak::Hasher::finalize(hasher, &mut hash);
        let derived_addr = hex::encode(&hash[12..]);
        assert_eq!(*result.get_address(), derived_addr);
    }

    #[test]
    fn test_find_eth_vanity_empty_returns_random() {
        let result = find_eth_vanity_raw("", "", 1);
        assert!(result.is_ok());
    }
}
