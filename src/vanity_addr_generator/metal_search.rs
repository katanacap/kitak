//! # Metal GPU-accelerated Ethereum vanity address search
//!
//! Hybrid CPU+GPU pipeline:
//! - CPU generates public keys using k256 batch normalization (fast EC operations)
//! - GPU computes Keccak256 + pattern matching in parallel (thousands of threads)
//! - Apple Silicon unified memory = zero-copy data transfer

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar, U256};

use metal::*;

use crate::error::VanityError;
use crate::keys_and_address::EthereumKeyPair;
use crate::vanity_addr_generator::eth_search::RawPattern;

/// Number of keys per GPU dispatch.
const GPU_BATCH_SIZE: usize = 4096;

/// Metal shader source compiled at build time.
const SHADER_SOURCE: &str = include_str!("../../shaders/eth_vanity.metal");

/// GPU-accelerated Ethereum vanity address search.
///
/// Uses Metal compute shaders for parallel Keccak256 hashing and pattern matching.
/// CPU handles EC key generation, GPU handles the hash-intensive work.
pub fn find_eth_vanity_metal(
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

    // Initialize Metal
    let device = Device::system_default().expect("No Metal GPU found");
    let command_queue = device.new_command_queue();

    // Compile shader
    let options = CompileOptions::new();
    options.set_language_version(MTLLanguageVersion::V2_4);
    let library = device
        .new_library_with_source(SHADER_SOURCE, &options)
        .expect("Failed to compile Metal shader");
    let function = library
        .get_function("eth_vanity_kernel", None)
        .expect("Kernel function not found");
    let pipeline = device
        .new_compute_pipeline_state_with_function(&function)
        .expect("Failed to create compute pipeline");

    let max_threads = pipeline.max_total_threads_per_threadgroup() as usize;

    // Create GPU buffers (shared memory — zero copy on Apple Silicon)
    let pubkeys_buf = device.new_buffer(
        (GPU_BATCH_SIZE * 64) as u64,
        MTLResourceOptions::StorageModeShared,
    );
    // Ensure non-empty buffers (Metal doesn't allow zero-length)
    let prefix_data: Vec<u8> = if prefix_pattern.full_bytes.is_empty() {
        vec![0u8]
    } else {
        prefix_pattern.full_bytes.clone()
    };
    let suffix_data: Vec<u8> = if suffix_pattern.full_bytes.is_empty() {
        vec![0u8]
    } else {
        suffix_pattern.full_bytes.clone()
    };
    let prefix_buf = device.new_buffer_with_data(
        prefix_data.as_ptr() as *const _,
        prefix_data.len() as u64,
        MTLResourceOptions::StorageModeShared,
    );
    let suffix_buf = device.new_buffer_with_data(
        suffix_data.as_ptr() as *const _,
        suffix_data.len() as u64,
        MTLResourceOptions::StorageModeShared,
    );

    // Params: [prefix_len, suffix_len, prefix_has_nibble, suffix_has_nibble, prefix_trailing, suffix_trailing]
    let params: [u32; 6] = [
        prefix_pattern.full_bytes.len() as u32,
        suffix_pattern.full_bytes.len() as u32,
        prefix_pattern.has_trailing_nibble as u32,
        suffix_pattern.has_trailing_nibble as u32,
        prefix_pattern.trailing_nibble as u32,
        suffix_pattern.trailing_nibble as u32,
    ];
    let params_buf = device.new_buffer_with_data(
        params.as_ptr() as *const _,
        std::mem::size_of_val(&params) as u64,
        MTLResourceOptions::StorageModeShared,
    );
    let result_buf = device.new_buffer(4, MTLResourceOptions::StorageModeShared);

    // CPU key generation uses multiple threads to fill the pubkey buffer
    let found = Arc::new(AtomicBool::new(false));

    loop {
        if found.load(Ordering::Relaxed) {
            break;
        }

        // Phase 1: CPU generates GPU_BATCH_SIZE public keys using k256 batch normalization
        let g = ProjectivePoint::GENERATOR;
        let mut rng = rand::rng();
        let mut scalar_bytes = [0u8; 32];
        rand::Rng::fill_bytes(&mut rng, &mut scalar_bytes);
        let start_scalar = <Scalar as Reduce<U256>>::reduce_bytes(
            &k256::elliptic_curve::generic_array::GenericArray::from(scalar_bytes),
        );
        let start_point = ProjectivePoint::GENERATOR * start_scalar;

        // Generate projective points in chunks and batch normalize
        let pubkeys_ptr = pubkeys_buf.contents() as *mut u8;
        let chunk_size = 256; // batch normalize in chunks of 256
        let mut batch_point = start_point;

        for chunk_start in (0..GPU_BATCH_SIZE).step_by(chunk_size) {
            let chunk_end = std::cmp::min(chunk_start + chunk_size, GPU_BATCH_SIZE);
            let n = chunk_end - chunk_start;

            let mut proj = vec![ProjectivePoint::IDENTITY; n];
            let mut affine = vec![AffinePoint::IDENTITY; n];

            let mut current = batch_point;
            for i in 0..n {
                proj[i] = current;
                current = current + g;
            }
            batch_point = current;

            k256::elliptic_curve::group::Curve::batch_normalize(&proj, &mut affine);

            for i in 0..n {
                let encoded = affine[i].to_encoded_point(false);
                let bytes = encoded.as_bytes();
                let offset = (chunk_start + i) * 64;
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr().add(1), // skip 0x04 prefix
                        pubkeys_ptr.add(offset),
                        64,
                    );
                }
            }
        }

        // Phase 2: GPU dispatch — Keccak256 + pattern check
        // Reset result to UINT_MAX (no match)
        unsafe {
            *(result_buf.contents() as *mut u32) = u32::MAX;
        }

        let command_buffer = command_queue.new_command_buffer();
        let encoder = command_buffer.new_compute_command_encoder();
        encoder.set_compute_pipeline_state(&pipeline);
        encoder.set_buffer(0, Some(&pubkeys_buf), 0);
        encoder.set_buffer(1, Some(&prefix_buf), 0);
        encoder.set_buffer(2, Some(&suffix_buf), 0);
        encoder.set_buffer(3, Some(&params_buf), 0);
        encoder.set_buffer(4, Some(&result_buf), 0);

        let grid_size = MTLSize::new(GPU_BATCH_SIZE as u64, 1, 1);
        let threadgroup_size = MTLSize::new(max_threads as u64, 1, 1);
        encoder.dispatch_threads(grid_size, threadgroup_size);
        encoder.end_encoding();
        command_buffer.commit();
        command_buffer.wait_until_completed();

        // Phase 3: Check result
        let match_idx = unsafe { *(result_buf.contents() as *const u32) };
        if match_idx != u32::MAX {
            let idx = match_idx as usize;
            let secret_scalar = start_scalar + Scalar::from(idx as u64);
            let secret_bytes = secret_scalar.to_bytes();

            let sk = secp256k1::SecretKey::from_byte_array(secret_bytes.into())
                .expect("valid secret key");
            let secp = secp256k1::Secp256k1::new();
            let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

            // Recompute the hash to get the address
            let pk_bytes_full = pk.serialize_uncompressed();
            let mut hash = [0u8; 32];
            let mut hasher = tiny_keccak::Keccak::v256();
            tiny_keccak::Hasher::update(&mut hasher, &pk_bytes_full[1..]);
            tiny_keccak::Hasher::finalize(hasher, &mut hash);

            return Ok(EthereumKeyPair::from_raw_parts(sk, pk, &hash));
        }
    }

    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys_and_address::KeyPairGenerator;

    #[test]
    fn test_metal_vanity_prefix() {
        let result = find_eth_vanity_metal("ab", "", 1);
        assert!(result.is_ok());
        let kp = result.unwrap();
        assert!(
            kp.get_address().starts_with("ab"),
            "Address {} should start with 'ab'",
            kp.get_address()
        );
    }

    #[test]
    fn test_metal_vanity_suffix() {
        let result = find_eth_vanity_metal("", "cd", 1);
        assert!(result.is_ok());
        let kp = result.unwrap();
        assert!(
            kp.get_address().ends_with("cd"),
            "Address {} should end with 'cd'",
            kp.get_address()
        );
    }

    #[test]
    fn test_metal_vanity_prefix_suffix() {
        let result = find_eth_vanity_metal("a", "1", 1);
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
    fn test_metal_vanity_correctness() {
        let result = find_eth_vanity_metal("aa", "", 1).unwrap();

        let secp = secp256k1::Secp256k1::new();
        let derived_pk = secp256k1::PublicKey::from_secret_key(&secp, result.private_key());
        assert_eq!(*result.public_key(), derived_pk);

        let pk_bytes = derived_pk.serialize_uncompressed();
        let mut hash = [0u8; 32];
        let mut hasher = tiny_keccak::Keccak::v256();
        tiny_keccak::Hasher::update(&mut hasher, &pk_bytes[1..]);
        tiny_keccak::Hasher::finalize(hasher, &mut hash);
        let derived_addr = hex::encode(&hash[12..]);
        assert_eq!(*result.get_address(), derived_addr);
    }
}
