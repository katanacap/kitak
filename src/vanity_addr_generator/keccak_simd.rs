//! # 2-way Parallel Keccak-256 using NEON SIMD (aarch64)
//!
//! Processes 2 Keccak-256 hashes simultaneously using ARM NEON 128-bit registers.
//! Each `uint64x2_t` holds the same state word from 2 independent Keccak states.
//!
//! All rotations use compile-time constant shift amounts (immediate operands),
//! avoiding the slow `vshlq_u64` variable-shift path.

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

#[cfg(target_arch = "aarch64")]
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Rotate left with compile-time constant shift using immediate NEON ops.
#[cfg(target_arch = "aarch64")]
macro_rules! rotl {
    ($a:expr, $left:literal, $right:literal) => {
        vorrq_u64(vshlq_n_u64::<$left>($a), vshrq_n_u64::<$right>($a))
    };
}

#[cfg(target_arch = "aarch64")]
#[allow(clippy::needless_range_loop)]
pub fn keccak256_x2(input0: &[u8], input1: &[u8], output0: &mut [u8; 32], output1: &mut [u8; 32]) {
    debug_assert_eq!(input0.len(), 64);
    debug_assert_eq!(input1.len(), 64);

    unsafe {
        let mut state = [vdupq_n_u64(0); 25];

        // Absorb 64 bytes (8 words) from each input — raw pointer reads, no bounds checks
        let p0 = input0.as_ptr() as *const u64;
        let p1 = input1.as_ptr() as *const u64;
        for i in 0..8 {
            let w0 = p0.add(i).read_unaligned().to_le();
            let w1 = p1.add(i).read_unaligned().to_le();
            *state.get_unchecked_mut(i) = vcombine_u64(vcreate_u64(w0), vcreate_u64(w1));
        }

        // Padding: byte 64 → 0x01 into word 8; byte 135 → 0x80 into word 16
        state[8] = veorq_u64(state[8], vdupq_n_u64(0x01));
        state[16] = veorq_u64(state[16], vdupq_n_u64(0x80u64 << 56));

        // 24 rounds of Keccak-f[1600]
        for round in 0..24 {
            // θ: column parity
            let c0 = veorq_u64(
                veorq_u64(state[0], state[5]),
                veorq_u64(state[10], veorq_u64(state[15], state[20])),
            );
            let c1 = veorq_u64(
                veorq_u64(state[1], state[6]),
                veorq_u64(state[11], veorq_u64(state[16], state[21])),
            );
            let c2 = veorq_u64(
                veorq_u64(state[2], state[7]),
                veorq_u64(state[12], veorq_u64(state[17], state[22])),
            );
            let c3 = veorq_u64(
                veorq_u64(state[3], state[8]),
                veorq_u64(state[13], veorq_u64(state[18], state[23])),
            );
            let c4 = veorq_u64(
                veorq_u64(state[4], state[9]),
                veorq_u64(state[14], veorq_u64(state[19], state[24])),
            );

            let d0 = veorq_u64(c4, rotl!(c1, 1, 63));
            let d1 = veorq_u64(c0, rotl!(c2, 1, 63));
            let d2 = veorq_u64(c1, rotl!(c3, 1, 63));
            let d3 = veorq_u64(c2, rotl!(c4, 1, 63));
            let d4 = veorq_u64(c3, rotl!(c0, 1, 63));

            for i in (0..25).step_by(5) {
                state[i] = veorq_u64(state[i], d0);
                state[i + 1] = veorq_u64(state[i + 1], d1);
                state[i + 2] = veorq_u64(state[i + 2], d2);
                state[i + 3] = veorq_u64(state[i + 3], d3);
                state[i + 4] = veorq_u64(state[i + 4], d4);
            }

            // ρ+π: fully unrolled with immediate shifts (no variable shifts!)
            let mut tmp = [vdupq_n_u64(0); 25];
            tmp[0] = state[0]; // rot=0
            tmp[10] = rotl!(state[1], 1, 63); // rot=1
            tmp[20] = rotl!(state[2], 62, 2); // rot=62
            tmp[5] = rotl!(state[3], 28, 36); // rot=28
            tmp[15] = rotl!(state[4], 27, 37); // rot=27
            tmp[16] = rotl!(state[5], 36, 28); // rot=36
            tmp[1] = rotl!(state[6], 44, 20); // rot=44
            tmp[11] = rotl!(state[7], 6, 58); // rot=6
            tmp[21] = rotl!(state[8], 55, 9); // rot=55
            tmp[6] = rotl!(state[9], 20, 44); // rot=20
            tmp[7] = rotl!(state[10], 3, 61); // rot=3
            tmp[17] = rotl!(state[11], 10, 54); // rot=10
            tmp[2] = rotl!(state[12], 43, 21); // rot=43
            tmp[12] = rotl!(state[13], 25, 39); // rot=25
            tmp[22] = rotl!(state[14], 39, 25); // rot=39
            tmp[23] = rotl!(state[15], 41, 23); // rot=41
            tmp[8] = rotl!(state[16], 45, 19); // rot=45
            tmp[18] = rotl!(state[17], 15, 49); // rot=15
            tmp[3] = rotl!(state[18], 21, 43); // rot=21
            tmp[13] = rotl!(state[19], 8, 56); // rot=8
            tmp[14] = rotl!(state[20], 18, 46); // rot=18
            tmp[24] = rotl!(state[21], 2, 62); // rot=2
            tmp[9] = rotl!(state[22], 61, 3); // rot=61
            tmp[19] = rotl!(state[23], 56, 8); // rot=56
            tmp[4] = rotl!(state[24], 14, 50); // rot=14

            // χ: non-linear mixing (vbicq = AND-NOT)
            for y in 0..5 {
                let b = y * 5;
                let t0 = tmp[b];
                let t1 = tmp[b + 1];
                let t2 = tmp[b + 2];
                let t3 = tmp[b + 3];
                let t4 = tmp[b + 4];
                state[b] = veorq_u64(t0, vbicq_u64(t2, t1));
                state[b + 1] = veorq_u64(t1, vbicq_u64(t3, t2));
                state[b + 2] = veorq_u64(t2, vbicq_u64(t4, t3));
                state[b + 3] = veorq_u64(t3, vbicq_u64(t0, t4));
                state[b + 4] = veorq_u64(t4, vbicq_u64(t1, t0));
            }

            // ι: round constant
            state[0] = veorq_u64(state[0], vdupq_n_u64(RC[round]));
        }

        // Squeeze: first 4 words = 32 bytes — raw pointer writes, no bounds checks
        let out0 = output0.as_mut_ptr() as *mut u64;
        let out1 = output1.as_mut_ptr() as *mut u64;
        for i in 0..4 {
            let s = *state.get_unchecked(i);
            out0.add(i).write_unaligned(vgetq_lane_u64(s, 0).to_le());
            out1.add(i).write_unaligned(vgetq_lane_u64(s, 1).to_le());
        }
    }
}

#[cfg(not(target_arch = "aarch64"))]
pub fn keccak256_x2(input0: &[u8], input1: &[u8], output0: &mut [u8; 32], output1: &mut [u8; 32]) {
    use tiny_keccak::{Hasher, Keccak};
    let mut h = Keccak::v256();
    h.update(input0);
    h.finalize(output0);
    let mut h = Keccak::v256();
    h.update(input1);
    h.finalize(output1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tiny_keccak::{Hasher, Keccak};

    #[test]
    fn test_keccak256_x2_matches_sequential() {
        let input0: Vec<u8> = (0..64).collect();
        let mut input1 = vec![0u8; 64];
        for i in 0..64 {
            input1[i] = (255 - i) as u8;
        }

        let mut ref0 = [0u8; 32];
        let mut ref1 = [0u8; 32];
        let mut h = Keccak::v256();
        h.update(&input0);
        h.finalize(&mut ref0);
        let mut h = Keccak::v256();
        h.update(&input1);
        h.finalize(&mut ref1);

        let mut out0 = [0u8; 32];
        let mut out1 = [0u8; 32];
        keccak256_x2(&input0, &input1, &mut out0, &mut out1);

        assert_eq!(out0, ref0, "Hash 0 mismatch");
        assert_eq!(out1, ref1, "Hash 1 mismatch");
    }

    #[test]
    fn test_keccak256_x2_identical_inputs() {
        let input = vec![0xABu8; 64];
        let mut out0 = [0u8; 32];
        let mut out1 = [0u8; 32];
        keccak256_x2(&input, &input, &mut out0, &mut out1);
        assert_eq!(out0, out1);

        let mut reference = [0u8; 32];
        let mut h = Keccak::v256();
        h.update(&input);
        h.finalize(&mut reference);
        assert_eq!(out0, reference);
    }

    #[test]
    fn test_keccak256_x2_zeros() {
        let input = vec![0u8; 64];
        let mut out0 = [0u8; 32];
        let mut out1 = [0u8; 32];
        keccak256_x2(&input, &input, &mut out0, &mut out1);

        let mut reference = [0u8; 32];
        let mut h = Keccak::v256();
        h.update(&input);
        h.finalize(&mut reference);
        assert_eq!(out0, reference);
    }

    #[test]
    fn test_keccak256_x2_many_random() {
        use rand::Rng;
        let mut rng = rand::rng();
        for _ in 0..100 {
            let mut in0 = [0u8; 64];
            let mut in1 = [0u8; 64];
            rng.fill_bytes(&mut in0);
            rng.fill_bytes(&mut in1);

            let mut ref0 = [0u8; 32];
            let mut ref1 = [0u8; 32];
            let mut h = Keccak::v256();
            h.update(&in0);
            h.finalize(&mut ref0);
            let mut h = Keccak::v256();
            h.update(&in1);
            h.finalize(&mut ref1);

            let mut out0 = [0u8; 32];
            let mut out1 = [0u8; 32];
            keccak256_x2(&in0, &in1, &mut out0, &mut out1);

            assert_eq!(out0, ref0, "Mismatch on random input 0");
            assert_eq!(out1, ref1, "Mismatch on random input 1");
        }
    }
}
