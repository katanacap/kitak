#include <metal_stdlib>
using namespace metal;

// Keccak-256 round constants
constant ulong RC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
    0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
    0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL,
};

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

inline void keccak_f(thread ulong* state) {
    for (int round = 0; round < 24; round++) {
        // theta
        ulong c0 = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
        ulong c1 = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
        ulong c2 = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
        ulong c3 = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
        ulong c4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        ulong d0 = c4 ^ ROTL64(c1, 1);
        ulong d1 = c0 ^ ROTL64(c2, 1);
        ulong d2 = c1 ^ ROTL64(c3, 1);
        ulong d3 = c2 ^ ROTL64(c4, 1);
        ulong d4 = c3 ^ ROTL64(c0, 1);

        for (int i = 0; i < 25; i += 5) {
            state[i]   ^= d0;
            state[i+1] ^= d1;
            state[i+2] ^= d2;
            state[i+3] ^= d3;
            state[i+4] ^= d4;
        }

        // rho + pi (fully unrolled with constant rotations)
        ulong tmp[25];
        tmp[0]  = state[0];
        tmp[10] = ROTL64(state[1],  1);
        tmp[20] = ROTL64(state[2],  62);
        tmp[5]  = ROTL64(state[3],  28);
        tmp[15] = ROTL64(state[4],  27);
        tmp[16] = ROTL64(state[5],  36);
        tmp[1]  = ROTL64(state[6],  44);
        tmp[11] = ROTL64(state[7],  6);
        tmp[21] = ROTL64(state[8],  55);
        tmp[6]  = ROTL64(state[9],  20);
        tmp[7]  = ROTL64(state[10], 3);
        tmp[17] = ROTL64(state[11], 10);
        tmp[2]  = ROTL64(state[12], 43);
        tmp[12] = ROTL64(state[13], 25);
        tmp[22] = ROTL64(state[14], 39);
        tmp[23] = ROTL64(state[15], 41);
        tmp[8]  = ROTL64(state[16], 45);
        tmp[18] = ROTL64(state[17], 15);
        tmp[3]  = ROTL64(state[18], 21);
        tmp[13] = ROTL64(state[19], 8);
        tmp[14] = ROTL64(state[20], 18);
        tmp[24] = ROTL64(state[21], 2);
        tmp[9]  = ROTL64(state[22], 61);
        tmp[19] = ROTL64(state[23], 56);
        tmp[4]  = ROTL64(state[24], 14);

        // chi
        for (int y = 0; y < 5; y++) {
            int b = y * 5;
            state[b]   = tmp[b]   ^ (~tmp[b+1] & tmp[b+2]);
            state[b+1] = tmp[b+1] ^ (~tmp[b+2] & tmp[b+3]);
            state[b+2] = tmp[b+2] ^ (~tmp[b+3] & tmp[b+4]);
            state[b+3] = tmp[b+3] ^ (~tmp[b+4] & tmp[b]);
            state[b+4] = tmp[b+4] ^ (~tmp[b]   & tmp[b+1]);
        }

        // iota
        state[0] ^= RC[round];
    }
}

inline void keccak256(thread const uchar* input, uint input_len, thread uchar* output) {
    ulong state[25] = {0};

    // Absorb (input_len <= 136 assumed — single block for 64-byte input)
    for (uint i = 0; i < input_len / 8; i++) {
        ulong word = 0;
        for (uint j = 0; j < 8; j++) {
            word |= ulong(input[i * 8 + j]) << (j * 8);
        }
        state[i] ^= word;
    }
    // Handle remaining bytes
    uint rem_start = (input_len / 8) * 8;
    if (rem_start < input_len) {
        ulong word = 0;
        for (uint j = 0; j < input_len - rem_start; j++) {
            word |= ulong(input[rem_start + j]) << (j * 8);
        }
        state[input_len / 8] ^= word;
    }

    // Keccak padding (0x01 ... 0x80)
    uint pad_byte_idx = input_len;
    state[pad_byte_idx / 8] ^= ulong(0x01) << ((pad_byte_idx % 8) * 8);
    // rate = 136 bytes, last byte of rate block
    state[16] ^= ulong(0x80) << 56; // byte 135 = word 16, byte 7

    keccak_f(state);

    // Squeeze first 32 bytes
    for (uint i = 0; i < 4; i++) {
        for (uint j = 0; j < 8; j++) {
            output[i * 8 + j] = uchar((state[i] >> (j * 8)) & 0xFF);
        }
    }
}

// Main kernel: hash pubkeys and check prefix/suffix pattern
kernel void eth_vanity_kernel(
    device const uchar* pubkeys       [[buffer(0)]], // N * 64 bytes (uncompressed, no 0x04)
    device const uchar* prefix_bytes  [[buffer(1)]], // prefix pattern raw bytes
    device const uchar* suffix_bytes  [[buffer(2)]], // suffix pattern raw bytes
    device const uint*  params        [[buffer(3)]], // [prefix_len, suffix_len, prefix_nibble_flag, suffix_nibble_flag, prefix_trailing, suffix_trailing]
    device atomic_uint* result_idx    [[buffer(4)]], // output: index of match (UINT_MAX = none)
    uint tid [[thread_position_in_grid]]
) {
    uint prefix_len   = params[0]; // number of full bytes in prefix
    uint suffix_len   = params[1]; // number of full bytes in suffix
    uint prefix_has_nibble = params[2]; // 1 if odd-length prefix
    uint suffix_has_nibble = params[3]; // 1 if odd-length suffix
    uint prefix_trailing   = params[4]; // trailing nibble value for prefix
    uint suffix_trailing   = params[5]; // trailing nibble value for suffix

    // Read 64-byte pubkey for this thread
    thread uchar input[64];
    uint base = tid * 64;
    for (uint i = 0; i < 64; i++) {
        input[i] = pubkeys[base + i];
    }

    // Compute Keccak-256
    thread uchar hash[32];
    keccak256(input, 64, hash);

    // Address is hash[12..32] (20 bytes)
    thread const uchar* addr = hash + 12;

    // Check prefix
    bool prefix_ok = true;
    for (uint i = 0; i < prefix_len; i++) {
        if (addr[i] != prefix_bytes[i]) {
            prefix_ok = false;
            break;
        }
    }
    if (prefix_ok && prefix_has_nibble) {
        if ((addr[prefix_len] >> 4) != prefix_trailing) {
            prefix_ok = false;
        }
    }

    if (!prefix_ok) return;

    // Check suffix
    bool suffix_ok = true;
    if (suffix_has_nibble) {
        uint byte_offset = 20 - (suffix_len * 2 + 1 + 1) / 2;
        if ((addr[byte_offset] & 0x0F) != suffix_trailing) {
            suffix_ok = false;
        }
        for (uint i = 0; i < suffix_len && suffix_ok; i++) {
            if (addr[byte_offset + 1 + i] != suffix_bytes[i]) {
                suffix_ok = false;
            }
        }
    } else {
        uint byte_offset = 20 - suffix_len;
        for (uint i = 0; i < suffix_len && suffix_ok; i++) {
            if (addr[byte_offset + i] != suffix_bytes[i]) {
                suffix_ok = false;
            }
        }
    }

    if (suffix_ok) {
        atomic_store_explicit(result_idx, tid, memory_order_relaxed);
    }
}
