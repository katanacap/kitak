use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

#[cfg(feature = "ethereum")]
use kitak::EthereumKeyPair;
#[cfg(feature = "solana")]
use kitak::SolanaKeyPair;
use kitak::keys_and_address::BitcoinKeyPair;
use kitak::vanity_addr_generator::comp::{
    contains_case_insensitive, contains_memx, eq_prefix_case_insensitive, eq_prefix_memx,
    eq_suffix_case_insensitive, eq_suffix_memx,
};
use kitak::{BATCH_SIZE, KeyPairGenerator, VanityAddr, VanityMode};

// ---------------------------------------------------------------------------
// Bitcoin keypair generation benchmarks
// ---------------------------------------------------------------------------

fn bench_btc_generate_random(c: &mut Criterion) {
    c.bench_function("btc_generate_random", |b| {
        b.iter(|| black_box(BitcoinKeyPair::generate_random()))
    });
}

fn bench_btc_generate_batch(c: &mut Criterion) {
    c.bench_function("btc_generate_batch", |b| {
        b.iter(|| {
            let batch: [BitcoinKeyPair; BATCH_SIZE] = BitcoinKeyPair::generate_batch();
            black_box(batch);
        })
    });
}

fn bench_btc_fill_batch(c: &mut Criterion) {
    let mut batch: [BitcoinKeyPair; BATCH_SIZE] = BitcoinKeyPair::generate_batch();
    c.bench_function("btc_fill_batch", |b| {
        b.iter(|| {
            BitcoinKeyPair::fill_batch(&mut batch);
            black_box(&batch);
        })
    });
}

// ---------------------------------------------------------------------------
// Ethereum keypair generation benchmarks
// ---------------------------------------------------------------------------

#[cfg(feature = "ethereum")]
fn bench_eth_generate_random(c: &mut Criterion) {
    c.bench_function("eth_generate_random", |b| {
        b.iter(|| black_box(EthereumKeyPair::generate_random()))
    });
}

#[cfg(feature = "ethereum")]
fn bench_eth_generate_batch(c: &mut Criterion) {
    c.bench_function("eth_generate_batch", |b| {
        b.iter(|| {
            let batch: [EthereumKeyPair; BATCH_SIZE] = EthereumKeyPair::generate_batch();
            black_box(batch);
        })
    });
}

#[cfg(feature = "ethereum")]
fn bench_eth_fill_batch(c: &mut Criterion) {
    let mut batch: [EthereumKeyPair; BATCH_SIZE] = EthereumKeyPair::generate_batch();
    c.bench_function("eth_fill_batch", |b| {
        b.iter(|| {
            EthereumKeyPair::fill_batch(&mut batch);
            black_box(&batch);
        })
    });
}

// ---------------------------------------------------------------------------
// Solana keypair generation benchmarks
// ---------------------------------------------------------------------------

#[cfg(feature = "solana")]
fn bench_sol_generate_random(c: &mut Criterion) {
    c.bench_function("sol_generate_random", |b| {
        b.iter(|| black_box(SolanaKeyPair::generate_random()))
    });
}

#[cfg(feature = "solana")]
fn bench_sol_generate_batch(c: &mut Criterion) {
    c.bench_function("sol_generate_batch", |b| {
        b.iter(|| {
            let batch: [SolanaKeyPair; BATCH_SIZE] = SolanaKeyPair::generate_batch();
            black_box(batch);
        })
    });
}

#[cfg(feature = "solana")]
fn bench_sol_fill_batch(c: &mut Criterion) {
    let mut batch: [SolanaKeyPair; BATCH_SIZE] = SolanaKeyPair::generate_batch();
    c.bench_function("sol_fill_batch", |b| {
        b.iter(|| {
            SolanaKeyPair::fill_batch(&mut batch);
            black_box(&batch);
        })
    });
}

// ---------------------------------------------------------------------------
// Comparison function benchmarks
// ---------------------------------------------------------------------------

fn bench_eq_prefix_memx(c: &mut Criterion) {
    let addr = b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    let pat = b"1A1z";
    c.bench_function("eq_prefix_memx", |b| {
        b.iter(|| black_box(eq_prefix_memx(addr, pat)))
    });
}

fn bench_eq_suffix_memx(c: &mut Criterion) {
    let addr = b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    let pat = b"fNa";
    c.bench_function("eq_suffix_memx", |b| {
        b.iter(|| black_box(eq_suffix_memx(addr, pat)))
    });
}

fn bench_contains_memx(c: &mut Criterion) {
    let addr = b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    let pat = b"Gefi";
    c.bench_function("contains_memx", |b| {
        b.iter(|| black_box(contains_memx(addr, pat)))
    });
}

fn bench_eq_prefix_case_insensitive(c: &mut Criterion) {
    let addr = b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    let pat = b"1a1z";
    c.bench_function("eq_prefix_case_insensitive", |b| {
        b.iter(|| black_box(eq_prefix_case_insensitive(addr, pat)))
    });
}

fn bench_eq_suffix_case_insensitive(c: &mut Criterion) {
    let addr = b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    let pat = b"fna";
    c.bench_function("eq_suffix_case_insensitive", |b| {
        b.iter(|| black_box(eq_suffix_case_insensitive(addr, pat)))
    });
}

fn bench_contains_case_insensitive(c: &mut Criterion) {
    let addr = b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    let pat = b"gefi";
    c.bench_function("contains_case_insensitive", |b| {
        b.iter(|| black_box(contains_case_insensitive(addr, pat)))
    });
}

// ---------------------------------------------------------------------------
// End-to-end vanity generation benchmarks
// ---------------------------------------------------------------------------

fn bench_vanity_btc(c: &mut Criterion) {
    let mut group = c.benchmark_group("vanity_e2e");
    group.sample_size(10);

    group.bench_function("btc_prefix_1char", |b| {
        b.iter(|| {
            let result =
                VanityAddr::generate::<BitcoinKeyPair>("A", 4, true, true, VanityMode::Prefix);
            black_box(result.unwrap());
        })
    });

    group.bench_function("btc_prefix_2char", |b| {
        b.iter(|| {
            let result =
                VanityAddr::generate::<BitcoinKeyPair>("Ab", 4, true, true, VanityMode::Prefix);
            black_box(result.unwrap());
        })
    });

    group.bench_function("btc_anywhere_2char_ci", |b| {
        b.iter(|| {
            let result =
                VanityAddr::generate::<BitcoinKeyPair>("ab", 4, false, true, VanityMode::Anywhere);
            black_box(result.unwrap());
        })
    });

    group.finish();
}

#[cfg(feature = "ethereum")]
fn bench_vanity_eth(c: &mut Criterion) {
    use kitak::vanity_addr_generator::eth_search::find_eth_vanity_raw;

    let mut group = c.benchmark_group("vanity_e2e");
    group.sample_size(10);

    // Generic path (old)
    group.bench_function("eth_prefix_2char_generic", |b| {
        b.iter(|| {
            let result =
                VanityAddr::generate::<EthereumKeyPair>("ab", 4, false, true, VanityMode::Prefix);
            black_box(result.unwrap());
        })
    });

    // Raw byte fast path (new)
    group.bench_function("eth_prefix_2char_raw", |b| {
        b.iter(|| {
            let result = find_eth_vanity_raw("ab", "", 4);
            black_box(result.unwrap());
        })
    });

    // Generic path 3-char prefix
    group.bench_function("eth_prefix_3char_generic", |b| {
        b.iter(|| {
            let result =
                VanityAddr::generate::<EthereumKeyPair>("abc", 4, false, true, VanityMode::Prefix);
            black_box(result.unwrap());
        })
    });

    // Raw byte fast path 3-char prefix
    group.bench_function("eth_prefix_3char_raw", |b| {
        b.iter(|| {
            let result = find_eth_vanity_raw("abc", "", 4);
            black_box(result.unwrap());
        })
    });

    // Combined prefix+suffix (only available via raw path)
    group.bench_function("eth_prefix1_suffix1_raw", |b| {
        b.iter(|| {
            let result = find_eth_vanity_raw("a", "1", 4);
            black_box(result.unwrap());
        })
    });

    group.finish();
}

#[cfg(feature = "metal-gpu")]
fn bench_vanity_eth_metal(c: &mut Criterion) {
    use kitak::vanity_addr_generator::metal_search::find_eth_vanity_metal;

    let mut group = c.benchmark_group("vanity_e2e");
    group.sample_size(10);

    group.bench_function("eth_prefix_2char_metal", |b| {
        b.iter(|| {
            let result = find_eth_vanity_metal("ab", "", 1);
            black_box(result.unwrap());
        })
    });

    group.bench_function("eth_prefix_3char_metal", |b| {
        b.iter(|| {
            let result = find_eth_vanity_metal("abc", "", 1);
            black_box(result.unwrap());
        })
    });

    group.bench_function("eth_prefix1_suffix1_metal", |b| {
        b.iter(|| {
            let result = find_eth_vanity_metal("a", "1", 1);
            black_box(result.unwrap());
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

#[cfg(not(any(feature = "ethereum", feature = "solana")))]
criterion_group!(
    keygen,
    bench_btc_generate_random,
    bench_btc_generate_batch,
    bench_btc_fill_batch,
);

#[cfg(all(feature = "ethereum", not(feature = "solana")))]
criterion_group!(
    keygen,
    bench_btc_generate_random,
    bench_btc_generate_batch,
    bench_btc_fill_batch,
    bench_eth_generate_random,
    bench_eth_generate_batch,
    bench_eth_fill_batch,
);

#[cfg(all(feature = "solana", not(feature = "ethereum")))]
criterion_group!(
    keygen,
    bench_btc_generate_random,
    bench_btc_generate_batch,
    bench_btc_fill_batch,
    bench_sol_generate_random,
    bench_sol_generate_batch,
    bench_sol_fill_batch,
);

#[cfg(all(feature = "ethereum", feature = "solana"))]
criterion_group!(
    keygen,
    bench_btc_generate_random,
    bench_btc_generate_batch,
    bench_btc_fill_batch,
    bench_eth_generate_random,
    bench_eth_generate_batch,
    bench_eth_fill_batch,
    bench_sol_generate_random,
    bench_sol_generate_batch,
    bench_sol_fill_batch,
);

criterion_group!(
    comparison,
    bench_eq_prefix_memx,
    bench_eq_suffix_memx,
    bench_contains_memx,
    bench_eq_prefix_case_insensitive,
    bench_eq_suffix_case_insensitive,
    bench_contains_case_insensitive,
);

#[cfg(not(feature = "ethereum"))]
criterion_group!(vanity_e2e, bench_vanity_btc,);

#[cfg(all(feature = "ethereum", not(feature = "metal-gpu")))]
criterion_group!(vanity_e2e, bench_vanity_btc, bench_vanity_eth,);

#[cfg(feature = "metal-gpu")]
criterion_group!(
    vanity_e2e,
    bench_vanity_btc,
    bench_vanity_eth,
    bench_vanity_eth_metal,
);

criterion_main!(keygen, comparison, vanity_e2e);
