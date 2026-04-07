<h1 align="center">kitak</h1>

<p align="center">
  <strong>Vanity address generator for Ethereum, Bitcoin, and Solana</strong><br>
  <em>Find your perfect wallet address — fast.</em>
</p>

---

## What is this?

kitak generates crypto wallet keypairs where the address matches a pattern you choose. Want an Ethereum address that starts with `0xdead`? Or one that starts AND ends with `1111`? kitak finds the private key for it.

```
$ kitak --eth -p 1111 --suffix-pattern 1111 -t 6

[42.8s] prefix '1111' + suffix '1111' | checked: 0.27B | speed: 6.35M keys/s
FOUND IN 42.8 SECONDS!

private_key (hex): 0x4a7f...c9d2
public_key (hex):  0x04e3a1...
address:           0x11119da4e7c2b053f8a4b6d8e2f17ca930e41111
```

## Why kitak?

|  | kitak | typical vanity gen |
|--|-------|-------------------|
| ETH speed (6 threads) | **6.5M keys/sec** | ~0.3M keys/sec |
| Prefix + suffix search | single pass | regex (slow) |
| Chains | BTC + ETH + SOL | usually one |
| SIMD acceleration | NEON on Apple Silicon | none |

### How it's fast

kitak doesn't just brute-force harder — it eliminates unnecessary work:

1. **No hex encoding in the hot loop** — patterns are compared directly against raw Keccak hash bytes
2. **Batch EC point addition** — Montgomery trick: 1 modular inversion for 256 keys instead of 256
3. **Incremental keys** (P += G) — EC point addition is ~50x cheaper than full scalar multiplication
4. **2-way NEON Keccak** — hashes 2 keys per pass on ARM with compile-time constant rotations
5. **jemalloc** — optimized allocator for multi-threaded workloads

## Quick start

```bash
# Install
cargo install kitak --features ethereum

# Find an ETH address starting with "dead"
kitak --eth -p dead

# Starting with "1111" AND ending with "1111"
kitak --eth -p 1111 --suffix-pattern 1111 -t 8

# Bitcoin address with "test" anywhere (case-sensitive)
kitak -a -c test

# Solana address ending with "123"
kitak --sol -s 123
```

## Installation

```bash
cargo install kitak                       # Bitcoin only
cargo install kitak --features ethereum   # + Ethereum
cargo install kitak --features solana     # + Solana
cargo install kitak --features all        # Everything
```

Or build from source:

```bash
git clone https://github.com/katanacap/kitak.git
cd kitak
cargo build --release --features ethereum
```

## CLI reference

```
kitak [OPTIONS] <PATTERN>
```

### Chain selection

| Flag | Chain |
|------|-------|
| `--btc` | Bitcoin (default) |
| `--eth` | Ethereum |
| `--sol` | Solana |

### Pattern modes

| Flag | Description | Example |
|------|-------------|---------|
| `-p, --prefix` | Starts with (default) | `kitak --eth -p dead` |
| `-s, --suffix` | Ends with | `kitak --eth -s beef` |
| `-a, --anywhere` | Contains | `kitak -a cafe` |
| `-r, --regex` | Regex | `kitak -r "^1E.*T$"` |
| `--suffix-pattern` | Prefix AND suffix | `kitak --eth -p aa --suffix-pattern bb` |

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --threads <N>` | Worker threads | 8 |
| `-c, --case-sensitive` | Exact case matching | off |
| `-d, --disable-fast` | Allow longer patterns | off |
| `-i, --input-file <FILE>` | Batch patterns from file | — |
| `-o, --output-file <FILE>` | Save results to file | — |
| `-f, --force-flags` | CLI flags override file flags | off |

### Difficulty reference

How long to expect (single thread, Ethereum):

| Pattern | Probability | ~Time |
|---------|------------|-------|
| 2 hex chars | 1 in 256 | instant |
| 4 hex chars | 1 in 65K | <1 sec |
| 6 hex chars | 1 in 16M | ~5 sec |
| 8 hex chars (prefix+suffix) | 1 in 4.3B | ~10 min |
| 10 hex chars | 1 in 1T | ~3 days |

Scale linearly with thread count. 8 threads = 8x faster.

## Batch file

Process multiple patterns at once:

```bash
kitak -i patterns.txt -o wallets.txt
```

`patterns.txt`:
```
dead -p --eth
cafe -a -c
abc -s --sol
```

## Library usage

```toml
[dependencies]
kitak = { version = "3.0", features = ["ethereum"] }
```

### Basic

```rust
use kitak::{BitcoinKeyPair, VanityAddr, VanityMode};

let kp: BitcoinKeyPair = VanityAddr::generate(
    "abc", 8, false, true, VanityMode::Anywhere,
).unwrap();

println!("{}", kp.get_comp_address());
```

### Ethereum fast path

```rust
use kitak::vanity_addr_generator::eth_search::find_eth_vanity_raw;

// Prefix only
let kp = find_eth_vanity_raw("dead", "", 8).unwrap();

// Prefix + suffix
let kp = find_eth_vanity_raw("1111", "1111", 8).unwrap();

println!("0x{}", kp.get_address());
```

## Benchmarks

```bash
cargo bench --features ethereum
```

Apple Silicon, 4 threads:

| Benchmark | Before | After | Speedup |
|-----------|--------|-------|---------|
| ETH prefix 2-char | 5.87 ms | 246 us | **23.8x** |
| ETH prefix 3-char | 11.97 ms | 757 us | **15.8x** |
| BTC fill_batch | 3.88 ms | 1.65 ms | **2.35x** |

## Architecture

```
src/
  main.rs                       # CLI + jemalloc global allocator
  lib.rs                        # Public API exports
  keys_and_address/
    btc.rs                      # Bitcoin: incremental EC, buffer reuse
    eth.rs                      # Ethereum: incremental EC, inline hex
    sol.rs                      # Solana
  vanity_addr_generator/
    vanity_addr.rs              # Generic multi-threaded search
    eth_search.rs               # ETH fast path: raw bytes + batch inversion
    keccak_simd.rs              # 2-way NEON parallel Keccak-256
    comp.rs                     # Pattern matching (memx, Boyer-Moore)
    chain.rs                    # Chain-specific validation
    metal_search.rs             # Metal GPU (experimental)
shaders/
  eth_vanity.metal              # Metal compute shader
benches/
  benchmarks.rs                 # Criterion benchmarks
```

## Security

- Keys generated with cryptographically secure RNGs (`rand::rng()`)
- Incremental generation (P += G) is mathematically equivalent to random keys — no security reduction
- Private keys never leave your machine — output to stdout or local file only
- Import into MetaMask via "Import Account" with the hex private key

## Credits

Built by [Katana Capital](https://github.com/katanacap). Based on [btc-vanity](https://github.com/Emivvvvv/btc-vanity) by Emirhan TALA.

## License

Apache-2.0
