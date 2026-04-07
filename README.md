<h1 align="center">kitak</h1>

<p align="center">
  <strong>Vanity address generator for Ethereum · Bitcoin · Solana</strong><br>
  <em>Find your perfect wallet address — fast.</em>
</p>

---

## What is this?

kitak generates crypto wallet keypairs where the address matches a pattern you choose. Want an Ethereum address that starts with `0xdead`? Or one that starts AND ends with `1111`? kitak finds the private key for it.

```
$ kitak -p 1111 -s 1111 -t 6

  ━━━ kitak v3.1.1 ━━━

  ETH  prefix 1111 ... 1111  (6 threads)

  00:42  0x1111a8F3e29C4b...9c2E1111    270.4M  6.4M/s

  ✓ FOUND in 42.8s  (270.4M checked, 6.3M/s)

  address:      0x11119da4e7c2b053f8a4b6d8e2f17ca930e41111
  private_key:  0x4a7f...c9d2
```

## Why kitak?

|  | kitak | typical vanity gen |
|--|-------|-------------------|
| ETH speed (6 threads) | **6.5M keys/sec** | ~0.3M keys/sec |
| Prefix + suffix search | `-p dead -s beef` | regex only (slow) |
| Chains | ETH + BTC + SOL | usually one |
| SIMD acceleration | NEON on Apple Silicon | none |

### How it's fast

1. **No hex encoding in the hot loop** — patterns compared directly against raw Keccak hash bytes
2. **Montgomery batch inversion** — 1 modular inversion for 256 keys instead of 256 (ETH and BTC)
3. **Incremental keys** (P += G) — EC point addition is ~50x cheaper than full scalar multiplication
4. **2-way NEON Keccak** — hashes 2 keys per pass on ARM with compile-time constant rotations
5. **jemalloc** — optimized allocator for multi-threaded workloads

## Quick start

```bash
# Install (all chains included by default)
cargo install kitak

# ETH prefix
kitak -p dead

# ETH prefix + suffix
kitak -p 1111 -s 1111 -t 8

# ETH suffix only
kitak -s beef

# BTC containing 'test'
kitak --btc -a test

# SOL suffix
kitak --sol -s abc
```

## Installation

### Homebrew (macOS)

```bash
brew tap katanacap/tap
brew install kitak
```

### Cargo

```bash
cargo install kitak
```

### From source

```bash
git clone https://github.com/katanacap/kitak.git
cd kitak
cargo build --release
```

All chains (Bitcoin, Ethereum, Solana) are included by default.

## CLI reference

```
kitak [OPTIONS] <PATTERN>
```

### Chain selection

| Flag | Chain |
|------|-------|
| `--eth` | Ethereum (default) |
| `--btc` | Bitcoin |
| `--sol` | Solana |

### Pattern modes

| Flag | Description | Example |
|------|-------------|---------|
| `-p, --prefix` | Starts with (default) | `kitak -p dead` |
| `-s, --suffix` | Suffix pattern | `kitak -s beef` |
| `-p` + `-s` | Prefix AND suffix | `kitak -p aa -s bb` |
| `-a, --anywhere` | Contains | `kitak --btc -a cafe` |
| `-r, --regex` | Regex | `kitak --btc -r "^1E.*T$"` |

`-s` is smart: alone it's suffix-only mode, with `-p` it searches both simultaneously.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --threads <N>` | Worker threads | 8 |
| `-c, --case-sensitive` | Exact case matching | off |
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
cafe -a --btc
abc -s --sol
```

## Library usage

```toml
[dependencies]
kitak = "3.1"  # all chains included by default
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
cargo bench
```

Apple Silicon, `fill_batch` (256 keys per batch):

| Chain | Naive | Optimized | Per-key | Speedup |
|-------|-------|-----------|---------|---------|
| **ETH** | 2.27 ms | 0.99 ms | 3.9 us | **2.3x** |
| **BTC** | 2.79 ms | 1.03 ms | 4.0 us | **2.7x** |
| **SOL** | 2.45 ms | 2.47 ms | 9.6 us | 1.0x |

ETH fast path (raw bytes + SIMD) vs generic:

| Benchmark | Generic | Fast path | Speedup |
|-----------|---------|-----------|---------|
| ETH prefix 2-char | 5.87 ms | 246 us | **23.8x** |
| ETH prefix 3-char | 11.97 ms | 757 us | **15.8x** |

## Architecture

```
src/
  main.rs                       # CLI + jemalloc global allocator
  lib.rs                        # Public API exports
  keys_and_address/
    btc.rs                      # Bitcoin: k256 batch normalization
    eth.rs                      # Ethereum: incremental EC, inline hex
    sol.rs                      # Solana: ed25519-dalek (lightweight)
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

- Keys generated with cryptographically secure RNGs
- Incremental generation (P += G) is mathematically equivalent to random keys
- Private keys never leave your machine — output to stdout or local file only
- Import into MetaMask via "Import Account" with the hex private key

## Credits

Built by [Katana Capital](https://github.com/katanacap). Based on [btc-vanity](https://github.com/Emivvvvv/btc-vanity) by Emirhan TALA.

## License

Apache-2.0
