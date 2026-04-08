#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(feature = "ethereum")]
use kitak::EthereumKeyPair;
#[cfg(any(feature = "ethereum", feature = "solana"))]
use kitak::KeyPairGenerator;
#[cfg(feature = "solana")]
use kitak::SolanaKeyPair;
use kitak::cli::cli;
use kitak::error::VanityError;
use kitak::file::{parse_input_file, write_output_file};
use kitak::flags::{PatternsSource, VanityFlags, parse_cli};
use kitak::keys_and_address::BitcoinKeyPair;
use kitak::vanity_addr_generator::chain::Chain;
use kitak::vanity_addr_generator::vanity_addr::{VanityAddr, VanityMode};

use std::path::Path;
use std::process;

/// Generates and formats a vanity address depending on the chain.
/// Returns a `Result<String, String>` where the `Ok(String)` is the final formatted output.
fn generate_vanity_address(pattern: &str, vanity_flags: &VanityFlags) -> Result<String, String> {
    let chain = vanity_flags.chain.unwrap_or(Chain::Ethereum);

    let suffix_pat = vanity_flags.suffix_pattern.as_deref().unwrap_or("");

    let out = match chain {
        Chain::Bitcoin => {
            let result: Result<BitcoinKeyPair, VanityError> =
                match vanity_flags.vanity_mode.unwrap_or(VanityMode::Prefix) {
                    VanityMode::Regex => {
                        VanityAddr::generate_regex::<BitcoinKeyPair>(pattern, vanity_flags.threads)
                    }
                    VanityMode::Prefix if !suffix_pat.is_empty() => {
                        VanityAddr::generate_prefix_suffix::<BitcoinKeyPair>(
                            pattern,
                            suffix_pat,
                            vanity_flags.threads,
                            vanity_flags.is_case_sensitive,
                            !vanity_flags.disable_fast_mode,
                        )
                    }
                    _ => VanityAddr::generate::<BitcoinKeyPair>(
                        pattern,
                        vanity_flags.threads,
                        vanity_flags.is_case_sensitive,
                        !vanity_flags.disable_fast_mode,
                        vanity_flags.vanity_mode.unwrap_or(VanityMode::Prefix),
                    ),
                };

            match result {
                Ok(res) => {
                    let s = format!(
                        "  \x1b[1maddress:\x1b[0m      \x1b[32m{}\x1b[0m\n\
                         \x1b[1m  private_key:\x1b[0m  {}\n\
                         \x1b[1m  public_key:\x1b[0m   {}\n",
                        res.get_comp_address(),
                        res.get_wif_private_key(),
                        res.get_comp_public_key(),
                    );
                    Ok(s)
                }
                Err(e) => Err(e.to_string()),
            }
        }

        #[cfg(feature = "ethereum")]
        Chain::Ethereum => {
            let mode = vanity_flags.vanity_mode.unwrap_or(VanityMode::Prefix);

            let result: Result<EthereumKeyPair, VanityError> = match mode {
                VanityMode::Regex => {
                    VanityAddr::generate_regex::<EthereumKeyPair>(pattern, vanity_flags.threads)
                }
                VanityMode::Prefix => {
                    // Prefix (+ optional suffix): fast path
                    kitak::vanity_addr_generator::eth_search::find_eth_vanity_raw(
                        pattern,
                        suffix_pat,
                        vanity_flags.threads,
                    )
                }
                VanityMode::Suffix => {
                    // Suffix only: -s without -p. Pattern comes from suffix_pattern.
                    let suffix_val = if suffix_pat.is_empty() {
                        pattern
                    } else {
                        suffix_pat
                    };
                    kitak::vanity_addr_generator::eth_search::find_eth_vanity_raw(
                        "",
                        suffix_val,
                        vanity_flags.threads,
                    )
                }
                _ => VanityAddr::generate::<EthereumKeyPair>(
                    pattern,
                    vanity_flags.threads,
                    vanity_flags.is_case_sensitive,
                    !vanity_flags.disable_fast_mode,
                    mode,
                ),
            };

            // 2) Format on success
            match result {
                Ok(res) => {
                    let private_key_hex = res.get_private_key_as_hex();
                    let pub_key_hex = res.get_public_key_as_hex();
                    let address = res.get_address();

                    let s = format!(
                        "  \x1b[1maddress:\x1b[0m      \x1b[32m0x{address}\x1b[0m\n\
                         \x1b[1m  private_key:\x1b[0m  0x{private_key_hex}\n\
                         \x1b[1m  public_key:\x1b[0m   0x{pub_key_hex}\n"
                    );
                    Ok(s)
                }
                Err(e) => Err(e.to_string()),
            }
        }

        #[cfg(feature = "solana")]
        Chain::Solana => {
            // 1) Generate the Solana vanity
            let result: Result<SolanaKeyPair, VanityError> =
                match vanity_flags.vanity_mode.unwrap_or(VanityMode::Prefix) {
                    VanityMode::Regex => {
                        VanityAddr::generate_regex::<SolanaKeyPair>(pattern, vanity_flags.threads)
                    }
                    VanityMode::Prefix if !suffix_pat.is_empty() => {
                        VanityAddr::generate_prefix_suffix::<SolanaKeyPair>(
                            pattern,
                            suffix_pat,
                            vanity_flags.threads,
                            vanity_flags.is_case_sensitive,
                            !vanity_flags.disable_fast_mode,
                        )
                    }
                    _ => VanityAddr::generate::<SolanaKeyPair>(
                        pattern,
                        vanity_flags.threads,
                        vanity_flags.is_case_sensitive,
                        !vanity_flags.disable_fast_mode,
                        vanity_flags.vanity_mode.unwrap_or(VanityMode::Prefix),
                    ),
                };

            // 2) Format on success
            match result {
                Ok(res) => {
                    let private_key_b58 = res.get_private_key_as_base58();
                    let address = res.get_address();
                    let s = format!(
                        "  \x1b[1maddress:\x1b[0m      \x1b[32m{address}\x1b[0m\n\
                         \x1b[1m  private_key:\x1b[0m  {private_key_b58}\n"
                    );
                    Ok(s)
                }
                Err(e) => Err(e.to_string()),
            }
        }
        // This arm handles missing features.
        #[cfg(not(feature = "ethereum"))]
        Chain::Ethereum => Err(VanityError::MissingFeatureEthereum.to_string()),
        #[cfg(not(feature = "solana"))]
        Chain::Solana => Err(VanityError::MissingFeatureSolana.to_string()),
    };

    match out {
        Ok(s) => Ok(s),
        Err(e) => Err(format!("\x1b[31m✗\x1b[0m Skipping: {e}\n")),
    }
}

/// A single function to handle generating and printing/writing a vanity address
/// for a given `pattern` + final `VanityFlags`.
fn handle_item(pattern: &str, flags: &VanityFlags) {
    let vanity_mode = flags.vanity_mode.unwrap_or(VanityMode::Prefix);

    // For suffix-only mode with -s, the actual pattern is in suffix_pattern
    let effective_pattern = if vanity_mode == VanityMode::Suffix {
        if !pattern.is_empty() && flags.suffix_pattern.is_some() {
            // Ambiguous: both positional and -s provided without -p
            // Treat positional as prefix → combined mode
            // (handled below by overriding vanity_mode)
            pattern
        } else if pattern.is_empty() {
            flags.suffix_pattern.as_deref().unwrap_or("")
        } else {
            pattern
        }
    } else {
        pattern
    };

    // If suffix-only mode but positional arg also provided, switch to prefix+suffix
    let vanity_mode = if vanity_mode == VanityMode::Suffix
        && !pattern.is_empty()
        && flags.suffix_pattern.is_some()
    {
        VanityMode::Prefix
    } else {
        vanity_mode
    };

    let mode_str = match vanity_mode {
        VanityMode::Prefix => "prefix",
        VanityMode::Suffix => "suffix",
        VanityMode::Anywhere => "contains",
        VanityMode::Regex => "regex",
    };

    let chain = flags.chain.unwrap_or(Chain::Ethereum);
    let chain_str = match chain {
        Chain::Bitcoin => "BTC",
        Chain::Ethereum => "ETH",
        Chain::Solana => "SOL",
    };

    // Compact pattern display
    let suffix_str = flags.suffix_pattern.as_deref().unwrap_or("");
    let pattern_display = if !suffix_str.is_empty() && vanity_mode == VanityMode::Prefix {
        format!("{} ... {}", effective_pattern, suffix_str)
    } else {
        effective_pattern.to_string()
    };

    eprintln!(
        "\n  \x1b[1;36m━━━ kitak v{} ━━━\x1b[0m\n",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!(
        "  \x1b[90m{}\x1b[0m  \x1b[1m{}\x1b[0m \x1b[32m{}\x1b[0m  \x1b[90m({} threads)\x1b[0m",
        chain_str, mode_str, pattern_display, flags.threads
    );

    let buffer1 = format!("{mode_str}: '{effective_pattern}'\n");

    let result = generate_vanity_address(effective_pattern, flags);

    // 5) Format result or error, then handle output
    match result {
        Ok(buffer2) => {
            // If the user gave an output_file_name, write to that file.
            // Otherwise, print to stdout.
            if let Some(ref file_path) = flags.output_file_name {
                // example from your existing code:
                if let Err(e) =
                    write_output_file(Path::new(file_path), &format!("{buffer1}\n{buffer2}"))
                {
                    eprintln!("Failed to write output: {e}");
                }
            } else {
                println!("{buffer2}");
            }
        }
        Err(error_message) => {
            eprintln!("{error_message}");
        }
    }
}

fn main() {
    let app = cli();
    let (cli_flags, source) = match app.try_get_matches() {
        Ok(matches) => parse_cli(matches),
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    };

    // 4) Decide how we get our pattern(s):
    match source {
        PatternsSource::SingleString(pattern) => {
            // We only have one pattern. "Unify" is trivial because there's no file-based flags
            // So just use our CLI flags directly
            handle_item(&pattern, &cli_flags);
        }

        PatternsSource::InputFile(file_path) => {
            // The user specified an input file, so parse each line
            let items = match parse_input_file(&file_path) {
                Ok(lines) => lines,
                Err(e) => {
                    eprintln!("Error reading file '{file_path}': {e}");
                    process::exit(1);
                }
            };

            // For each line in the file, unify that line’s flags with the CLI’s flags
            for file_item in items {
                // Merge the line flags + CLI flags
                let final_flags = cli_flags.unify(&file_item.flags);
                // Then handle the pattern from that line
                handle_item(&file_item.pattern, &final_flags);
            }
        }
    }
}
