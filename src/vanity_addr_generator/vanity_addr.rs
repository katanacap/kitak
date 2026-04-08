//! # Vanity Address Generator Module
//!
//! This module defines the [VanityAddr] and [SearchEngines] structs, which handle the generation
//! of vanity cryptocurrency addresses using custom patterns and regular expressions. It supports:
//! - Validation and adjustment of inputs for specific chains.
//! - Multi-threaded generation of vanity addresses.
//! - Pattern matching using prefix, suffix, anywhere, and regex modes.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Instant;

use crate::BATCH_SIZE;
use crate::error::VanityError;
use crate::vanity_addr_generator::chain::VanityChain;
use crate::vanity_addr_generator::comp::{
    contains_case_insensitive, contains_memx, eq_prefix_case_insensitive, eq_prefix_memx,
    eq_suffix_case_insensitive, eq_suffix_memx,
};

use regex::Regex;

/// An empty struct that provides functionality for generating vanity addresses.
///
/// This struct contains only static methods and acts as a logical container for
/// vanity address generation functionality.
pub struct VanityAddr;

/// Enum to define the matching mode for vanity address generation.
#[derive(Copy, Clone, Debug, PartialEq, Default)]
pub enum VanityMode {
    /// Matches addresses that start with the pattern.
    #[default]
    Prefix,
    /// Matches addresses that end with the pattern.
    Suffix,
    /// Matches addresses that contain the pattern anywhere.
    Anywhere,
    /// Matches addresses based on a regular expression.
    Regex,
}

impl VanityAddr {
    /// Generates a vanity address for a given pattern.
    ///
    /// # Arguments
    /// - `string`: The pattern string to match against addresses.
    /// - `threads`: The number of threads to use for address generation.
    /// - `case_sensitive`: Whether the matching should be case-sensitive.
    /// - `fast_mode`: Whether to enable fast mode (with stricter limits on pattern length).
    /// - `vanity_mode`: The mode of matching (e.g., prefix, suffix).
    ///
    /// # Returns
    /// - `Ok(T)` where `T` is a type implementing [VanityChain], containing the generated address.
    /// - `Err(VanityError)` if the input is invalid or generation fails.
    ///
    /// # Behavior
    /// - Validates the input string for chain-specific rules.
    /// - Adjusts the input string based on the chain and vanity mode.
    /// - Uses multiple threads to search for a matching address.
    pub fn generate<T: VanityChain + 'static>(
        string: &str,
        threads: usize,
        case_sensitive: bool,
        fast_mode: bool,
        vanity_mode: VanityMode,
    ) -> Result<T, VanityError> {
        T::validate_input(string, fast_mode, case_sensitive)?;
        let adjusted_string = T::adjust_input(string, vanity_mode);

        if string.is_empty() {
            return Ok(T::generate_random());
        }

        Ok(SearchEngines::find_vanity_address::<T>(
            adjusted_string,
            None,
            threads,
            case_sensitive,
            vanity_mode,
        ))
    }

    /// Generate with combined prefix + suffix matching.
    pub fn generate_prefix_suffix<T: VanityChain + 'static>(
        prefix: &str,
        suffix: &str,
        threads: usize,
        case_sensitive: bool,
        fast_mode: bool,
    ) -> Result<T, VanityError> {
        T::validate_input(prefix, fast_mode, case_sensitive)?;
        if !suffix.is_empty() {
            T::validate_input(suffix, fast_mode, case_sensitive)?;
        }
        let adjusted_prefix = T::adjust_input(prefix, VanityMode::Prefix);

        if prefix.is_empty() && suffix.is_empty() {
            return Ok(T::generate_random());
        }

        let suffix_adjusted = if suffix.is_empty() {
            None
        } else {
            Some(suffix.to_string())
        };

        Ok(SearchEngines::find_vanity_address::<T>(
            adjusted_prefix,
            suffix_adjusted,
            threads,
            case_sensitive,
            VanityMode::Prefix,
        ))
    }

    /// Generates a vanity address based on a regular expression.
    ///
    /// # Arguments
    /// - `regex_str`: The regular expression to match against addresses.
    /// - `threads`: The number of threads to use for address generation.
    ///
    /// # Returns
    /// - `Ok(T)` where `T` is a type implementing [VanityChain], containing the generated address.
    /// - `Err(VanityError)` if the regex is invalid or generation fails.
    ///
    /// # Behavior
    /// - Validates the regular expression for chain-specific rules.
    /// - Adjusts the regex pattern based on the chain.
    /// - Uses multiple threads to search for a matching address.
    pub fn generate_regex<T: VanityChain + 'static>(
        regex_str: &str,
        threads: usize,
    ) -> Result<T, VanityError> {
        T::validate_regex_pattern(regex_str)?;
        let adjusted_regex = T::adjust_regex_pattern(regex_str);

        if regex_str.is_empty() {
            return Ok(T::generate_random());
        }

        SearchEngines::find_vanity_address_regex::<T>(adjusted_regex, threads)
    }
}

/// A helper struct that implements the core logic for searching for vanity addresses.
///
/// This struct contains static methods for address search using both plain patterns
/// and regular expressions.
pub struct SearchEngines;

impl SearchEngines {
    /// Searches for a vanity address matching the given string pattern.
    ///
    /// # Arguments
    /// - `string`: The string pattern to match against addresses.
    /// - `threads`: The number of threads to use for address generation.
    /// - `case_sensitive`: Whether the matching should be case-sensitive.
    /// - `vanity_mode`: The mode of matching (e.g., prefix, suffix).
    ///
    /// # Returns
    /// - A type implementing [VanityChain] that contains the generated address.
    ///
    /// # Behavior
    /// - Spawns multiple threads to search for a matching address.
    /// - Uses an atomic flag to stop all threads once a match is found.
    /// - Uses an `mpsc` channel to send the matching address back to the main thread.
    fn find_vanity_address<T: VanityChain + 'static>(
        string: String,
        suffix: Option<String>,
        threads: usize,
        case_sensitive: bool,
        vanity_mode: VanityMode,
    ) -> T {
        let string_bytes = string.as_bytes();
        let lower_string_bytes = if !case_sensitive {
            string_bytes
                .iter()
                .map(|b| b.to_ascii_lowercase())
                .collect::<Vec<u8>>()
        } else {
            vec![]
        };

        // Prepare suffix bytes for combined prefix+suffix
        let suffix_bytes = suffix.as_deref().unwrap_or("").as_bytes().to_vec();
        let lower_suffix_bytes: Vec<u8> = if !case_sensitive {
            suffix_bytes
                .iter()
                .map(|b| b.to_ascii_lowercase())
                .collect()
        } else {
            vec![]
        };
        let has_suffix = !suffix_bytes.is_empty();

        let (sender, receiver) = mpsc::channel();
        let found_any = Arc::new(AtomicBool::new(false));
        let total_checked = Arc::new(AtomicU64::new(0));

        // Progress reporter thread with matrix-style scrambling
        {
            let found_any = Arc::clone(&found_any);
            let total_checked = Arc::clone(&total_checked);
            let pattern_display = string.clone();
            let suffix_display = suffix.clone().unwrap_or_default();
            thread::spawn(move || {
                let start = Instant::now();
                let mut last_count = 0u64;
                let mut last_time = start;
                // Base58 charset (no 0, O, I, l)
                let b58_chars: &[u8] =
                    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
                let prefix_len = pattern_display.len();
                let suffix_len = suffix_display.len();
                let addr_len: usize = 34; // approximate for display
                let mid_len = addr_len.saturating_sub(prefix_len + suffix_len);
                let mut displayed = false;

                while !found_any.load(Ordering::Relaxed) {
                    thread::sleep(std::time::Duration::from_millis(10));
                    if found_any.load(Ordering::Relaxed) {
                        break;
                    }

                    if !displayed {
                        eprintln!();
                        displayed = true;
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

                    let mins = (elapsed as u64) / 60;
                    let secs = (elapsed as u64) % 60;

                    let count_display = if count >= 1_000_000_000 {
                        format!("{:.2}B", count as f64 / 1_000_000_000.0)
                    } else if count >= 1_000_000 {
                        format!("{:.1}M", count as f64 / 1_000_000.0)
                    } else if count >= 1_000 {
                        format!("{:.0}K", count as f64 / 1_000.0)
                    } else {
                        format!("{count}")
                    };

                    let scrambled: String = (0..mid_len)
                        .map(|_| b58_chars[rand::random_range(0..b58_chars.len())] as char)
                        .collect();

                    eprint!(
                        "\r\x1b[K  \x1b[37m{:02}:{:02}\x1b[0m  \x1b[1;32m{}\x1b[36m{}\x1b[1;32m{}\x1b[0m  \x1b[1;37m{:>8}\x1b[0m  \x1b[1;33m{:.1}M/s\x1b[0m",
                        mins,
                        secs,
                        pattern_display,
                        scrambled,
                        suffix_display,
                        count_display,
                        speed / 1_000_000.0,
                    );

                    last_count = count;
                    last_time = now;
                }

                let count = total_checked.load(Ordering::Relaxed);
                let elapsed = start.elapsed().as_secs_f64();
                let avg_speed = count as f64 / elapsed.max(0.001);
                let prefix = if displayed { "\r\x1b[K\n" } else { "" };
                eprintln!(
                    "{prefix}\n  \x1b[32m✓ FOUND\x1b[0m in \x1b[33m{:.1}s\x1b[0m  \x1b[90m({:.1}M checked, {:.1}M/s)\x1b[0m\n",
                    elapsed,
                    count as f64 / 1_000_000.0,
                    avg_speed / 1_000_000.0,
                );
            });
        }

        for _ in 0..threads {
            let sender = sender.clone();
            let found_any = found_any.clone();
            let total_checked = Arc::clone(&total_checked);

            let thread_string_bytes = string_bytes.to_vec();
            let thread_lower_string_bytes = lower_string_bytes.clone();
            let thread_suffix_bytes = suffix_bytes.clone();
            let thread_lower_suffix_bytes = lower_suffix_bytes.clone();

            thread::spawn(move || {
                let mut batch: [T; BATCH_SIZE] = T::generate_batch();
                let mut dummy = T::generate_random();

                let pattern_len = if case_sensitive {
                    thread_string_bytes.len()
                } else {
                    thread_lower_string_bytes.len()
                };

                while !found_any.load(Ordering::Relaxed) {
                    T::fill_batch(&mut batch);

                    let mut i = 0;
                    while i < BATCH_SIZE {
                        let end = std::cmp::min(i + 8, BATCH_SIZE);

                        #[allow(clippy::needless_range_loop)]
                        for j in i..end {
                            if j.is_multiple_of(4) && found_any.load(Ordering::Relaxed) {
                                return;
                            }

                            let keys_and_address = &batch[j];
                            let address_bytes = keys_and_address.get_address_bytes();

                            if address_bytes.len() < pattern_len {
                                continue;
                            }

                            let prefix_matches = if case_sensitive {
                                match vanity_mode {
                                    VanityMode::Prefix => {
                                        eq_prefix_memx(address_bytes, &thread_string_bytes)
                                    }
                                    VanityMode::Suffix => {
                                        eq_suffix_memx(address_bytes, &thread_string_bytes)
                                    }
                                    VanityMode::Anywhere => {
                                        contains_memx(address_bytes, &thread_string_bytes)
                                    }
                                    VanityMode::Regex => unreachable!(),
                                }
                            } else {
                                match vanity_mode {
                                    VanityMode::Prefix => eq_prefix_case_insensitive(
                                        address_bytes,
                                        &thread_lower_string_bytes,
                                    ),
                                    VanityMode::Suffix => eq_suffix_case_insensitive(
                                        address_bytes,
                                        &thread_lower_string_bytes,
                                    ),
                                    VanityMode::Anywhere => contains_case_insensitive(
                                        address_bytes,
                                        &thread_lower_string_bytes,
                                    ),
                                    VanityMode::Regex => unreachable!(),
                                }
                            };

                            // Check suffix if combined mode
                            let matches = prefix_matches
                                && (!has_suffix
                                    || if case_sensitive {
                                        eq_suffix_memx(address_bytes, &thread_suffix_bytes)
                                    } else {
                                        eq_suffix_case_insensitive(
                                            address_bytes,
                                            &thread_lower_suffix_bytes,
                                        )
                                    });

                            if matches {
                                if !found_any.swap(true, Ordering::Relaxed) {
                                    std::mem::swap(&mut batch[j], &mut dummy);
                                    let _ = sender.send(dummy);
                                }
                                return;
                            }
                        }

                        i = end;
                    }

                    total_checked.fetch_add(BATCH_SIZE as u64, Ordering::Relaxed);
                }
            });
        }

        let result = receiver
            .recv()
            .expect("Receiver closed before a vanity address was found");
        // Let progress thread finish printing ✓ FOUND
        thread::sleep(std::time::Duration::from_millis(50));
        result
    }

    /// Searches for a vanity address matching the given regex pattern.
    ///
    /// # Arguments
    /// - `regex_str`: The regex pattern to match against addresses.
    /// - `threads`: The number of threads to use for address generation.
    ///
    /// # Returns
    /// - `Ok(T)` where `T` is a type implementing [VanityChain], containing the generated address.
    /// - `Err(VanityError)` if the regex is invalid or generation fails.
    ///
    /// # Behavior
    /// - Spawns multiple threads to search for a matching address.
    /// - Uses an atomic flag to stop all threads once a match is found.
    /// - Uses an `mpsc` channel to send the matching address back to the main thread.
    pub fn find_vanity_address_regex<T: VanityChain + 'static>(
        regex_str: String,
        threads: usize,
    ) -> Result<T, VanityError> {
        // Validate the regex syntax
        let _test_regex = Regex::new(&regex_str).map_err(|_e| VanityError::InvalidRegex)?;

        let (sender, receiver) = mpsc::channel();
        let found_any = Arc::new(AtomicBool::new(false));

        for _ in 0..threads {
            let sender = sender.clone();
            let found_any = Arc::clone(&found_any);
            let regex_clone = regex_str.clone();

            thread::spawn(move || {
                // Compile regex once per thread
                let regex = Regex::new(&regex_clone).unwrap();
                let mut batch: [T; BATCH_SIZE] = T::generate_batch();
                let mut dummy = T::generate_random();

                while !found_any.load(Ordering::Relaxed) {
                    // Generate a batch of addresses
                    T::fill_batch(&mut batch);

                    // Check each address in the batch
                    for (i, keys_and_address) in batch.iter().enumerate() {
                        let address = keys_and_address.get_address();
                        if regex.is_match(address) && !found_any.load(Ordering::Relaxed) {
                            // If a match is found, send it to the main thread
                            if !found_any.swap(true, Ordering::Relaxed) {
                                std::mem::swap(&mut batch[i], &mut dummy);
                                let _ = sender.send(dummy);
                                return;
                            }
                        }
                    }
                }
            });
        }

        // The main thread just waits for the first successful result.
        // As soon as one thread sends over the channel, we have our vanity address.
        Ok(receiver
            .recv()
            .expect("Receiver closed before a matching address was found"))
    }
}

#[cfg(test)]
mod tests {
    use super::{VanityAddr, VanityMode};

    mod bitcoin_vanity_tests {
        use super::*;
        use crate::keys_and_address::BitcoinKeyPair;

        #[test]
        fn test_generate_vanity_prefix() {
            let vanity_string = "et";
            let keys_and_address = VanityAddr::generate::<BitcoinKeyPair>(
                vanity_string,
                4,                  // Use 4 threads
                true,               // Case-insensitivity
                true,               // Fast mode (limits string size with 4 characters)
                VanityMode::Prefix, // Vanity mode set to Prefix
            )
            .unwrap();

            let vanity_addr_starts_with = "1et";
            assert!(
                keys_and_address
                    .get_comp_address()
                    .starts_with(vanity_addr_starts_with)
            );
        }

        #[test]
        fn test_generate_vanity_suffix() {
            let vanity_string = "12";
            let keys_and_address = VanityAddr::generate::<BitcoinKeyPair>(
                vanity_string,
                4,                  // Use 4 threads
                false,              // Case-insensitivity
                true,               // Fast mode (limits string size with 4 characters)
                VanityMode::Suffix, // Vanity mode set to Suffix
            )
            .unwrap();

            assert!(keys_and_address.get_comp_address().ends_with(vanity_string));
        }

        #[test]
        fn test_generate_vanity_anywhere() {
            let vanity_string = "ab";
            let keys_and_address = VanityAddr::generate::<BitcoinKeyPair>(
                vanity_string,
                4,                    // Use 4 threads
                true,                 // Case-insensitivity
                true,                 // Fast mode (limits string size with 4 characters)
                VanityMode::Anywhere, // Vanity mode set to Anywhere
            )
            .unwrap();

            assert!(keys_and_address.get_comp_address().contains(vanity_string));
        }

        #[test]
        #[should_panic(expected = "FastModeEnabled")]
        fn test_generate_vanity_string_too_long_with_fast_mode() {
            let vanity_string = "123456"; // String longer than 5 characters
            let _ = VanityAddr::generate::<BitcoinKeyPair>(
                vanity_string,
                4,                  // Use 4 threads
                false,              // Case-insensitivity
                true,               // Fast mode (limits string size with 4 characters)
                VanityMode::Prefix, // Vanity mode set to Prefix
            )
            .unwrap();
        }

        #[test]
        #[should_panic(expected = "InputNotBase58")]
        fn test_generate_vanity_invalid_base58() {
            let vanity_string = "emiO"; // Contains invalid base58 character 'O'
            let _ = VanityAddr::generate::<BitcoinKeyPair>(
                vanity_string,
                4,                  // Use 4 threads
                false,              // Case-insensitivity
                true,               // Fast mode (limits string size with 4 characters)
                VanityMode::Prefix, // Vanity mode set to Prefix
            )
            .unwrap();
        }

        #[test]
        fn test_generate_regex_et_ends() {
            let pattern = "ET$";
            let keys_and_address = VanityAddr::generate_regex::<BitcoinKeyPair>(pattern, 4)
                .expect("Failed to generate address for 'ET$'");
            let address = keys_and_address.get_comp_address();

            // The final pattern is "ET$" => ends with "ET"
            assert!(
                address.ends_with("ET"),
                "Address should end with 'ET': {}",
                address
            );
        }

        #[test]
        fn test_generate_regex_rewrite() {
            // Original pattern is '^E' (not '^1'), so the code will insert '1', resulting in '^1E'.
            // We expect it eventually to find an address starting with "1E".
            let pattern = "^E";
            let keys_and_address =
                VanityAddr::generate_regex::<BitcoinKeyPair>(pattern, 4).unwrap();
            let address = keys_and_address.get_comp_address();
            // Now that we know it's '^1E', check the first two characters:
            assert!(
                address.starts_with("1E"),
                "Address should start with '1E': {}",
                address
            );
        }

        #[test]
        fn test_generate_regex_e_any_t() {
            // Must start with "1E" (rewritten from "^E") and end with "T".
            let pattern = "^E.*T$";
            let keys_and_address = VanityAddr::generate_regex::<BitcoinKeyPair>(pattern, 4)
                .expect("Failed to generate address for '^E.*T$'");
            let address = keys_and_address.get_comp_address();

            // Because of rewriting, the actual pattern used is '^1E.*T$'.
            // 1) Check it starts with "1E"
            assert!(
                address.starts_with("1E"),
                "Address should start with '1E': {}",
                address
            );
            // 2) Check it ends with 'T'
            assert!(
                address.ends_with('T'),
                "Address should end with 'T': {}",
                address
            );
        }

        #[test]
        fn test_generate_regex_e_69_any_t() {
            // Must start with "1E", contain "69", and end with "T".
            // Rewritten from "^E.*69.*T$" => "^1E.*69.*T$"
            let pattern = "^E.*69.*T$";
            let keys_and_address = VanityAddr::generate_regex::<BitcoinKeyPair>(pattern, 4)
                .expect("Failed to generate address for '^E.*69.*T$'");
            let address = keys_and_address.get_comp_address();

            // After rewriting: '^1E.*69.*T$'
            assert!(
                address.starts_with("1E"),
                "Address should start with '1E': {}",
                address
            );
            assert!(
                address.contains("69"),
                "Address should contain '69': {}",
                address
            );
            assert!(
                address.ends_with('T'),
                "Address should end with 'T': {}",
                address
            );
        }

        #[test]
        #[should_panic(expected = "InvalidRegex")]
        fn test_generate_regex_invalid_syntax() {
            let pattern = "^(abc";
            let _ = VanityAddr::generate_regex::<BitcoinKeyPair>(pattern, 4).unwrap();
        }

        #[test]
        #[should_panic(expected = "RegexNotBase58")]
        fn test_generate_regex_forbidden_char_zero() {
            let pattern = "^0";
            let _ = VanityAddr::generate_regex::<BitcoinKeyPair>(pattern, 4).unwrap();
        }

        #[test]
        #[should_panic(expected = "RegexNotBase58")]
        fn test_generate_regex_forbidden_char_o() {
            let pattern = "^O";
            let _ = VanityAddr::generate_regex::<BitcoinKeyPair>(pattern, 4).unwrap();
        }

        #[test]
        #[should_panic(expected = "RegexNotBase58")]
        fn test_generate_regex_forbidden_char_i() {
            let pattern = "^I";
            let _ = VanityAddr::generate_regex::<BitcoinKeyPair>(pattern, 4).unwrap();
        }
    }

    #[cfg(feature = "ethereum")]
    mod ethereum_vanity_tests {
        use super::*;
        use crate::keys_and_address::{EthereumKeyPair, KeyPairGenerator};

        #[test]
        fn test_generate_vanity_prefix() {
            let vanity_string = "ab";
            let keys_and_address = VanityAddr::generate::<EthereumKeyPair>(
                vanity_string,
                4,                  // Use 4 threads
                false,              // Case-insensitivity
                true,               // Fast mode
                VanityMode::Prefix, // Vanity mode set to Prefix
            )
            .unwrap();

            let expected_prefix = "ab";
            assert!(
                keys_and_address
                    .get_address()
                    .to_lowercase()
                    .starts_with(expected_prefix)
            );
        }

        #[test]
        fn test_generate_vanity_suffix() {
            let vanity_string = "123";
            let keys_and_address = VanityAddr::generate::<EthereumKeyPair>(
                vanity_string,
                4,                  // Use 4 threads
                false,              // Case-sensitivity
                true,               // Fast mode
                VanityMode::Suffix, // Vanity mode set to Suffix
            )
            .unwrap();

            assert!(keys_and_address.get_address().ends_with(vanity_string));
        }

        #[test]
        fn test_generate_vanity_anywhere() {
            let vanity_string = "abc";
            let keys_and_address = VanityAddr::generate::<EthereumKeyPair>(
                vanity_string,
                4,                    // Use 4 threads
                false,                // Case-insensitivity
                true,                 // Fast mode (limits string size to 16 characters)
                VanityMode::Anywhere, // Vanity mode set to Anywhere
            )
            .unwrap();

            assert!(keys_and_address.get_address().contains(vanity_string));
        }

        #[test]
        #[should_panic(expected = "FastModeEnabled")]
        fn test_generate_vanity_string_too_long_with_fast_mode() {
            let vanity_string = "12345678901234567890"; // String longer than 16 characters
            let _ = VanityAddr::generate::<EthereumKeyPair>(
                vanity_string,
                4,                  // Use 4 threads
                false,              // Case-sensitivity
                true,               // Fast mode (limits string size to 16 characters)
                VanityMode::Prefix, // Vanity mode set to Prefix
            )
            .unwrap();
        }

        #[test]
        #[should_panic(expected = "InputNotBase16")]
        fn test_generate_vanity_invalid_base16() {
            let vanity_string = "g123"; // Contains invalid base16 character 'g'
            let _ = VanityAddr::generate::<EthereumKeyPair>(
                vanity_string,
                4,                  // Use 4 threads
                false,              // Case-sensitivity
                true,               // Fast mode
                VanityMode::Prefix, // Vanity mode set to Prefix
            )
            .unwrap();
        }

        #[test]
        #[should_panic(expected = "InputNotBase16")]
        fn test_generate_vanity_with_prefix() {
            let vanity_string = "0xdead"; // Contains invalid base16 character 'x'
            let _ = VanityAddr::generate::<EthereumKeyPair>(
                vanity_string,
                4,                  // Use 4 threads
                false,              // Case-sensitivity
                true,               // Fast mode
                VanityMode::Prefix, // Vanity mode set to Prefix
            )
            .unwrap();
        }

        #[test]
        fn test_generate_regex_prefix() {
            let pattern = "^ab";
            let keys_and_address =
                VanityAddr::generate_regex::<EthereumKeyPair>(pattern, 4).unwrap();
            let address = keys_and_address.get_address();

            assert!(
                address.starts_with("ab"),
                "Address should start with 'ab': {}",
                address
            );
        }

        #[test]
        fn test_generate_regex_suffix() {
            let pattern = "cd$";
            let keys_and_address =
                VanityAddr::generate_regex::<EthereumKeyPair>(pattern, 4).unwrap();
            let address = keys_and_address.get_address();

            assert!(
                address.ends_with("cd"),
                "Address should end with 'cd': {}",
                address
            );
        }

        #[test]
        fn test_generate_regex_anywhere() {
            let pattern = ".*abc.*";
            let keys_and_address =
                VanityAddr::generate_regex::<EthereumKeyPair>(pattern, 4).unwrap();
            let address = keys_and_address.get_address();

            assert!(
                address.contains("abc"),
                "Address should contain 'abc': {}",
                address
            );
        }

        #[test]
        #[should_panic(expected = "InvalidRegex")]
        fn test_generate_regex_invalid_syntax() {
            let pattern = "^(abc";
            let _ = VanityAddr::generate_regex::<EthereumKeyPair>(pattern, 4).unwrap();
        }

        #[test]
        #[should_panic(expected = "RegexNotBase16")]
        fn test_generate_regex_invalid_characters() {
            let pattern = "^gh";
            let _ = VanityAddr::generate_regex::<EthereumKeyPair>(pattern, 4).unwrap();
        }

        #[test]
        #[should_panic(expected = "RegexNotBase16")]
        fn test_generate_regex_with_prefix() {
            let pattern = "^0xdead";
            let _ = VanityAddr::generate_regex::<EthereumKeyPair>(pattern, 4).unwrap();
        }

        #[test]
        fn test_generate_regex_complex_pattern() {
            let pattern = "^ab.*12$";
            let keys_and_address =
                VanityAddr::generate_regex::<EthereumKeyPair>(pattern, 4).unwrap();
            let address = keys_and_address.get_address();

            assert!(
                address.starts_with("ab"),
                "Address should start with 'ab': {}",
                address
            );
            assert!(
                address.ends_with("12"),
                "Address should end with '12': {}",
                address
            );
        }
    }

    #[cfg(feature = "solana")]
    mod solana_vanity_tests {
        use super::*;
        use crate::keys_and_address::{KeyPairGenerator, SolanaKeyPair};

        #[test]
        fn test_generate_vanity_prefix() {
            let vanity_string = "et";
            let keys_and_address = VanityAddr::generate::<SolanaKeyPair>(
                vanity_string,
                4,                  // Use 4 threads
                true,               // Case-insensitivity
                true,               // Fast mode (limits string size with 44 characters)
                VanityMode::Prefix, // Vanity mode set to Prefix
            )
            .unwrap();

            let vanity_addr_starts_with = "et";
            assert!(
                keys_and_address
                    .get_address()
                    .starts_with(vanity_addr_starts_with)
            );
        }

        #[test]
        fn test_generate_vanity_suffix() {
            let vanity_string = "12";
            let keys_and_address = VanityAddr::generate::<SolanaKeyPair>(
                vanity_string,
                4,                  // Use 4 threads
                false,              // Case-insensitivity
                true,               // Fast mode (limits string size with 44 characters)
                VanityMode::Suffix, // Vanity mode set to Suffix
            )
            .unwrap();

            assert!(keys_and_address.get_address().ends_with(vanity_string));
        }

        #[test]
        fn test_generate_vanity_anywhere() {
            let vanity_string = "ab";
            let keys_and_address = VanityAddr::generate::<SolanaKeyPair>(
                vanity_string,
                4,                    // Use 4 threads
                true,                 // Case-insensitivity
                true,                 // Fast mode (limits string size with 44 characters)
                VanityMode::Anywhere, // Vanity mode set to Anywhere
            )
            .unwrap();

            assert!(keys_and_address.get_address().contains(vanity_string));
        }

        #[test]
        #[should_panic(expected = "FastModeEnabled")]
        fn test_generate_vanity_string_too_long_with_fast_mode() {
            let vanity_string = "123456"; // String longer than 5 characters
            let _ = VanityAddr::generate::<SolanaKeyPair>(
                vanity_string,
                4,                  // Use 4 threads
                false,              // Case-insensitivity
                true,               // Fast mode (limits string size with 44 characters)
                VanityMode::Prefix, // Vanity mode set to Prefix
            )
            .unwrap();
        }

        #[test]
        #[should_panic(expected = "InputNotBase58")]
        fn test_generate_vanity_invalid_base58() {
            let vanity_string = "emiO"; // Contains invalid base58 character 'O'
            let _ = VanityAddr::generate::<SolanaKeyPair>(
                vanity_string,
                4,                  // Use 4 threads
                false,              // Case-insensitivity
                true,               // Fast mode (limits string size with 44 characters)
                VanityMode::Prefix, // Vanity mode set to Prefix
            )
            .unwrap();
        }

        #[test]
        fn test_generate_regex_prefix() {
            let pattern = "^et";
            let keys_and_address = VanityAddr::generate_regex::<SolanaKeyPair>(pattern, 4).unwrap();
            let address = keys_and_address.get_address();

            assert!(
                address.starts_with("et"),
                "Address should start with 'et': {}",
                address
            );
        }

        #[test]
        fn test_generate_regex_suffix() {
            let pattern = "cd$";
            let keys_and_address = VanityAddr::generate_regex::<SolanaKeyPair>(pattern, 4).unwrap();
            let address = keys_and_address.get_address();

            assert!(
                address.ends_with("cd"),
                "Address should end with 'cd': {}",
                address
            );
        }

        #[test]
        fn test_generate_regex_anywhere() {
            let pattern = ".*ab.*";
            let keys_and_address = VanityAddr::generate_regex::<SolanaKeyPair>(pattern, 4).unwrap();
            let address = keys_and_address.get_address();

            assert!(
                address.contains("ab"),
                "Address should contain 'ab': {}",
                address
            );
        }

        #[test]
        #[should_panic(expected = "InvalidRegex")]
        fn test_generate_regex_invalid_syntax() {
            let pattern = "^(abc";
            let _ = VanityAddr::generate_regex::<SolanaKeyPair>(pattern, 4).unwrap();
        }

        #[test]
        #[should_panic(expected = "RegexNotBase58")]
        fn test_generate_regex_invalid_characters() {
            let pattern = "^ghO";
            let _ = VanityAddr::generate_regex::<SolanaKeyPair>(pattern, 4).unwrap();
        }

        #[test]
        fn test_generate_regex_starts_with_e() {
            let pattern = "^e";
            let keys_and_address = VanityAddr::generate_regex::<SolanaKeyPair>(pattern, 4).unwrap();
            let address = keys_and_address.get_address();

            assert!(
                address.starts_with("e"),
                "Address should start with 'e': {}",
                address
            );
        }

        #[test]
        fn test_generate_regex_contains_11() {
            let pattern = ".*11.*";
            let keys_and_address = VanityAddr::generate_regex::<SolanaKeyPair>(pattern, 4).unwrap();
            let address = keys_and_address.get_address();

            assert!(
                address.contains("11"),
                "Address should contain '11': {}",
                address
            );
        }

        #[test]
        fn test_generate_regex_contains_22() {
            let pattern = ".*22.*";
            let keys_and_address = VanityAddr::generate_regex::<SolanaKeyPair>(pattern, 4).unwrap();
            let address = keys_and_address.get_address();

            assert!(
                address.contains("22"),
                "Address should contain '22': {}",
                address
            );
        }

        #[test]
        fn test_generate_regex_ends_with_t() {
            let pattern = "t$";
            let keys_and_address = VanityAddr::generate_regex::<SolanaKeyPair>(pattern, 4).unwrap();
            let address = keys_and_address.get_address();

            assert!(
                address.ends_with("t"),
                "Address should end with 't': {}",
                address
            );
        }

        #[test]
        fn test_generate_regex_complex_sequence() {
            let pattern = "11.*22";
            let keys_and_address = VanityAddr::generate_regex::<SolanaKeyPair>(pattern, 4).unwrap();
            let address = keys_and_address.get_address();

            assert!(
                address.contains("11") && address.contains("22"),
                "Address should contain '11' followed by '22': {}",
                address
            );
        }

        #[test]
        fn test_generate_regex_complex_pattern() {
            let pattern = "^e.*9.*t$";
            let keys_and_address = VanityAddr::generate_regex::<SolanaKeyPair>(pattern, 4).unwrap();
            let address = keys_and_address.get_address();

            assert!(
                address.starts_with("e"),
                "Address should start with 'e': {}",
                address
            );
            assert!(
                address.contains("9"),
                "Address should contain '9': {}",
                address
            );
            assert!(
                address.ends_with("t"),
                "Address should end with 't': {}",
                address
            );
        }
    }
}
