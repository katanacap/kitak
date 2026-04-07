//! # Vanity Address Generation Module
//!
//! This module is the core of kitak. It provides the functionality to generate Bitcoin vanity addresses.

pub mod chain;
pub mod vanity_addr;

pub mod comp;
#[cfg(feature = "ethereum")]
pub mod eth_search;
#[cfg(feature = "ethereum")]
pub mod keccak_simd;
#[cfg(feature = "metal-gpu")]
pub mod metal_search;
