//! Complete bounded pure Resolver daemon business logic, with caller-provided
//! transaction scratch, clocks, entropy and native IDNA capability. No host I/O.
//! See owner module for exact capacities and dirty-scratch/unchanged-owner rules.
#![no_std]
#![forbid(unsafe_code)]
pub mod cache;
pub mod files;
pub mod lookup;
pub mod owner;
pub mod pool;
pub mod storage;
