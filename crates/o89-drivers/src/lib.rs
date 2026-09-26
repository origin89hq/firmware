//! The controller's device dialects, and the seams they read through.
//!
//! `no_std` and no `alloc`, like `o89-core`, and naming no peripheral: a
//! driver speaks to a [`port`] trait, so a captured or hand-built exchange
//! is a host test. A dialect's [`dialect::Cell`] declares the provenance the
//! vendor can justify, and decoding writes exactly that into the store
//! (F-052); nothing publishes as `measured` by default.
//!
//! Devices are a closed set known at build time, so they are an enum,
//! [`Device`], with one poll entry per kind of bus: a dialect lands as a
//! variant, and the compiler finds every place that has to answer for it.

#![no_std]

pub mod adc;
mod device;
pub mod dialect;
pub mod ds18b20;
pub mod modbus;
pub mod onewire;
pub mod port;

pub use device::*;
