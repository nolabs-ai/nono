//! AWS SigV4 support for nono-proxy.
//!
//! This module provides:
//! - `endpoints`: host-to-service mapping table and region extraction.
//! - `route`: per-route state (`AwsRoute`) and the owned route+provider table (`AwsRouteTable`).
//! - `sign`: SigV4 request signing with selective auth header stripping.

pub mod endpoints;
pub mod route;
pub mod sign;
