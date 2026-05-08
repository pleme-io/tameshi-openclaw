//! Tameshi-OpenClaw — AI agent integrity attestation integration.
//!
//! Provides skill creation gating, continuous compliance scanning,
//! attested skill store client, and OpenClaw hook integration.

pub mod api;
pub mod config;
pub mod core;
pub mod entities;
pub mod error;
pub mod hooks;
pub mod mcps;
pub mod scanner;
pub mod skill;
