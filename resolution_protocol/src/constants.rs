#![allow(dead_code)]
use const_format::formatcp;

pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_VERSION: &'static str = "1";
pub const PROTOCOL_ALPN: &[u8] = formatcp!("/resolution_comms/{PROTOCOL_VERSION}").as_bytes();