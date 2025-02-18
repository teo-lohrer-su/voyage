use std::net::{Ipv4Addr, Ipv6Addr};

use caracat::rate_limiter::RateLimitingMethod;

#[derive(Debug, Clone)]
pub struct CaracatConfig {
    /// Number of probes to send before calling the rate limiter.
    /// Default: 100
    pub batch_size: u64,

    /// Identifier encoded in the probes (random by default).
    /// Default: 0
    pub instance_id: u16,

    /// Whether to actually send the probes on the network or not.
    /// Default: false
    pub dry_run: bool,

    /// Do not send probes with ttl < min_ttl.
    /// Default: None
    pub min_ttl: Option<u8>,

    /// Do not send probes with ttl > max_ttl.
    /// Default: None
    pub max_ttl: Option<u8>,

    /// Check that replies match valid probes.
    /// Default: false
    pub integrity_check: bool,

    /// Interface from which to send the packets.
    /// Default: default interface
    pub interface: String,

    /// Source IPv4 address
    /// Default: None
    pub src_ipv4_addr: Option<Ipv4Addr>,

    /// Source IPv6 address
    /// Default: None
    pub src_ipv6_addr: Option<Ipv6Addr>,

    /// Maximum number of probes to send (unlimited by default).
    /// Default: None
    pub max_probes: Option<u64>,

    /// Number of packets to send per probe.
    /// Default: 1
    pub packets: u64,

    /// Probing rate in packets per second.
    /// Default: 100
    pub probing_rate: u64,

    /// Method to use to limit the packets rate.
    /// Default: Auto
    pub rate_limiting_method: RateLimitingMethod,
}

impl Default for CaracatConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            instance_id: 0,
            dry_run: false,
            min_ttl: None,
            max_ttl: None,
            integrity_check: false,
            interface: Default::default(),
            src_ipv4_addr: None,
            src_ipv6_addr: None,
            max_probes: None,
            packets: 1,
            probing_rate: 100,
            rate_limiting_method: RateLimitingMethod::Auto,
        }
    }
}
