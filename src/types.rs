use std::net::IpAddr;

use caracat::models::{Reply, L4};

#[allow(clippy::upper_case_acronyms)]
#[derive(Eq, PartialEq, Hash, Clone, Copy, Debug)]
pub(crate) enum L4Wrapper {
    ICMP,
    ICMPv6,
    UDP,
}

impl From<L4> for L4Wrapper {
    fn from(l4: L4) -> Self {
        match l4 {
            L4::ICMP => L4Wrapper::ICMP,
            L4::ICMPv6 => L4Wrapper::ICMPv6,
            L4::UDP => L4Wrapper::UDP,
        }
    }
}

impl From<u8> for L4Wrapper {
    fn from(l4: u8) -> Self {
        match l4 {
            1 => L4Wrapper::ICMP,
            58 => L4Wrapper::ICMPv6,
            17 => L4Wrapper::UDP,
            _ => panic!("Unknown L4 protocol"),
        }
    }
}

impl From<&L4Wrapper> for L4 {
    fn from(l4: &L4Wrapper) -> Self {
        match l4 {
            L4Wrapper::ICMP => L4::ICMP,
            L4Wrapper::ICMPv6 => L4::ICMPv6,
            L4Wrapper::UDP => L4::UDP,
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
pub type TTL = u8;
pub(crate) type Port = u16;

#[derive(Eq, PartialEq, Hash, Clone, Copy, Debug)]
pub struct Flow {
    pub(crate) protocol: L4Wrapper,
    pub(crate) dst_address: IpAddr,
    pub(crate) src_port: Port,
    pub(crate) dst_port: Port,
}

impl From<&Reply> for Flow {
    fn from(value: &Reply) -> Self {
        Flow {
            protocol: value.probe_protocol.into(),
            dst_address: value.probe_dst_addr,
            src_port: value.probe_src_port,
            dst_port: value.probe_dst_port,
        }
    }
}

#[derive(Eq, Hash, PartialEq, Debug)]
pub struct Link<'a> {
    pub(crate) ttl: TTL,
    pub(crate) near_ip: Option<&'a IpAddr>,
    pub(crate) far_ip: Option<&'a IpAddr>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ReplyPair<'a> {
    pub(crate) ttl: TTL,
    pub(crate) first_reply: Option<&'a Reply>,
    pub(crate) second_reply: Option<&'a Reply>,
}
