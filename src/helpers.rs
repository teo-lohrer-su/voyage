use std::net::{IpAddr, Ipv4Addr};

use caracat::models::Reply;
use pnet::packet::{icmp, ip::IpNextHeaderProtocols};

use crate::types::ReplyPair;

pub fn reply(probe_ttl: u8, reply_src_addr: &str, probe_dst_addr: &str) -> Reply {
    Reply {
        probe_ttl,
        reply_src_addr: IpAddr::from(reply_src_addr.parse::<Ipv4Addr>().unwrap()),
        probe_dst_addr: IpAddr::from(probe_dst_addr.parse::<Ipv4Addr>().unwrap()),
        probe_protocol: 1,
        reply_icmp_type: icmp::IcmpTypes::TimeExceeded.0,
        reply_protocol: IpNextHeaderProtocols::Icmp.0,
        ..Default::default()
    }
}

// since Reply does not implement PartialEq, we need to compare the fields manually
pub fn reply_eq(r1: &Reply, r2: &Reply) -> bool {
    r1.probe_ttl == r2.probe_ttl
        && r1.reply_src_addr == r2.reply_src_addr
        && r1.reply_dst_addr == r2.reply_dst_addr
        && r1.reply_protocol == r2.reply_protocol
    // && r1.to_string() == r2.to_string()
}

pub fn replies_eq(replies1: &[&Reply], replies2: &[&Reply]) -> bool {
    // order insensitive
    replies1.len() == replies2.len()
        && replies1
            .iter()
            .all(|r1| replies2.iter().any(|r2| reply_eq(r1, r2)))
}

pub fn reply_pair_eq(pair1: &ReplyPair, pair2: &ReplyPair) -> bool {
    pair1.ttl == pair2.ttl
        && match (pair1.first_reply, pair2.first_reply) {
            (None, None) => true,
            (Some(r1), Some(r2)) => reply_eq(r1, r2),
            _ => false,
        }
        && match (pair1.second_reply, pair2.second_reply) {
            (None, None) => true,
            (Some(r1), Some(r2)) => reply_eq(r1, r2),
            _ => false,
        }
}

pub fn format_reply(reply: &Reply) -> String {
    format!(
        "Reply(ttl={}, src={}, dst={})",
        reply.probe_ttl, reply.reply_src_addr, reply.probe_dst_addr
    )
}

pub fn format_reply_pair(pair: &ReplyPair) -> String {
    format!(
        "ReplyPair(ttl={}, first={}, second={})",
        pair.ttl,
        pair.first_reply
            .map(format_reply)
            .unwrap_or_else(|| "None".to_string()),
        pair.second_reply
            .map(format_reply)
            .unwrap_or_else(|| "None".to_string())
    )
}
