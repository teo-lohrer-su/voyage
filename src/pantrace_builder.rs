use caracat::models::Reply;
use chrono::DateTime;
use itertools::Itertools;
use pantrace::formats::internal::{
    MplsEntry, TracerouteFlow, TracerouteHop, TracerouteProbe, TracerouteReply,
};

use crate::links::get_replies_by_flow;

fn reply_to_pantrace_reply(reply: &Reply) -> TracerouteReply {
    TracerouteReply {
        timestamp: DateTime::from_timestamp_micros(reply.capture_timestamp as i64).unwrap(),
        quoted_ttl: reply.quoted_ttl,
        ttl: reply.reply_ttl,
        size: reply.reply_size,
        addr: reply.reply_src_addr,
        icmp_type: reply.reply_icmp_type,
        icmp_code: reply.reply_icmp_code,
        mpls_labels: reply
            .reply_mpls_labels
            .iter()
            .map(|l| MplsEntry {
                label: l.label,
                exp: l.experimental,
                bottom_of_stack: l.bottom_of_stack as u8,
                ttl: l.ttl,
            })
            .collect(),
        rtt: reply.rtt as f64,
    }
}

fn reply_to_pantrace_probe(reply: &Reply) -> TracerouteProbe {
    let capture_usec = reply.capture_timestamp;
    let rtt_tenth_msec = reply.rtt as u64;
    let emission_usec = capture_usec - rtt_tenth_msec * 100;
    TracerouteProbe {
        timestamp: DateTime::from_timestamp_micros(emission_usec as i64).unwrap(),
        size: reply.probe_size,
        reply: Some(reply_to_pantrace_reply(reply)),
    }
}

fn generate_pantrace_traceroute_flow(replies: &[&Reply]) -> TracerouteFlow {
    let src_port = replies[0].probe_src_port;
    let dst_port = replies[0].probe_dst_port;
    TracerouteFlow {
        src_port,
        dst_port,
        hops: replies
            .iter()
            .group_by(|r| r.probe_ttl)
            .into_iter()
            .map(|(ttl, replies)| TracerouteHop {
                ttl,
                probes: replies
                    .map(|&reply| reply_to_pantrace_probe(reply))
                    .collect(),
            })
            .collect(),
    }
}

pub fn replies_to_pantrace_flows(replies: &[&Reply]) -> Vec<TracerouteFlow> {
    let replies_by_flow = get_replies_by_flow(replies);
    replies_by_flow
        .into_values()
        .map(|replies| generate_pantrace_traceroute_flow(&replies))
        .collect()
}

pub fn replies_to_single_pantrace_flow(replies: &[&Reply]) -> TracerouteFlow {
    generate_pantrace_traceroute_flow(replies)
}
