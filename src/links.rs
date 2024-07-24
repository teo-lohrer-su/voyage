use std::collections::HashMap;

use caracat::models::Reply;
use itertools::iproduct;

use crate::types::{Flow, Link, ReplyPair, TTL};

use std::collections::HashSet;

// pub(crate) fn get_replies_by_ttl(replies: Vec<&Reply>) -> HashMap<TTL, Vec<&Reply>> {
// pub(crate) fn get_replies_by_ttl<'a>(replies: &[&'a Reply]) -> HashMap<TTL, Vec<&'a Reply>> {
pub(crate) fn get_replies_by_ttl<'a>(replies: &[&'a Reply]) -> HashMap<TTL, Vec<&'a Reply>> {
    replies.iter().fold(HashMap::new(), |mut acc, r| {
        acc.entry(r.probe_ttl).or_default().push(r);
        acc
    })
}

pub(crate) fn get_replies_by_flow<'a>(replies: &[&'a Reply]) -> HashMap<Flow, Vec<&'a Reply>> {
    replies.iter().fold(HashMap::new(), |mut acc, &r| {
        acc.entry(r.into()).or_default().push(r);
        acc
    })
}

fn get_pairs_by_flow<'a>(replies: &[&'a Reply]) -> HashMap<Flow, Vec<ReplyPair<'a>>> {
    // fn get_pairs_by_flow<'a>(replies: Vec<&'a Reply>) -> HashMap<Flow, Vec<ReplyPair<'a>>> {
    let mut pairs_by_flow: HashMap<Flow, Vec<ReplyPair>> = HashMap::new();

    let replies_by_flow = get_replies_by_flow(replies);

    for (flow, flow_replies) in replies_by_flow {
        let ttl_replies = get_replies_by_ttl(flow_replies.as_slice());

        let (min_ttl, max_ttl) = (
            *ttl_replies.keys().min().unwrap(),
            *ttl_replies.keys().max().unwrap(),
        );
        for near_ttl in min_ttl..=max_ttl {
            let fetch_replies = |ttl| {
                ttl_replies
                    .get(&ttl)
                    .map(|replies| replies.iter().map(|&reply| Some(reply)).collect::<Vec<_>>())
                    .unwrap_or(vec![None])
            };
            let near_replies = fetch_replies(near_ttl);
            let far_replies = fetch_replies(near_ttl + 1);
            iproduct!(near_replies, far_replies).for_each(|replies| {
                if replies.0.is_some() || replies.1.is_some() {
                    let pair = ReplyPair {
                        ttl: near_ttl,
                        first_reply: replies.0,
                        second_reply: replies.1,
                    };
                    pairs_by_flow.entry(flow).or_default().push(pair);
                }
            })
        }
    }
    pairs_by_flow
}

pub(crate) fn _get_pairs_by_flow<'a>(replies: &[&'a Reply]) -> HashMap<Flow, Vec<ReplyPair<'a>>> {
    let mut pairs_by_flow: HashMap<Flow, Vec<ReplyPair>> = HashMap::new();

    let replies_by_flow = get_replies_by_flow(replies);

    for (flow, flow_replies) in replies_by_flow {
        let replies_by_ttl = get_replies_by_ttl(&flow_replies[..]);
        let (min_ttl, max_ttl) = (
            *replies_by_ttl.keys().min().unwrap(),
            *replies_by_ttl.keys().max().unwrap(),
        );

        for near_ttl in min_ttl..=max_ttl {
            let fetch_replies = |ttl| {
                replies_by_ttl
                    .get(&ttl)
                    .map(|replies| replies.iter().map(|&reply| Some(reply)).collect::<Vec<_>>())
                    .unwrap_or(vec![None])
            };
            let near_replies = fetch_replies(near_ttl);
            let far_replies = fetch_replies(near_ttl + 1);
            iproduct!(near_replies, far_replies).for_each(|replies| {
                let pair = ReplyPair {
                    ttl: near_ttl,
                    first_reply: replies.0,
                    second_reply: replies.1,
                };
                pairs_by_flow.entry(flow).or_default().push(pair);
            })
        }
    }
    pairs_by_flow
}

pub(crate) fn get_links_by_ttl<'a>(replies: &[&'a Reply]) -> HashMap<TTL, HashSet<Link<'a>>> {
    let mut links_by_ttl: HashMap<u8, HashSet<Link>> = HashMap::new();
    let pairs_by_flow = get_pairs_by_flow(replies);

    for (_, pairs) in pairs_by_flow {
        for pair in pairs {
            let link = Link {
                ttl: pair.ttl,
                near_ip: pair.first_reply.map(|r| &r.reply_src_addr),
                far_ip: pair.second_reply.map(|r| &r.reply_src_addr),
            };

            links_by_ttl.entry(pair.ttl).or_default().insert(link);
        }
    }

    links_by_ttl
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    const IPS: [&str; 10] = [
        "192.168.0.2",
        "192.168.0.3",
        "192.168.0.4",
        "192.168.0.5",
        "192.168.0.6",
        "192.168.0.7",
        "192.168.0.8",
        "192.168.0.9",
        "192.168.0.10",
        "192.168.0.11",
    ];

    // since Reply does not implement PartialEq, we need to compare the fields manually
    fn reply_eq(r1: &Reply, r2: &Reply) -> bool {
        r1.probe_ttl == r2.probe_ttl
            && r1.reply_src_addr == r2.reply_src_addr
            && r1.reply_dst_addr == r2.reply_dst_addr
            && r1.reply_protocol == r2.reply_protocol
        // && r1.to_string() == r2.to_string()
    }

    fn replies_eq(replies1: &[&Reply], replies2: &[&Reply]) -> bool {
        // order insensitive
        replies1.len() == replies2.len()
            && replies1
                .iter()
                .all(|r1| replies2.iter().any(|r2| reply_eq(r1, r2)))
    }

    fn reply_pair_eq(pair1: &ReplyPair, pair2: &ReplyPair) -> bool {
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

    fn reply(probe_ttl: u8, reply_src_addr: &str, probe_dst_addr: &str) -> Reply {
        Reply {
            probe_ttl,
            reply_src_addr: IpAddr::from(reply_src_addr.parse::<Ipv4Addr>().unwrap()),
            probe_dst_addr: IpAddr::from(probe_dst_addr.parse::<Ipv4Addr>().unwrap()),
            probe_protocol: 1,
            ..Default::default()
        }
    }

    #[test]
    fn test_get_replies_by_ttl() {
        let replies: Vec<Reply> = vec![
            reply(1, IPS[0], IPS[9]),
            reply(2, IPS[1], IPS[9]),
            reply(1, IPS[2], IPS[9]),
            reply(3, IPS[3], IPS[9]),
            reply(2, IPS[4], IPS[9]),
        ];

        let expected: HashMap<TTL, Vec<&Reply>> = [
            (1, vec![&replies[0], &replies[2]]),
            (2, vec![&replies[1], &replies[4]]),
            (3, vec![&replies[3]]),
        ]
        .into_iter()
        .collect();

        let replies_refs: Vec<&Reply> = replies.iter().collect();

        let result = get_replies_by_ttl(&replies_refs[..]);

        assert_eq!(expected.len(), result.len());
        for (ttl, replies) in expected {
            assert!(result.contains_key(&ttl));
            assert!(replies_eq(&replies, &result[&ttl]));
        }
    }

    #[test]
    fn test_get_replies_by_flow() {
        let replies: Vec<Reply> = vec![
            reply(1, IPS[0], IPS[9]),
            reply(2, IPS[1], IPS[8]),
            reply(1, IPS[2], IPS[9]),
            reply(3, IPS[3], IPS[8]),
            reply(2, IPS[4], IPS[9]),
        ];

        let flow_1 = Flow::from(&replies[0]);
        let flow_2 = Flow::from(&replies[1]);

        let expected: HashMap<Flow, Vec<&Reply>> = [
            (flow_1, vec![&replies[0], &replies[2], &replies[4]]),
            (flow_2, vec![&replies[1], &replies[3]]),
        ]
        .into_iter()
        .collect();

        let replies_refs: Vec<&Reply> = replies.iter().collect();

        let result = get_replies_by_flow(&replies_refs[..]);

        assert_eq!(expected.len(), result.len());
        for (flow, replies) in expected {
            assert!(result.contains_key(&flow));
            assert!(replies_eq(&replies, &result[&flow]));
        }
    }

    #[test]
    fn test_get_pairs_by_flow() {
        // 0-4, 2-4, 1-3
        let replies: Vec<Reply> = vec![
            reply(1, IPS[0], IPS[9]),
            reply(2, IPS[1], IPS[8]),
            reply(1, IPS[2], IPS[9]),
            reply(3, IPS[3], IPS[8]),
            reply(2, IPS[4], IPS[9]),
        ];

        let flow_1 = Flow::from(&replies[0]);
        let flow_2 = Flow::from(&replies[1]);

        let expected: HashMap<Flow, Vec<ReplyPair>> = [
            (
                flow_1,
                vec![
                    ReplyPair {
                        ttl: 1,
                        first_reply: Some(&replies[0]),
                        second_reply: Some(&replies[4]),
                    },
                    ReplyPair {
                        ttl: 1,
                        first_reply: Some(&replies[2]),
                        second_reply: Some(&replies[4]),
                    },
                    ReplyPair {
                        ttl: 2,
                        first_reply: Some(&replies[4]),
                        second_reply: None,
                    },
                ],
            ),
            (
                flow_2,
                vec![
                    ReplyPair {
                        ttl: 2,
                        first_reply: Some(&replies[1]),
                        second_reply: Some(&replies[3]),
                    },
                    ReplyPair {
                        ttl: 3,
                        first_reply: Some(&replies[3]),
                        second_reply: None,
                    },
                ],
            ),
        ]
        .into_iter()
        .collect();

        let replies_refs: Vec<&Reply> = replies.iter().collect();

        let result = get_pairs_by_flow(&replies_refs[..]);

        assert_eq!(expected.len(), result.len());
        for (flow, pairs) in expected {
            assert!(result.contains_key(&flow));
            assert_eq!(
                pairs.len(),
                result[&flow].len(),
                "flow: {:?}, \npairs: {:?} \nresult_pairs: {:?}",
                flow,
                pairs,
                result[&flow]
            );
            for pair in pairs {
                assert!(
                    result[&flow].iter().any(|p| { reply_pair_eq(&pair, p) }),
                    "pair not found: {:?}\n\nresult_pairs: {:?}",
                    pair,
                    result[&flow]
                );
            }
        }
    }
}
