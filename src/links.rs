use std::collections::HashMap;

use caracat::models::Reply;
use itertools::iproduct;

use crate::types::{Flow, Link, ReplyPair, TTL};

use std::collections::HashSet;

pub(crate) fn get_replies_by_ttl(replies: Vec<&Reply>) -> HashMap<TTL, Vec<&Reply>> {
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

// fn get_pairs_by_flow<'a>(replies: &'a [&'a Reply]) -> HashMap<Flow, Vec<ReplyPair<'a>>> {
fn get_pairs_by_flow<'a>(replies: Vec<&'a Reply>) -> HashMap<Flow, Vec<ReplyPair<'a>>> {
    let mut pairs_by_flow: HashMap<Flow, Vec<ReplyPair<'a>>> = HashMap::new();

    let replies_by_flow = get_replies_by_flow(&replies);

    for (flow, flow_replies) in replies_by_flow {
        let ttl_replies = get_replies_by_ttl(flow_replies);

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

pub(crate) fn _get_pairs_by_flow<'a>(replies: &'a [&'a Reply]) -> HashMap<Flow, Vec<ReplyPair>> {
    let mut pairs_by_flow: HashMap<Flow, Vec<ReplyPair>> = HashMap::new();

    let replies_by_flow = get_replies_by_flow(replies);

    for (flow, flow_replies) in replies_by_flow {
        let replies_by_ttl = get_replies_by_ttl(flow_replies);
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

pub(crate) fn get_links_by_ttl(replies: Vec<&Reply>) -> HashMap<TTL, HashSet<Link<'_>>> {
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

    #[test]
    fn test_get_replies_by_ttl() {
        let src_addr_str_1 = "192.168.0.2";
        let src_addr_str_2 = "192.168.0.3";
        let src_addr_1 = IpAddr::from(src_addr_str_1.parse::<Ipv4Addr>().unwrap());
        let src_addr_2 = IpAddr::from(src_addr_str_2.parse::<Ipv4Addr>().unwrap());

        let replies: Vec<Reply> = vec![
            Reply {
                probe_ttl: 1,
                reply_src_addr: src_addr_1,
                ..Default::default()
            },
            Reply {
                probe_ttl: 2,
                reply_src_addr: src_addr_1,
                ..Default::default()
            },
            Reply {
                probe_ttl: 1,
                reply_src_addr: src_addr_2,
                ..Default::default()
            },
            Reply {
                probe_ttl: 3,
                reply_src_addr: src_addr_1,
                ..Default::default()
            },
            Reply {
                probe_ttl: 2,
                reply_src_addr: src_addr_2,
                ..Default::default()
            },
        ];

        let expected: HashMap<TTL, Vec<&Reply>> = [
            (1, vec![&replies[0], &replies[2]]),
            (2, vec![&replies[1], &replies[4]]),
            (3, vec![&replies[3]]),
        ]
        .into_iter()
        .collect();

        let result = get_replies_by_ttl(replies.iter().collect());

        for (ttl, replies) in expected {
            assert_eq!(result.get(&ttl).unwrap().len(), replies.len());
            for reply in replies {
                assert!(result.get(&ttl).unwrap().iter().any(|r| {
                    r.probe_ttl == reply.probe_ttl
                        && r.reply_src_addr == reply.reply_src_addr
                        && r.reply_dst_addr == reply.reply_dst_addr
                        && r.reply_protocol == reply.reply_protocol
                }));
            }
        }
    }
}
