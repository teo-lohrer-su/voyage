use std::collections::HashMap;

use caracat::models::Reply;
use itertools::iproduct;

use crate::types::{Flow, Link, ReplyPair, TTL};

use std::collections::HashSet;

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
    if replies.is_empty() {
        return HashMap::new();
    }
    let (min_ttl, max_ttl) = (
        replies.iter().map(|r| r.probe_ttl).min().unwrap(),
        replies.iter().map(|r| r.probe_ttl).max().unwrap(),
    );
    // println!("min_ttl: {}, max_ttl: {}", min_ttl, max_ttl);
    let mut pairs_by_flow: HashMap<Flow, Vec<ReplyPair>> = HashMap::new();

    let replies_by_flow = get_replies_by_flow(replies);

    for (flow, flow_replies) in replies_by_flow {
        // for this flow, group replies by ttl
        // note that there may be missing ttl values
        // also note that there should be at most one reply per ttl (we are in a fixed flow)
        let ttl_replies = get_replies_by_ttl(flow_replies.as_slice());

        // maybe compute the min and max ttl over ALL flows?
        // let (min_ttl, max_ttl) = (
        //     *ttl_replies.keys().min().unwrap(),
        //     *ttl_replies.keys().max().unwrap(),
        // );
        // println!("min_ttl: {}, max_ttl: {}", min_ttl, max_ttl);

        // for each ttl (we consider the ttl to be the one for the near reply)
        for near_ttl in min_ttl..=max_ttl {
            let fetch_replies = |ttl| {
                ttl_replies
                    .get(&ttl)
                    .map(|replies| replies.iter().map(|&reply| Some(reply)).collect::<Vec<_>>())
                    .unwrap_or(vec![None])
            };
            // we fetch replies that match the ttl (and the flow)
            let near_replies = fetch_replies(near_ttl);
            // we fetch replies that match the ttl + 1 (and the flow)
            let far_replies = fetch_replies(near_ttl + 1);
            // since they share the same flow, and are one hop away, we conclude there is a link
            iproduct!(near_replies, far_replies).for_each(|replies| {
                // we only consider pairs where at least one reply is present
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

// pub(crate) fn get_links_by_ttl(replies: &[&Reply]) -> HashMap<TTL, HashSet<Link>> {
pub(crate) fn get_links_by_ttl(replies: &[&Reply]) -> HashMap<TTL, Vec<Link>> {
    // links are simply ReplyPairs with the near and far IPs
    // let mut links_by_ttl: HashMap<u8, HashSet<Link>> = HashMap::new();
    let mut links_by_ttl: HashMap<u8, Vec<Link>> = HashMap::new();
    let pairs_by_flow = get_pairs_by_flow(replies);

    // println!("pairs_by_flow: {:?}", pairs_by_flow);
    // println!("replies: {:?}", replies);

    for (_, pairs) in pairs_by_flow {
        for pair in pairs {
            let link = Link {
                ttl: pair.ttl,
                near_ip: pair.first_reply.map(|r| r.reply_src_addr),
                far_ip: pair.second_reply.map(|r| r.reply_src_addr),
            };

            // links_by_ttl.entry(pair.ttl).or_default().insert(link);
            links_by_ttl.entry(pair.ttl).or_default().push(link);
        }
    }

    links_by_ttl
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::helpers::{format_reply_pair, replies_eq, reply, reply_pair_eq};
    use std::iter::repeat;

    const IP: [&str; 10] = [
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

    #[test]
    fn test_get_replies_by_ttl() {
        let replies: Vec<Reply> = vec![
            reply(1, IP[0], IP[9]),
            reply(2, IP[1], IP[9]),
            reply(1, IP[2], IP[9]),
            reply(3, IP[3], IP[9]),
            reply(2, IP[4], IP[9]),
        ];

        let expected: HashMap<TTL, Vec<&Reply>> = [
            (1, vec![&replies[0], &replies[2]]),
            (2, vec![&replies[1], &replies[4]]),
            (3, vec![&replies[3]]),
        ]
        .into_iter()
        .collect();

        let replies_refs: Vec<&Reply> = replies.iter().collect();

        let result = get_replies_by_ttl(&replies_refs);

        assert_eq!(expected.len(), result.len());
        for (ttl, replies) in expected {
            assert!(result.contains_key(&ttl));
            assert!(replies_eq(&replies, &result[&ttl]));
        }
    }

    #[test]
    fn test_get_replies_by_flow() {
        let replies: Vec<Reply> = vec![
            reply(1, IP[0], IP[9]),
            reply(2, IP[1], IP[8]),
            reply(1, IP[2], IP[9]),
            reply(3, IP[3], IP[8]),
            reply(2, IP[4], IP[9]),
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

        let result = get_replies_by_flow(&replies_refs);

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
            reply(1, IP[0], IP[9]),
            reply(2, IP[1], IP[8]),
            reply(1, IP[2], IP[9]),
            reply(3, IP[3], IP[8]),
            reply(2, IP[4], IP[9]),
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
                        ttl: 1,
                        first_reply: None,
                        second_reply: Some(&replies[1]),
                    },
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

        let result = get_pairs_by_flow(&replies_refs);

        assert_eq!(expected.len(), result.len());
        for (flow, pairs) in expected {
            assert!(result.contains_key(&flow));
            assert_eq!(
                pairs.len(),
                result[&flow].len(),
                "flow: {:?}, \npairs: {} \nresult_pairs: {}",
                flow,
                pairs
                    .iter()
                    .map(format_reply_pair)
                    .collect::<Vec<_>>()
                    .iter()
                    .zip(repeat("\n"))
                    .map(|(a, b)| a.to_owned() + b)
                    .collect::<String>(),
                result[&flow]
                    .iter()
                    .map(format_reply_pair)
                    .collect::<Vec<_>>()
                    .iter()
                    .zip(repeat(&"\n".to_owned()))
                    .map(|(a, b)| a.to_owned() + b)
                    .collect::<String>()
            );
            for pair in pairs {
                assert!(
                    result[&flow].iter().any(|p| { reply_pair_eq(&pair, p) }),
                    "pair not found: {:?}\n\nresult_pairs: {:?}",
                    format_reply_pair(&pair),
                    result[&flow].iter().map(format_reply_pair)
                );
            }
        }
    }
}
