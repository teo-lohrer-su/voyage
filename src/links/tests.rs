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
