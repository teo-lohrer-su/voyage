use std::collections::HashMap;

use caracat::models::Reply;
use itertools::iproduct;

use crate::types::{Flow, Link, ReplyPair, TTL};

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
    // let (min_ttl, max_ttl) = (
    //     replies.iter().map(|r| r.probe_ttl).min().unwrap(),
    //     replies.iter().map(|r| r.probe_ttl).max().unwrap(),
    // );
    // println!("min_ttl: {}, max_ttl: {}", min_ttl, max_ttl);
    let mut pairs_by_flow: HashMap<Flow, Vec<ReplyPair>> = HashMap::new();

    let replies_by_flow = get_replies_by_flow(replies);

    for (flow, flow_replies) in replies_by_flow {
        // for this flow, group replies by ttl
        // note that there may be missing ttl values
        // also note that there should be at most one reply per ttl (we are in a fixed flow)
        let ttl_replies = get_replies_by_ttl(flow_replies.as_slice());

        // maybe compute the min and max ttl over ALL flows?
        let (min_ttl, max_ttl) = (
            *ttl_replies.keys().min().unwrap(),
            *ttl_replies.keys().max().unwrap(),
        );
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
mod tests;
