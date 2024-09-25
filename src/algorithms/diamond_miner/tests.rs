use itertools::Itertools;

use crate::helpers::reply;

use super::*;

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
const DEST: [&str; 10] = [
    "192.170.0.2",
    "192.170.0.3",
    "192.170.0.4",
    "192.170.0.5",
    "192.170.0.6",
    "192.170.0.7",
    "192.170.0.8",
    "192.170.0.9",
    "192.170.0.10",
    "192.170.0.11",
];

fn diamond_miner() -> DiamondMiner {
    DiamondMiner::new(
        IpAddr::V4(DEST[0].parse().unwrap()),
        1,
        20,
        24000,
        33434,
        L4::UDP,
        95.0,
        10,
    )
}

#[test]
fn test_nodes_distribution_at_ttl() {
    let mut miner = diamond_miner();
    let replies = vec![
        reply(1, IP[0], DEST[0]),
        reply(1, IP[1], DEST[0]),
        reply(2, IP[2], DEST[0]),
        reply(2, IP[2], DEST[0]),
        reply(2, IP[3], DEST[0]),
    ];
    miner.next_round(replies, false);

    let nodes = vec![
        IpAddr::V4(IP[0].parse().unwrap()),
        IpAddr::V4(IP[1].parse().unwrap()),
    ];
    let ttl = 1;

    let distribution = miner.nodes_distribution_at_ttl(&nodes, ttl);
    assert_eq!(distribution.len(), 2);
    assert_eq!(distribution[&nodes[0]], 0.5);
    assert_eq!(distribution[&nodes[1]], 0.5);

    let nodes = vec![
        IpAddr::V4(IP[2].parse().unwrap()),
        IpAddr::V4(IP[3].parse().unwrap()),
    ];
    let ttl = 2;

    let distribution = miner.nodes_distribution_at_ttl(&nodes, ttl);
    assert_eq!(distribution.len(), 2);
    assert!(distribution[&nodes[0]] > 0.66 && distribution[&nodes[0]] < 0.67);
    assert!(distribution[&nodes[1]] > 0.33 && distribution[&nodes[1]] < 0.34);
}

#[test]
fn test_unresolved_nodes_at_ttl_basic() {
    let mut miner = diamond_miner();
    // we start with two replies at TTLs 1 and 2
    // ---- [ IP[1] ] ---- [ IP[2] ] -.-.-.- [ DEST[0] ]
    let replies = vec![reply(1, IP[1], DEST[0]), reply(2, IP[2], DEST[0])];

    miner.next_round(replies, false);

    // at that point, both nodes are unresolved
    let expected_unresolved = [
        IpAddr::V4(IP[1].parse().unwrap()),
        IpAddr::V4(IP[2].parse().unwrap()),
    ];

    let links_by_ttl = miner.links_by_ttl();
    println!(">> miner.replies_by_round: {:?}", miner.replies_by_round);
    println!(">>links_by_ttl: {:?}", links_by_ttl);

    // we fetch the unresolved nodes at TTL 1
    let (unresolved_nodes, max_weighted_threshold) = miner.unresolved_nodes_at_ttl(1, false);

    // there should be only one unresolved node at TTL 1
    assert_eq!(
        unresolved_nodes.len(),
        1,
        "Unresolved nodes number. unresolved_nodes: {:?}, max_weighted_threshold: {}",
        unresolved_nodes,
        max_weighted_threshold
    );
    assert_eq!(max_weighted_threshold, 6, "Max weighted threshold");
    assert_eq!(
        unresolved_nodes.into_iter().next().unwrap(),
        expected_unresolved[0],
        "Unresolved nodes"
    );

    // we fetch the unresolved nodes at TTL 2
    let (unresolved_nodes, max_weighted_threshold) = miner.unresolved_nodes_at_ttl(2, false);

    // there should be only one unresolved node at TTL 2
    assert_eq!(
        unresolved_nodes.len(),
        1,
        "Unresolved nodes number. unresolved_nodes: {:?}",
        unresolved_nodes
    );
    assert_eq!(max_weighted_threshold, 1, "Max weighted threshold");
    assert_eq!(
        unresolved_nodes.into_iter().next().unwrap(),
        expected_unresolved[1],
        "Unresolved nodes"
    );
}

#[test]
fn test_unresolved_nodes_at_ttl_complex() {
    let mut miner = diamond_miner();
    let replies = vec![
        reply(1, IP[1], DEST[1]),
        reply(1, IP[1], DEST[2]),
        reply(1, IP[1], DEST[3]),
        reply(1, IP[1], DEST[4]),
        reply(1, IP[1], DEST[5]),
        reply(1, IP[1], DEST[6]),
        reply(2, IP[2], DEST[1]),
        reply(2, IP[2], DEST[2]),
        reply(2, IP[2], DEST[3]),
        reply(2, IP[2], DEST[4]),
        reply(2, IP[3], DEST[5]),
        reply(2, IP[3], DEST[6]),
    ];

    miner.next_round(replies, false);

    let links_by_ttl = miner.links_by_ttl();

    println!(">>links_by_ttl: {:?}", links_by_ttl);

    let (unresolved_nodes, max_weighted_threshold) = miner.unresolved_nodes_at_ttl(1, false);

    assert_eq!(
        unresolved_nodes.len(),
        1,
        "Unresolved nodes number. unresolved_nodes: {:?}",
        unresolved_nodes
    );
    assert_eq!(max_weighted_threshold, 11, "Max weighted threshold");
    assert_eq!(
        unresolved_nodes.into_iter().next().unwrap(),
        IpAddr::V4(IP[1].parse().unwrap()),
        "Unresolved nodes"
    );
}

#[test]
fn test_unresolved_nodes_at_ttl_missing_link() {
    let mut miner = diamond_miner();
    // we setup a scenario where IP[1] responded for 6 different flows at TTL 1
    // and IP[2] responded for 6 different flows at TTL 2
    // but IP[3] only responded for a single flow at TTL 2
    // we should have IP[1] as unresolved at TTL 1
    // since we do not know where the response from IP[3] went through
    // we have to hypothesize that IP[3] is a potential successor of IP[1]
    // ^^^ this is not true, we would need to hypothesize that all nodes
    // at ttl n+1 are connected to all nodes at ttl n
    let replies = vec![
        reply(1, IP[1], DEST[1]),
        reply(1, IP[1], DEST[2]),
        reply(1, IP[1], DEST[3]),
        reply(1, IP[1], DEST[4]),
        reply(1, IP[1], DEST[5]),
        reply(1, IP[1], DEST[6]),
        //
        reply(2, IP[2], DEST[1]),
        reply(2, IP[2], DEST[2]),
        reply(2, IP[2], DEST[3]),
        reply(2, IP[2], DEST[4]),
        reply(2, IP[2], DEST[5]),
        reply(2, IP[2], DEST[6]),
        //
        reply(2, IP[3], DEST[7]),
    ];

    miner.next_round(replies, false);

    let links_by_ttl = miner.links_by_ttl();

    println!(">>links_by_ttl: {:?}", links_by_ttl);

    let (unresolved_nodes, max_weighted_threshold) = miner.unresolved_nodes_at_ttl(1, false);

    assert_eq!(
        unresolved_nodes.len(),
        // 1,
        0,
        "Unresolved nodes number. unresolved_nodes: {:?}",
        unresolved_nodes
    );
    assert_eq!(max_weighted_threshold, 0, "Max weighted threshold");
}

fn probes_to_count(probes: Vec<Probe>) -> HashMap<TTL, usize> {
    probes
        .iter()
        .group_by(|p| p.ttl)
        .into_iter()
        .map(|(k, v)| (k, v.count()))
        .collect()
}

#[test]
fn test_next_round() {
    let mut miner = diamond_miner();
    miner.dst_addr = IpAddr::V4(DEST[0].parse().unwrap());
    miner.min_ttl = 1;
    miner.max_ttl = 4;

    let replies = vec![];

    let probes = miner.next_round(replies, false);

    assert_eq!(probes.len(), 6 * 4);
    assert_eq!(
        probes_to_count(probes),
        HashMap::from([(1, 6), (2, 6), (3, 6), (4, 6)])
    );

    let replies = vec![
        reply(1, IP[1], DEST[1]),
        reply(1, IP[1], DEST[2]),
        reply(1, IP[1], DEST[3]),
        reply(1, IP[1], DEST[4]),
        reply(1, IP[1], DEST[5]),
        reply(1, IP[1], DEST[6]),
        //
        // IP[1] is resolved
        //
        reply(2, IP[2], DEST[1]),
        reply(2, IP[2], DEST[2]),
        reply(2, IP[2], DEST[3]),
        reply(2, IP[2], DEST[4]),
        reply(2, IP[2], DEST[5]),
        reply(2, IP[2], DEST[6]),
        //
        // IP[2] has two successors and six links
        // IP[2] is not resolved
        // IP[2] requires 11 outgoing links
        // IP[2] is reached by 100% of probes at TTL 2
        // IP[2] requires 11 probes at TTL 2 and 11 probes at TTL 3 in total
        //
        reply(3, IP[3], DEST[1]),
        reply(3, IP[3], DEST[2]),
        //
        // IP[3] has one successor and two links
        // IP[3] is not resolved
        // IP[3] requires 6 outgoing links
        // IP[3] is reached 1/3 of probes at TTL 3
        // IP[3] requires 18 probes at TTL 3 and 18 probes at TTL 4 in total
        //
        reply(3, IP[4], DEST[3]),
        reply(3, IP[4], DEST[4]),
        reply(3, IP[4], DEST[5]),
        reply(3, IP[4], DEST[6]),
        //
        // IP[4] has one successor and four links
        // IP[4] is not resolved
        // IP[4] requires 6 outgoing links
        // IP[4] is reached by 2/3 of probes at TTL 3
        // IP[4] requires  9 probes at TTL 3 and 9 probes at TTL 4 in total
        //
        reply(4, IP[5], DEST[1]),
        reply(4, IP[5], DEST[2]),
        reply(4, IP[5], DEST[3]),
        reply(4, IP[5], DEST[4]),
        reply(4, IP[5], DEST[5]),
        reply(4, IP[5], DEST[6]),
        //
        // IP[5] has a single successor and six links
        // IP[5] is resolved
        //
        reply(5, DEST[0], DEST[1]),
        reply(5, DEST[0], DEST[2]),
        reply(5, DEST[0], DEST[3]),
        reply(5, DEST[0], DEST[4]),
        reply(5, DEST[0], DEST[5]),
        reply(5, DEST[0], DEST[6]),
        //
        // DEST[0] is the destination
        // DEST[0] is resolved
    ];

    // In total, we need 11 probes in total at TTL 2, 18 at TTLs 3 and 4
    // We already sent 6 probes at every TTL

    let probes = miner.next_round(replies, false);

    assert_eq!(probes.len(), (11 - 6) + (18 - 6) + (18 - 6)); // 29
    assert_eq!(
        probes_to_count(probes),
        HashMap::from([(2, 11 - 6), (3, 18 - 6), (4, 18 - 6)])
    );
}
