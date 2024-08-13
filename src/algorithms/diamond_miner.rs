mod probe_generator;
mod sequential_mapper;
mod types;

use caracat::models::{Probe, Reply, L4};
pub use sequential_mapper::*;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::ops::Range;
use std::vec;

use crate::algorithms::utils::stopping_point;
use crate::links::get_links_by_ttl;
use crate::types::{Link, Port, TTL};

pub struct DiamondMiner {
    // Configuration parameters dst_addr: IpAddr,
    dst_addr: IpAddr,
    min_ttl: TTL,
    max_ttl: TTL,
    src_port: Port,
    dst_port: Port,
    protocol: L4,

    // Internal state
    failure_probability: f64,
    mapper_v4: SequentialFlowMapper,
    mapper_v6: SequentialFlowMapper,
    max_round: u32,
    current_round: u32,
    probes_sent: HashMap<TTL, usize>,
    replies_by_round: HashMap<u32, Vec<Reply>>,
}

// impl<'a> DiamondMiner<'a> {
#[allow(clippy::too_many_arguments)]
impl DiamondMiner {
    pub fn new(
        dst_addr: IpAddr,
        min_ttl: TTL,
        max_ttl: TTL,
        src_port: Port,
        dst_port: Port,
        protocol: L4,
        confidence: f64,
        max_round: u32,
    ) -> Self {
        let protocol = match (protocol, dst_addr) {
            (L4::ICMP, IpAddr::V4(_)) => L4::ICMP,
            (L4::ICMP, IpAddr::V6(_)) => L4::ICMPv6,
            (proto, _) => proto,
        };

        let failure_probability = 1.0 - confidence / 100.0;

        Self {
            dst_addr,
            min_ttl,
            max_ttl,
            src_port,
            dst_port,
            protocol,
            max_round,
            failure_probability,
            mapper_v4: SequentialFlowMapper::new(DEFAULT_PREFIX_SIZE_V4),
            mapper_v6: SequentialFlowMapper::new(DEFAULT_PREFIX_SIZE_V6),
            current_round: 0,
            probes_sent: HashMap::new(),
            replies_by_round: HashMap::new(),
        }
    }

    pub fn links_by_ttl(&self) -> HashMap<TTL, Vec<Link>> {
        // get_links_by_ttl(&self.time_exceeded_replies())
        get_links_by_ttl(&self.replies())
    }

    pub fn n_links_by_ttl(&self) -> HashMap<TTL, usize> {
        self.links_by_ttl()
            .iter()
            .map(|(&k, v)| (k, v.len()))
            .collect()
    }

    fn replies(&self) -> Vec<&Reply> {
        self.replies_by_round
            .values()
            .flat_map(|replies| replies.iter())
            .collect::<Vec<_>>()
    }

    pub fn time_exceeded_replies(&self) -> Vec<&Reply> {
        self.replies()
            .into_iter()
            // .copied()
            .filter(|&r| r.is_time_exceeded())
            .collect::<Vec<_>>()
    }

    fn nodes_distribution_at_ttl(&self, nodes: &[IpAddr], ttl: u8) -> HashMap<IpAddr, f64> {
        // TODO: check this code
        // a routine to fetch the number of replies from a given node at a given TTL
        // NOTE: a node may appear at multiple TTLs
        fn node_replies(replies: &[&Reply], node: IpAddr, ttl: u8) -> usize {
            replies
                .iter()
                .filter(|r| r.reply_src_addr == node && r.probe_ttl == ttl)
                .count()
        }

        // total number of observations of links reaching nodes at the current ttl.
        // since links are stored with the 'near_ttl',
        // we need to fetch them at ttl-1

        let link_dist: HashMap<IpAddr, usize> = nodes
            .iter()
            .map(|&node| (node, node_replies(&self.replies(), node, ttl)))
            .collect();

        let total: usize = link_dist.values().sum();
        let link_dist: HashMap<IpAddr, f64> = if total > 0 {
            link_dist
                .into_iter()
                .map(|(k, v)| (k, v as f64 / total as f64))
                .collect()
        } else {
            // if we did not observe links at the previous ttl
            // we won't apply weights to the n_k afterwards
            nodes
                .iter()
                .map(|&node| (node, 1.0 / nodes.len() as f64))
                .collect()
        };

        link_dist
    }

    pub fn unresolved_nodes_at_ttl(&self, ttl: u8) -> (HashSet<IpAddr>, usize) {
        let nodes_at_ttl: HashSet<IpAddr> = self
            .replies()
            .iter()
            .filter(|&r| r.probe_ttl == ttl)
            .map(|r| r.reply_src_addr)
            .collect();

        // if nodes_at_ttl.is_empty() {
        //     println!("No nodes at TTL {}", ttl);
        // }

        let nodes_at_ttl: Vec<IpAddr> = nodes_at_ttl.into_iter().collect();

        // let nodes_at_ttl: Vec<&IpAddr> = nodes_at_ttl.iter().collect();

        let link_dist = self.nodes_distribution_at_ttl(&nodes_at_ttl, ttl);

        // println!("   link_dist: {:?}", link_dist);

        let mut unresolved_nodes = HashSet::new();
        let mut weighted_thresholds = Vec::new();

        for node in nodes_at_ttl {
            if node == self.dst_addr {
                continue;
            }

            // successors are nodes at the next TTL that share a link with the current node
            // or links where we do not know the near_ip, ie. the far node is a potential successor
            let successors: HashSet<IpAddr> = self
                .links_by_ttl()
                .get(&ttl)
                // .unwrap_or(&HashSet::new())
                .unwrap_or(&vec![])
                .iter()
                // .filter(|l| (l.near_ip == Some(node) || l.near_ip.is_none()) && l.far_ip.is_some())
                .filter(|l| (l.near_ip == Some(node) && l.far_ip.is_some()) || l.near_ip.is_none())
                .map(|l| l.far_ip.unwrap())
                .collect();

            let n_successors = successors.len();

            // if n_successors == 0 && node != self.dst_addr {
            //     println!(
            //         "Node {} at TTL {} has no successors at TTL {}",
            //         node,
            //         ttl,
            //         ttl + 1
            //     );
            //     println!(
            //         "Its stopping point is {}",
            //         stopping_point(0, self.failure_probability)
            //     );
            // } else {
            //     println!(
            //         "Node {} at TTL {} has {} successors at TTL {}: {:?}",
            //         node,
            //         ttl,
            //         n_successors,
            //         ttl + 1,
            //         successors
            //     );
            //     println!(
            //         "links at TTL {}: {:?}",
            //         ttl,
            //         self.links_by_ttl()
            //             .get(&ttl)
            //             .unwrap()
            //             .iter()
            //             .map(|l| (l.near_ip, l.far_ip))
            //             .collect::<Vec<_>>()
            //     );
            //     println!(
            //         "links at next TTL {}: {:?}",
            //         ttl + 1,
            //         self.links_by_ttl()
            //             .get(&(ttl + 1))
            //             // .unwrap_or(&HashSet::new())
            //             .unwrap_or(&vec![])
            //             .iter()
            //             .map(|l| (l.near_ip, l.far_ip))
            //             .collect::<Vec<_>>()
            //     );
            // }

            let n_k = stopping_point(n_successors, self.failure_probability);

            // number of probes that went THROUGH the node
            // ie. the number of outgoing links from the node
            // (remember that links are stored with the 'near_ttl')
            // we only keep links that have a near_ip AND a far_ip
            let n_probes = self
                .links_by_ttl()
                .get(&ttl)
                .unwrap_or(&vec![])
                .iter()
                .filter(|l| l.near_ip == Some(node) && l.far_ip.is_some())
                .count();

            // if n_successors == 0 || n_probes >= n_k {
            // if a node has no successors, but is not the destination, it is unresolved
            if n_probes >= n_k || node == self.dst_addr {
                // node is resolved
                continue;
            }

            // if n_successors != 0 && n_probes < n_k {
            if n_probes < n_k {
                // node is unresolved
                unresolved_nodes.insert(node);
                weighted_thresholds.push((n_k as f64 / link_dist[&node]) as usize);
                // println!(
                //     "Node {} at TTL {} is unresolved with n_k = {} and n_probes = {}, and weighted threshold = {}",
                //     node, ttl, n_k, n_probes, (n_k as f64 / link_dist[&node]) as usize
                // );
            }
        }

        let max_weighted_threshold = weighted_thresholds.into_iter().max().unwrap_or(0);

        // if max_weighted_threshold == 0 && !unresolved_nodes.is_empty() {
        //     println!("!!!!!!!!!!!!!!!!!!!!");
        //     println!("!!!!!!!!!!!!!!!!!!!!");
        //     println!("{} unresolved nodes at TTL {}", unresolved_nodes.len(), ttl);
        //     println!("but max_weighted_threshold is 0");
        //     println!("!!!!!!!!!!!!!!!!!!!!");
        //     println!("!!!!!!!!!!!!!!!!!!!!");
        // }

        (unresolved_nodes, max_weighted_threshold)
    }

    pub fn next_round(&mut self, replies: Vec<Reply>) -> Vec<Probe> {
        self.current_round += 1;
        self.replies_by_round.insert(self.current_round, replies);

        if self.current_round >= self.max_round {
            return vec![];
        }

        // println!("links_by_ttl: {:?}", self.links_by_ttl());
        // println!("probes_sent: {:?}", self.probes_sent);

        let mut max_flows_by_ttl = HashMap::new();

        if self.current_round == 1 {
            let max_flow = stopping_point(1, self.failure_probability);
            for ttl in self.min_ttl..=self.max_ttl {
                max_flows_by_ttl.insert(ttl, max_flow);
            }
        } else {
            for ttl in self.min_ttl..=self.max_ttl {
                let (unresolved_nodes, max_flow) = self.unresolved_nodes_at_ttl(ttl);
                // println!("Unresolved nodes at TTL {}: {:?}", ttl, unresolved_nodes);
                max_flows_by_ttl.insert(ttl, max_flow);
            }
        }

        let flows_by_ttl: HashMap<TTL, Range<usize>> = max_flows_by_ttl
            .iter()
            .map(|(&ttl, &max_flow)| {
                let combined_max_flow = if ttl < self.min_ttl || ttl > self.max_ttl {
                    1
                } else {
                    let previous_max =
                        *max_flows_by_ttl.get(&(ttl.saturating_sub(1))).unwrap_or(&1);
                    previous_max.max(max_flow)
                };
                let sent_probes = *self.probes_sent.get(&ttl).unwrap_or(&0);
                (ttl, sent_probes..combined_max_flow)
            })
            .collect();

        // println!("current_round: {}", self.current_round);
        // println!("Flows by TTL: {:?}", flows_by_ttl);

        let mut probes = vec![];

        for (ttl, flow_range) in flows_by_ttl {
            for flow_id in flow_range {
                match self.dst_addr {
                    IpAddr::V4(_) => {
                        let (ip_offset, port_offset) = self.mapper_v4.offset(flow_id as u128);

                        let new_dst_addr: IpAddr = match self.dst_addr {
                            IpAddr::V4(addr) => {
                                let ip_offset = ip_offset as u32;
                                let addr = u32::from(addr);
                                let new_addr = addr + 2 * ip_offset;
                                IpAddr::V4(new_addr.into())
                            }
                            IpAddr::V6(addr) => {
                                let addr = u128::from(addr);
                                let new_addr = addr + 2 * ip_offset;
                                IpAddr::V6(new_addr.into())
                            }
                        };

                        assert!(self.current_round == 1 || ip_offset > 0 || port_offset > 0);

                        let probe = Probe {
                            dst_addr: new_dst_addr,
                            src_port: self.src_port + (port_offset as u16),
                            dst_port: self.dst_port,
                            protocol: self.protocol,
                            ttl,
                        };
                        probes.push(probe);
                    }
                    IpAddr::V6(_) => {
                        let (ip_offset, port_offset) = self.mapper_v6.offset(flow_id as u128);

                        let new_dst_addr: IpAddr = match self.dst_addr {
                            IpAddr::V4(addr) => {
                                let ip_offset = ip_offset as u32;
                                let addr = u32::from(addr);
                                let new_addr = addr + ip_offset;
                                IpAddr::V4(new_addr.into())
                            }
                            IpAddr::V6(addr) => {
                                let addr = u128::from(addr);
                                let new_addr = addr + ip_offset;
                                IpAddr::V6(new_addr.into())
                            }
                        };

                        let probe = Probe {
                            dst_addr: new_dst_addr,
                            src_port: self.src_port + (port_offset as u16),
                            dst_port: self.dst_port,
                            protocol: self.protocol,
                            ttl,
                        };
                        probes.push(probe);
                    }
                }
            }
        }

        for probe in &probes {
            *self.probes_sent.entry(probe.ttl).or_insert(0) += 1;
        }

        // assert all probes at a given TTL are unique
        for ttl in self.min_ttl..=self.max_ttl {
            let n_probes = probes.iter().filter(|p| p.ttl == ttl).count();
            let n_unique_probes = probes
                .iter()
                .filter(|p| p.ttl == ttl)
                .map(|p| (p.dst_addr, p.src_port))
                .collect::<HashSet<_>>()
                .len();
            assert_eq!(n_probes, n_unique_probes);
        }

        probes
    }
}

#[cfg(test)]
mod tests {
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
            IpAddr::V4(IP[0].parse().unwrap()),
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
        miner.next_round(replies);

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

        miner.next_round(replies);

        // at that point, both nodes are unresolved
        let expected_unresolved = [
            IpAddr::V4(IP[1].parse().unwrap()),
            IpAddr::V4(IP[2].parse().unwrap()),
        ];

        // let links_by_ttl = miner.links_by_ttl();
        // println!(">> miner.replies_by_round: {:?}", miner.replies_by_round);
        // println!(">>links_by_ttl: {:?}", links_by_ttl);

        // we fetch the unresolved nodes at TTL 1
        let (unresolved_nodes, max_weighted_threshold) = miner.unresolved_nodes_at_ttl(1);

        // there should be only one unresolved node at TTL 1
        assert_eq!(
            unresolved_nodes.len(),
            1,
            "Unresolved nodes number. unresolved_nodes: {:?}",
            unresolved_nodes
        );
        assert_eq!(max_weighted_threshold, 6, "Max weighted threshold");
        assert_eq!(
            unresolved_nodes.into_iter().next().unwrap(),
            expected_unresolved[0],
            "Unresolved nodes"
        );

        // we fetch the unresolved nodes at TTL 2
        let (unresolved_nodes, max_weighted_threshold) = miner.unresolved_nodes_at_ttl(2);

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

        miner.next_round(replies);

        let links_by_ttl = miner.links_by_ttl();

        println!(">>links_by_ttl: {:?}", links_by_ttl);

        let (unresolved_nodes, max_weighted_threshold) = miner.unresolved_nodes_at_ttl(1);

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

        miner.next_round(replies);

        let links_by_ttl = miner.links_by_ttl();

        println!(">>links_by_ttl: {:?}", links_by_ttl);

        let (unresolved_nodes, max_weighted_threshold) = miner.unresolved_nodes_at_ttl(1);

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

        let probes = miner.next_round(replies);

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
            // IP[2] is missing 5 additional links
            // IP[2] requires 5 additional probes at TTL 3
            //
            reply(3, IP[3], DEST[1]),
            reply(3, IP[3], DEST[2]),
            //
            // IP[3] has one successor and two links
            // IP[3] is not resolved
            // we should have 6 links between IP[3] and IPs at TTL 4
            // we need to send 6 probes in total to IP[3] at TTL 3 and 6 probes in total to IPs at TTL 4
            // for IP[3] we already sent 2 probes at TTL 3, 4 remain
            // but IP[3] is reached 1/3 of the time
            // so we need to send 12 probes to IP[3] at TTL 3
            // and we must send 12 probes in total to TTL 4
            // the objective is to manufacture enough outgoing links from IP[3]
            //
            reply(3, IP[4], DEST[3]),
            reply(3, IP[4], DEST[4]),
            reply(3, IP[4], DEST[5]),
            reply(3, IP[4], DEST[6]),
            //
            // IP[4] has one successor and four links
            // IP[4] is not resolved
            // IP[4] is missing 2 links and is reached 2/3 of the time
            // IP[4] requires 3 probes at TTL 4
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

        let probes = miner.next_round(replies);

        assert_eq!(probes.len(), (18 - 6) + (18 - 6) + (11 - 6)); // 29
        assert_eq!(
            probes_to_count(probes),
            HashMap::from([(2, 11 - 6), (3, 18 - 6), (4, 18 - 6)])
        );
    }
}
