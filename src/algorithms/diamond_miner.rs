mod probe_generator;
mod sequential_mapper;
mod types;

use caracat::models::{Probe, Reply, L4};
use itertools::Itertools;
use log::{debug, warn};
// use log::debug;
pub use sequential_mapper::*;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::ops::Range;
use std::vec;

use crate::algorithms::utils::stopping_point;
use crate::links::get_links_by_ttl;
use crate::types::{Link, Port, TTL};

use super::utils::{estimate_total_interfaces, LIKELIHOOD_THRESHOLD};

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
            // mapper_v4: SequentialFlowMapper::new(1),
            mapper_v6: SequentialFlowMapper::new(DEFAULT_PREFIX_SIZE_V6),
            // mapper_v6: SequentialFlowMapper::new(1),
            current_round: 0,
            probes_sent: HashMap::new(),
            replies_by_round: HashMap::new(),
        }
    }

    // pub fn links_by_ttl(&self) -> HashMap<TTL, Vec<Link>> {
    //     get_links_by_ttl(&self.time_exceeded_replies())
    // }

    // echo replies and destination unreachable replies should count towards successors counts
    pub fn links_by_ttl(&self) -> HashMap<TTL, Vec<Link>> {
        get_links_by_ttl(&self.replies())
        // get_links_by_ttl(&self.time_exceeded_replies())
    }

    pub fn n_links_by_ttl(&self) -> HashMap<TTL, usize> {
        self.links_by_ttl()
            .iter()
            .map(|(&k, v)| (k, v.len()))
            .collect()
    }

    pub fn replies(&self) -> Vec<&Reply> {
        self.replies_by_round
            .values()
            .flat_map(|replies| replies.iter())
            .collect::<Vec<_>>()
    }

    pub fn time_exceeded_replies(&self) -> Vec<&Reply> {
        self.replies()
            .into_iter()
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

    pub fn unresolved_nodes_at_ttl(
        &self,
        ttl: u8,
        estimate_successors: bool,
    ) -> (HashSet<IpAddr>, usize) {
        let nodes_at_ttl: HashSet<IpAddr> = self
            .replies()
            .iter()
            .filter(|&r| r.probe_ttl == ttl)
            .map(|r| r.reply_src_addr)
            .collect();

        let nodes_at_ttl: Vec<IpAddr> = nodes_at_ttl.into_iter().collect();

        let link_dist = self.nodes_distribution_at_ttl(&nodes_at_ttl, ttl);

        let mut unresolved_nodes = HashSet::new();
        let mut weighted_thresholds = Vec::new();

        for node in nodes_at_ttl {
            // if node == self.dst_addr {
            //     continue;
            // }
            // if the node is in the same subnet as the destination
            let prefix_length = (32 - (128 - self.mapper_v4.prefix_size.leading_zeros())) as u8;
            let dst_network =
                ip_network::IpNetwork::new_truncate(self.dst_addr, prefix_length).unwrap();

            if dst_network.contains(node) {
                continue;
            }

            // successors are nodes at the next TTL that share a link with the current node
            // or links where we do not know the near_ip, ie. the far node is a potential successor
            // ^ this is not true, we only consider links where we know the near_ip AND the far_ip
            let successors: HashSet<IpAddr> = self
                .links_by_ttl()
                .get(&ttl)
                .unwrap_or(&vec![])
                .iter()
                // .filter(|l| (l.near_ip == Some(node) && l.far_ip.is_some()) || l.near_ip.is_none())
                .filter(|l| l.near_ip == Some(node))
                .filter_map(|l| l.far_ip)
                .unique()
                .collect();

            let n_successors = successors.len();

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
                // .filter(|l| l.near_ip == Some(node))
                .count();

            if ttl == 4 || ttl == 5 || ttl == 6 {
                println!(
                    "[TTL {}]  {}: n_probes: {}, n_successors: {}, n_k: {}",
                    ttl, node, n_probes, n_successors, n_k
                );
            }

            // if a node has no successors, but is not the destination, it is unresolved
            if n_probes >= n_k || node == self.dst_addr {
                // node is resolved
                continue;
            }

            if n_probes < n_k && n_successors > 0 {
                // node is unresolved
                unresolved_nodes.insert(node);
                if estimate_successors {
                    let estimate = estimate_total_interfaces(n_k, n_probes, LIKELIHOOD_THRESHOLD);
                    let optimal_n_k = stopping_point(estimate, self.failure_probability);
                    if link_dist[&node] >= 0.001 {
                        weighted_thresholds
                            .push((n_k.max(optimal_n_k) as f64 / link_dist[&node]) as usize);
                    }
                } else {
                    if link_dist[&node] >= 0.001 {
                        weighted_thresholds.push((n_k as f64 / link_dist[&node]) as usize);
                        // weighted_thresholds.push(n_k as usize);
                    }
                }
            }
        }

        let max_weighted_threshold = weighted_thresholds.into_iter().max().unwrap_or(0);
        // let max_weighted_threshold = weighted_thresholds.into_iter().sum();

        debug!(
            "unresolved nodes at ttl {}: {:?}, max_weighted_threshold: {}",
            ttl, unresolved_nodes, max_weighted_threshold
        );

        (unresolved_nodes, max_weighted_threshold)
    }

    pub fn next_round(&mut self, replies: Vec<Reply>, estimate_successors: bool) -> Vec<Probe> {
        self.current_round += 1;
        self.replies_by_round.insert(self.current_round, replies);

        if self.current_round >= self.max_round {
            return vec![];
        }

        let mut max_flows_by_ttl = HashMap::new();

        if self.current_round == 1 {
            let max_flow = stopping_point(1, self.failure_probability);
            for ttl in self.min_ttl..=self.max_ttl {
                max_flows_by_ttl.insert(ttl, max_flow);
            }
        } else {
            for ttl in self.min_ttl..=self.max_ttl {
                let (_, max_flow) = self.unresolved_nodes_at_ttl(ttl, estimate_successors);
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
mod tests;
