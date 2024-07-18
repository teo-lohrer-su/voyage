mod probe_generator;
mod sequential_mapper;
mod types;

use caracat::models::{Probe, Reply, L4};
use pnet::packet::ip;
pub use probe_generator::*;
pub use sequential_mapper::*;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::vec;

use crate::algorithms::utils::general_stopping_point;
use crate::links::get_links_by_ttl;
use crate::types::{Link, Port, TTL};

use super::utils::stopping_point;

// pub struct DiamondMiner<'a> {
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
    // replies_by_round: HashMap<u32, &'a [&'a Reply]>,
    // replies_by_round: HashMap<u32, Vec<&'a Reply>>,
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
        confidence: u32,
        max_round: u32,
    ) -> Self { 
        let protocol = match (protocol, dst_addr) {
            (L4::ICMP, IpAddr::V4(_)) => L4::ICMP,
            (L4::ICMP, IpAddr::V6(_)) => L4::ICMPv6,
            (proto, _) => proto,
        };

        let failure_probability = 1.0 - (confidence as f64 / 100.0);

        Self {
            dst_addr,
            min_ttl,
            max_ttl,
            src_port,
            dst_port,
            protocol,
            max_round,
            failure_probability,
            mapper_v4: SequentialFlowMapper::new(1),
            mapper_v6: SequentialFlowMapper::new(1),
            current_round: 0,
            probes_sent: HashMap::new(),
            replies_by_round: HashMap::new(),
        }
    }

    fn links_by_ttl(&self) -> HashMap<TTL, HashSet<Link>> {
        get_links_by_ttl(self.time_exceeded_replies())
    }

    fn replies(&self) -> Vec<&Reply> {
        self.replies_by_round
            .values()
            .flat_map(|replies| replies.iter())
            .collect::<Vec<_>>()
    }

    fn time_exceeded_replies(&self) -> Vec<&Reply> {
        self.replies()
            .iter()
            .copied()
            .filter(|&r| r.is_time_exceeded())
            .collect::<Vec<_>>()
    }

    fn nodes_distribution_at_ttl<'a>(
        &self,
        nodes: Vec<&'a IpAddr>,
        ttl: u8,
    ) -> HashMap<&'a IpAddr, f64> {
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

        let link_dist: HashMap<&IpAddr, usize> = nodes
            .iter()
            .map(|&node| (node, node_replies(&self.replies(), *node, ttl)))
            .collect();

        let total: usize = link_dist.values().sum();
        let link_dist: HashMap<&IpAddr, f64> = if total > 0 {
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

    pub fn next_round(&mut self, replies: Vec<Reply>) -> Vec<Probe> {
        self.current_round += 1;
        self.replies_by_round.insert(self.current_round, replies);

        if self.current_round >= self.max_round {
            return vec![];
        }

        println!("links_by_ttl: {:?}", self.links_by_ttl());
        println!("probes_sent: {:?}", self.probes_sent);

        let flows_by_ttl: HashMap<_, _> = if self.current_round == 1 {
            println!("First round");
            let max_flow = 1;
            (self.min_ttl..=self.max_ttl)
                .map(|ttl| (ttl, 0..max_flow))
                .collect()
        } else {
            self.links_by_ttl()
                .iter()
                .map(|(ttl, links)| {
                    // let max_flow = stopping_point(links.len(), self.failure_probability);
                    let max_flow =
                        general_stopping_point(links.len() + 1, self.failure_probability);
                    println!("TTL: {}, max_flow: {}", ttl, max_flow);
                    let start_flow = *self.probes_sent.get(ttl).unwrap_or(&0);
                    (*ttl, start_flow..max_flow)
                })
                .collect()
        };

        println!("current_round: {}", self.current_round);
        println!("Flows by TTL: {:?}", flows_by_ttl);

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

        probes
    }
}
