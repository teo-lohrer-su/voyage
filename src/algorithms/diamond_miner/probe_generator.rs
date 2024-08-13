use ip_network::IpNetwork;
use itertools::iproduct;
use rand::{rngs::SmallRng, seq::SliceRandom, SeedableRng};
use std::net::Ipv6Addr;

use caracat::models::Probe;
use caracat::models::L4;

use super::sequential_mapper::SequentialFlowMapper;
use super::types::FlowId;
use super::DEFAULT_PREFIX_LEN_V4;
use super::DEFAULT_PREFIX_LEN_V6;
use super::DEFAULT_PROBE_DST_PORT;
use super::DEFAULT_PROBE_SRC_PORT;

#[derive(Debug, Clone)]
struct Prefix<'a> {
    prefix: &'a str,
    protocol: L4,
}

pub struct ProbeGenerator<'a> {
    prefixes: Vec<Prefix<'a>>,
    flow_ids: Vec<u32>,
    ttls: Vec<u8>,
    prefix_len_v4: u8,
    prefix_len_v6: u8,
    probe_src_port: u16,
    probe_dst_port: u16,
    mapper_v4: SequentialFlowMapper,
    mapper_v6: SequentialFlowMapper,
    seed: u64,
}

impl<'a> Default for ProbeGenerator<'a> {
    fn default() -> Self {
        Self {
            prefixes: Default::default(),
            flow_ids: Default::default(),
            ttls: Default::default(),
            prefix_len_v4: DEFAULT_PREFIX_LEN_V4,
            prefix_len_v6: DEFAULT_PREFIX_LEN_V6,
            probe_src_port: DEFAULT_PROBE_SRC_PORT,
            probe_dst_port: DEFAULT_PROBE_DST_PORT,
            mapper_v4: Default::default(),
            mapper_v6: Default::default(),
            seed: Default::default(),
        }
    }
}

impl<'a> IntoIterator for ProbeGenerator<'a> {
    type Item = Probe;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let extended_prefixes = self.prefixes.iter().flat_map(|a| {
            split_prefix(a.prefix, self.prefix_len_v4, self.prefix_len_v6)
                .iter()
                .map(|&(af, subprefix, subprefix_size)| (af, subprefix, subprefix_size, a.protocol))
                .collect::<Vec<_>>()
        });

        let mut grid: Vec<_> = iproduct!(extended_prefixes, self.ttls, self.flow_ids).collect();

        let mut rng = SmallRng::seed_from_u64(self.seed);
        grid.shuffle(&mut rng);

        let res = grid.iter().map(
            |&((af, subprefix, _subprefix_size, protocol), ttl, flow_id)| -> Probe {
                let mapper = match af {
                    4 => &self.mapper_v4,
                    6 => &self.mapper_v6,
                    _ => panic!("Invalid IP version"),
                };

                let (addr_offset, port_offset) = mapper.offset(flow_id as FlowId);

                Probe {
                    dst_addr: Ipv6Addr::from(
                        (u128::from_be_bytes(subprefix.octets()) + addr_offset).to_be_bytes(),
                    )
                    .into(),
                    src_port: self.probe_src_port + (port_offset as u16),
                    dst_port: self.probe_dst_port,
                    ttl,
                    protocol,
                }
            },
        );
        res.collect::<Vec<_>>().into_iter()
    }
}

fn split_prefix(
    prefix: &str,
    prefix_len_v4: u8,
    prefix_len_v6: u8,
) -> std::vec::Vec<(i32, std::net::Ipv6Addr, u128)> {
    let network: IpNetwork = prefix.parse().unwrap();

    match network {
        IpNetwork::V4(net) => {
            if net.netmask() == prefix_len_v4 {
                return vec![(
                    4,
                    net.network_address().to_ipv6_mapped(),
                    1 << (32 - prefix_len_v4),
                )];
            }
        }
        IpNetwork::V6(net) => {
            if net.netmask() == prefix_len_v6 {
                return vec![(6, net.network_address(), 1 << (128 - prefix_len_v6))];
            }
        }
    };

    let res = match network {
        IpNetwork::V4(net) => net
            .subnets_with_prefix(prefix_len_v4)
            .map(|subnet| {
                (
                    4,
                    subnet.network_address().to_ipv6_mapped(),
                    1 << (32 - prefix_len_v4),
                )
            })
            .collect::<Vec<_>>(),
        IpNetwork::V6(net) => net
            .subnets_with_prefix(prefix_len_v6)
            .map(|subnet| (6, subnet.network_address(), 1 << (128 - prefix_len_v6)))
            .collect::<Vec<_>>(),
    };
    assert!(!res.is_empty());
    res
}

#[cfg(test)]
mod tests;
