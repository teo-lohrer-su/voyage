use std::{collections::HashSet, net::IpAddr};

use itertools::Itertools;

use super::*;

#[test]
fn test_probe_generator_128() {
    let prefixes = vec![Prefix {
        prefix: "2001:4860:4860::8888/128",
        protocol: L4::ICMP,
    }];
    let generator = ProbeGenerator {
        prefixes,
        flow_ids: vec![10, 11, 12],
        ttls: vec![41, 42],
        prefix_len_v6: 128,
        mapper_v6: SequentialFlowMapper::new(1),
        ..Default::default()
    };
    let probes = generator.into_iter().collect_vec();
    assert_eq!(probes.len(), 6);
    for probe in probes.iter() {
        assert_eq!(Ok(probe.dst_addr), "2001:4860:4860::8888".parse());
        assert!((24_010..24_013).contains(&probe.src_port));
        assert_eq!(probe.dst_port, 33_434);
        assert!((41..43).contains(&probe.ttl));
        assert_eq!(probe.protocol, L4::ICMP);
    }
}

#[test]
fn test_probe_generator_63() {
    let prefixes = vec![Prefix {
        prefix: "2001:4860:4860:0000::/63",
        protocol: L4::ICMP,
    }];
    let generator = ProbeGenerator {
        prefixes,
        flow_ids: vec![10],
        ttls: vec![41],
        prefix_len_v6: 64,
        mapper_v6: SequentialFlowMapper::new(1 << 64),
        ..Default::default()
    };

    let probes: Vec<_> = generator.into_iter().collect();
    assert_eq!(probes.len(), 2);
    assert_eq!(
        probes
            .iter()
            .map(|probe| probe.dst_addr)
            .collect::<HashSet<_>>()
            .len(),
        2
    );

    let expected_addr: Vec<Result<IpAddr, _>> =
        vec!["2001:4860:4860::a".parse(), "2001:4860:4860:1::a".parse()];
    for probe in probes {
        assert!(
            expected_addr.contains(&Ok(probe.dst_addr)),
            "{}",
            probe.dst_addr
        );
        assert_eq!(probe.src_port, 24_000);
        assert_eq!(probe.dst_port, 33_434);
        assert_eq!(probe.ttl, 41);
        assert_eq!(probe.protocol, L4::ICMP);
    }
}

#[test]
fn test_probe_generator_32() {
    let prefixes = vec![Prefix {
        prefix: "8.8.8.8/32",
        protocol: L4::UDP,
    }];
    let generator = ProbeGenerator {
        prefixes,
        flow_ids: vec![10, 11, 12],
        ttls: vec![41, 42],
        prefix_len_v4: 32,
        mapper_v4: SequentialFlowMapper::new(1),
        ..Default::default()
    };

    let probes: Vec<_> = generator.into_iter().collect();
    assert_eq!(probes.len(), 6);
    assert_eq!(
        probes
            .iter()
            .map(|p| format!("{}", p))
            .collect::<HashSet<_>>()
            .len(),
        6
    );

    for probe in probes {
        assert_eq!(Ok(probe.dst_addr), "::ffff:808:808".parse());
        assert!((24_010..24_013).contains(&probe.src_port));
        assert_eq!(probe.dst_port, 33_434);
        assert!((41..43).contains(&probe.ttl));
        assert_eq!(probe.protocol, L4::UDP);
    }
}

#[test]
fn test_probe_generator_23() {
    let prefixes = vec![Prefix {
        prefix: "0.0.0.0/23",
        protocol: L4::UDP,
    }];
    let generator = ProbeGenerator {
        prefixes,
        flow_ids: vec![10],
        ttls: vec![41],
        prefix_len_v4: 24,
        mapper_v4: SequentialFlowMapper::new(1 << 8),
        ..Default::default()
    };

    let probes: Vec<_> = generator.into_iter().collect();

    assert_eq!(probes.len(), 2);
    assert_eq!(
        probes
            .iter()
            .map(|p| format!("{}", p))
            .collect::<HashSet<_>>()
            .len(),
        2
    );

    let expected_addr = ["::ffff:0:a".parse(), "::ffff:0:10a".parse()];

    for probe in probes {
        assert!(expected_addr.contains(&Ok(probe.dst_addr)));
        assert_eq!(probe.src_port, 24_000);
        assert_eq!(probe.dst_port, 33_434);
        assert_eq!(probe.ttl, 41);
        assert_eq!(probe.protocol, L4::UDP);
    }
}
