use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::vec;

use caracat::high_level::Config;

// use caracat::models::Reply;
use itertools::Itertools;
use netdev::get_default_interface;
use voyage::algorithms::diamond_miner::DiamondMiner;
// use voyage::algorithms::utils::{general_prob, stopping_point};

use anyhow::Result;
use voyage::probe::probe;
// use voyage::types::Flow;
use voyage::types::TTL;

fn main() -> Result<()> {
    // println!("Hello, world!");
    // for i in 1..=10 {
    //     println!("{}: {}", i, stopping_point(i, 0.01));
    // }

    // let triplets = [
    //     (4, 3, 2),
    //     (2, 2, 1),
    //     (2, 2, 2),
    //     (3, 2, 1),
    //     (3, 2, 2),
    //     (3, 2, 3),
    //     (3, 3, 1),
    //     (3, 3, 2),
    //     (3, 3, 3),
    // ];
    // for (K, n, k) in triplets {
    //     println!("K:{} n:{} k:{} --> p:{}", K, n, k, general_prob(K, n, k));
    // }

    // return Ok(());
    // println!("Let's go!");

    // println!("32: {} (should be 211)", general_stopping_point(32, 0.05));
    // return Ok(());

    // for total_interfaces in 1..=10
    // for n_probes in 1..=10
    // for target_interfaces in 1..=total_interfaces
    // print the general_prob(total_interfaces, n_probes, target_interfaces)

    // for total_interfaces in 1..=10 {
    //     for n_probes in 1..=10 {
    //         for target_interfaces in 1..=total_interfaces {
    //             println!(
    //                 "N:{} k:{} n:{} --> p:{}",
    //                 total_interfaces,
    //                 n_probes,
    //                 target_interfaces,
    //                 general_prob(total_interfaces, n_probes, target_interfaces)
    //             );
    //         }
    //     }
    // }

    // for total_interfaces in 1..=10 {
    //     println!(
    //         "N:{} stop:{}",
    //         total_interfaces,
    //         general_stopping_point(total_interfaces, 0.05)
    //     );
    // }

    // let dst_addr_str = "12.12.12.12";
    // let dst_addr_str = "103.37.83.226";
    // let dst_addr_str = "104.18.32.7";
    // let dst_addr_str = "157.240.221.35";
    // let dst_addr_str = "8.8.8.8";
    let dst_addr_str = "1.1.1.1";
    let dst_addr = IpAddr::from(dst_addr_str.parse::<Ipv4Addr>()?);
    let min_ttl = 0;
    let max_ttl = 32;
    let src_port = 0;
    let dst_port = 0;
    let protocol = caracat::models::L4::ICMP;
    let confidence = 95.0;
    let max_round = 10;

    let mut alg = DiamondMiner::new(
        dst_addr, min_ttl, max_ttl, src_port, dst_port, protocol, confidence, max_round,
    );

    let mut probes = alg.next_round(vec![], false);
    println!("sending {} probes", probes.len());

    let mut round = 0;

    while !probes.is_empty() {
        // print probes per TTL
        println!("Probes per TTL:");
        for (ttl, probes) in &probes.iter().group_by(|p| p.ttl) {
            println!("  TTL {}: {}", ttl, probes.count());
        }

        let config = Config {
            receiver_wait_time: std::time::Duration::from_secs(2),
            interface: get_default_interface().unwrap().name,
            ..Config::default()
        };
        round += 1;
        println!("Round: {}", round);
        let replies = probe(config, probes.into_iter())?;
        println!("received {} replies", replies.len());
        println!(
            "time_exceeded_replies: {}",
            replies.iter().filter(|r| r.is_time_exceeded()).count()
        );

        probes = alg.next_round(replies, false);
        println!("sending {} probes", probes.len());
    }

    let max_ttl = 20;

    let n_links = alg.n_links_by_ttl();
    // let links = alg.links_by_ttl();

    for ttl in 0..=max_ttl {
        println!("  TTL {}: {} links", ttl, n_links.get(&ttl).unwrap_or(&0));
        // println!("          {:?}", links.get(&ttl).unwrap_or(&vec![]));
    }

    println!("------------");

    // print all replies ips per ttl per flow

    let replies = alg.time_exceeded_replies();

    let ips_by_ttl: HashMap<TTL, HashSet<IpAddr>> = alg
        .links_by_ttl()
        .iter()
        .map(|(&ttl, links)| {
            (
                ttl,
                links
                    .iter()
                    .filter_map(|link| link.near_ip)
                    .collect::<HashSet<_>>(),
            )
        })
        .collect();

    // pretty print this table

    let sorted_ttls = {
        let mut ttls = ips_by_ttl.keys().copied().collect::<Vec<_>>();
        ttls.sort();
        ttls
    };

    // for (ttl, table) in ips_by_ttl_by_flow {
    for ttl in sorted_ttls.iter() {
        let table = ips_by_ttl.get(ttl).unwrap();
        println!("TTL: {} -> {:?}", ttl, table);
    }

    Ok(())
}
