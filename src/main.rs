use std::fs::File;
use std::net::{IpAddr, Ipv4Addr};
use std::vec;

use caracat::high_level::receive_loop::ReceiveLoop;
use caracat::high_level::send_loop::{self, SendLoop};
// use caracat::high_level::{probe, Config};
use caracat::high_level::Config;
use caracat::models::Reply;
use caracat::rate_limiter::RateLimiter;

use caracat::receiver;
use caracat::sender::{self, Sender};
use itertools::Itertools;
use voyage::algorithms::diamond_miner::DiamondMiner;
use voyage::algorithms::utils::{general_prob, general_stopping_point, stopping_point};

use anyhow::Result;
use voyage::probe::probe;

fn main() -> Result<()> {
    println!("Hello, world!");
    for i in 0..64 {
        println!("{}", stopping_point(i, 0.01));
    }
    println!("Let's go!");

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
    let dst_addr_str = "31.13.29.247";
    let dst_addr = IpAddr::from(dst_addr_str.parse::<Ipv4Addr>()?);
    let min_ttl = 0;
    let max_ttl = 64;
    let src_port = 0;
    let dst_port = 0;
    let protocol = caracat::models::L4::ICMP;
    let confidence = 95;
    let max_round = 10;

    let mut alg = DiamondMiner::new(
        dst_addr, min_ttl, max_ttl, src_port, dst_port, protocol, confidence, max_round,
    );

    let mut probes = alg.next_round(vec![]);
    println!("sending {} probes", probes.len());

    let mut round = 0;

    while !probes.is_empty() {
        // print probes per TTL
        println!("Probes per TTL:");
        for (ttl, probes) in &probes.iter().group_by(|p| p.ttl) {
            println!("  TTL {}: {}", ttl, probes.count());
        }

        let config = Config {
            // output_file_csv: Some("temp.csv".into()),
            receiver_wait_time: std::time::Duration::from_secs(2),
            ..Config::default()
        };
        println!("Round: {}", round);
        round += 1;
        let replies = probe(config, probes.into_iter())?;
        println!("received {} replies", replies.len());
        println!(
            "time_exceeded_replies: {}",
            replies.iter().filter(|r| r.is_time_exceeded()).count()
        );

        probes = alg.next_round(replies);
        println!("sending {} probes", probes.len());
    }

    Ok(())
}
