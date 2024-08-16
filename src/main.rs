use std::collections::{HashMap, HashSet};
use std::io::Stdout;
use std::net::{IpAddr, Ipv4Addr};
use std::vec;

use caracat::high_level::Config;

use chrono::Utc;
use netdev::get_default_interface;
use pantrace::formats::atlas::AtlasWriter;
use pantrace::formats::internal::{Protocol, Traceroute};
use pantrace::traits::TracerouteWriter;
use voyage::algorithms::diamond_miner::DiamondMiner;
use voyage::pantrace_builder::replies_to_pantrace_flows;

use anyhow::Result;
use voyage::probe::probe;
use voyage::types::TTL;

fn main() -> Result<()> {
    // let dst_addr_str = "12.12.12.12";
    let dst_addr_str = "103.37.83.226";
    // let dst_addr_str = "104.18.32.7";
    // let dst_addr_str = "157.240.221.35";
    // let dst_addr_str = "8.8.8.8";
    // let dst_addr_str = "1.1.1.1";
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

    let start_time = Utc::now();

    while !probes.is_empty() {
        // print probes per TTL
        println!("  Probes per TTL:");
        for ttl in min_ttl..=max_ttl {
            let ttl_probes = probes.iter().filter(|p| p.ttl == ttl).count();
            if ttl_probes > 0 {
                print!("  [TTL {}]: {}", ttl, ttl_probes);
            }
        }
        println!();

        let config = Config {
            receiver_wait_time: std::time::Duration::from_secs(2),
            interface: get_default_interface().unwrap().name,
            ..Config::default()
        };
        round += 1;
        println!("- Round: {}", round);
        let replies = probe(config, probes.into_iter())?;
        println!("  received {} replies", replies.len());
        println!(
            "  including {} time exceeded replies",
            replies.iter().filter(|r| r.is_time_exceeded()).count()
        );
        probes = alg.next_round(replies, false);
        println!("  sending {} probes", probes.len());
    }

    let end_time = Utc::now();

    let max_ttl = 20;

    let n_links = alg.n_links_by_ttl();

    for ttl in 0..=max_ttl {
        print!("  [TTL {}]: {} links", ttl, n_links.get(&ttl).unwrap_or(&0));
    }

    println!("\n------------");

    // print all replies ips per ttl per flow

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

    for ttl in sorted_ttls.iter() {
        let table = ips_by_ttl.get(ttl).unwrap();
        println!("[TTL: {}] -> {:?}", ttl, table);
    }

    let pantrace_flows = replies_to_pantrace_flows(&alg.time_exceeded_replies());

    let traceroute: Traceroute = Traceroute {
        measurement_name: "diamond_miner".to_string(),
        measurement_id: "0".to_string(),
        agent_id: "0".to_string(),
        start_time,
        end_time,
        protocol: Protocol::ICMP,
        src_addr: IpAddr::from(Ipv4Addr::new(192, 168, 1, 1)),
        src_addr_public: None,
        dst_addr,
        flows: pantrace_flows,
    };

    println!("--- ATLAS output ---");
    let stdout = std::io::stdout();
    let mut atlas_writer: AtlasWriter<Stdout> = AtlasWriter::new(stdout);
    atlas_writer.write_traceroute(&traceroute)?;

    println!("--- Iris output ---");
    let stdout = std::io::stdout();
    let mut iris_writer = pantrace::formats::iris::IrisWriter::new(stdout);
    iris_writer.write_traceroute(&traceroute)?;

    println!("--- flat / MetaTrace output ---");
    let stdout = std::io::stdout();
    let mut flat_writer = pantrace::formats::flat::FlatWriter::new(stdout);
    flat_writer.write_traceroute(&traceroute)?;

    println!("--- internal / Pantrace output ---");
    let stdout = std::io::stdout();
    let mut internal_writer = pantrace::formats::internal::InternalWriter::new(stdout);
    internal_writer.write_traceroute(&traceroute)?;

    // println!("--- Scamper / warts output (binary) ---");
    // let stdout = std::io::stdout();
    // let mut scamper_writer =
    //     pantrace::formats::scamper_trace_warts::ScamperTraceWartsWriter::new(stdout);
    // scamper_writer.write_traceroute(&traceroute)?;

    Ok(())
}
