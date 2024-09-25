use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use std::{fmt, vec};

use caracat::high_level::Config;

use chrono::Utc;
use itertools::Itertools;
use log::{debug, info};
use netdev::get_default_interface;
use pantrace::formats::atlas::AtlasWriter;
use pantrace::formats::internal::{Protocol, Traceroute};
use pantrace::traits::TracerouteWriter;
use voyage::algorithms::diamond_miner::DiamondMiner;
use voyage::classic_traceroute::ClassicTracerouteWriter;
use voyage::pantrace_builder::replies_to_pantrace_flows;

use anyhow::Result;
use voyage::probe::probe;
use voyage::types::{Link, TTL};

use clap::{Parser, ValueEnum};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum OutputFormat {
    Atlas,
    Iris,
    Flat,
    Internal,
    Traceroute,
    Scamper,
    Quiet,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputFormat::Atlas => write!(f, "atlas"),
            OutputFormat::Iris => write!(f, "iris"),
            OutputFormat::Flat => write!(f, "flat"),
            OutputFormat::Internal => write!(f, "internal"),
            OutputFormat::Traceroute => write!(f, "traceroute"),
            OutputFormat::Scamper => write!(f, "scamper"),
            OutputFormat::Quiet => write!(f, "quiet"),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProtocolArg {
    ICMP,
    UDP,
}

impl From<ProtocolArg> for caracat::models::L4 {
    fn from(protocol: ProtocolArg) -> Self {
        match protocol {
            ProtocolArg::UDP => caracat::models::L4::UDP,
            ProtocolArg::ICMP => caracat::models::L4::ICMP,
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Destination IP address
    #[arg(short, long)]
    dst_addr: String,

    /// Minimum TTL
    #[arg(long, default_value_t = 1)]
    min_ttl: u8,

    /// Maximum TTL
    #[arg(long, default_value_t = 32)]
    max_ttl: u8,

    /// Source port
    #[arg(long, default_value_t = 24000)]
    src_port: u16,

    /// Destination port
    #[arg(long, default_value_t = 33434)]
    dst_port: u16,

    /// Confidence level
    #[arg(short, long, default_value_t = 99.0)]
    confidence: f64,

    /// Maximum number of rounds
    #[arg(short, long, default_value_t = 100)]
    max_round: u32,

    /// Estimate successors
    #[arg(short, long, default_value_t = false)]
    estimate_successors: bool,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Traceroute)]
    output_format: OutputFormat,

    /// Receiver wait time in seconds
    #[arg(long, default_value_t = 1)]
    receiver_wait_time: u64,

    /// Probing rate in packets per second
    #[arg(long, default_value_t = 100)]
    probing_rate: u64,

    /// Protocol to use (ICMP or UDP)
    #[arg(short, long, value_enum, default_value_t = ProtocolArg::ICMP)]
    protocol: ProtocolArg,

    /// Network interface to use
    #[arg(short, long)]
    interface: Option<String>,

    /// Instance ID
    #[arg(long)]
    id: Option<u16>,
}

fn main() -> Result<()> {
    env_logger::init();
    // let dst_addr_str = "12.12.12.12";
    // let dst_addr_str = "103.37.83.226";
    // let dst_addr_str = "104.18.32.7";
    // let dst_addr_str = "157.240.221.35";
    // let dst_addr_str = "8.8.8.8";
    // let dst_addr_str = "1.1.1.1";
    let args = Args::parse();

    let dst_addr = IpAddr::from(args.dst_addr.parse::<Ipv4Addr>()?);
    let min_ttl = args.min_ttl;
    let max_ttl = args.max_ttl;
    let src_port = args.src_port;
    let dst_port = args.dst_port;
    let protocol = args.protocol.into();
    let confidence = args.confidence;
    let max_round = args.max_round;
    let estimate_successsors = args.estimate_successors;

    let mut alg = DiamondMiner::new(
        dst_addr, min_ttl, max_ttl, src_port, dst_port, protocol, confidence, max_round,
    );

    let mut round = 0;

    let mut probes = alg.next_round(vec![], estimate_successsors);
    info!(
        "round={} links_found={} total_ip={} probes={} expected_time={:.1}s",
        round,
        0,
        0,
        probes.len(),
        probes.len() as f64 / (args.probing_rate as f64),
    );

    let start_time = Utc::now();

    while !probes.is_empty() {
        let config = Config {
            receiver_wait_time: Duration::from_secs(args.receiver_wait_time),
            probing_rate: args.probing_rate,
            interface: args
                .interface
                .clone()
                .unwrap_or_else(|| get_default_interface().unwrap().name),
            instance_id: args.id.unwrap_or(0),
            ..Config::default()
        };
        round += 1;
        let replies = probe(config, probes.into_iter())?;
        debug!(
            "received {} replies including {} time exceeded replies",
            replies.len(),
            replies.iter().filter(|r| r.is_time_exceeded()).count()
        );

        let prep_start = Utc::now();

        probes = alg.next_round(replies, estimate_successsors);

        let prep_end = Utc::now();

        debug!(
            "Preparation time: {:.3}s",
            (prep_end - prep_start).num_milliseconds() as f64 * 1e-3
        );

        let n_probes_per_ttl = probes.iter().group_by(|probe| probe.ttl);

        for (ttl, probes) in n_probes_per_ttl.into_iter() {
            debug!("TTL {}: {} probes", ttl, probes.count());
        }
        // for ttl in min_ttl..=max_ttl {
        //     // number of ips at this ttl
        //     debug!(
        //         "TTL {}: {} ips",
        //         ttl,
        //         alg.time_exceeded_replies()
        //             .iter()
        //             .filter(|r| r.probe_ttl == ttl)
        //             .map(|r| r.reply_src_addr)
        //             .unique()
        //             .count()
        //     );
        // }

        // fetch the total number of distinct links in the alg

        let total_links = HashSet::<&Link>::from_iter(
            alg.links_by_ttl()
                .values()
                .flatten()
                .filter(|link| link.near_ip.is_some() && link.far_ip.is_some())
                .unique(),
        )
        .len();

        // Add the new logging information
        let total_ips: HashSet<IpAddr> = alg
            .time_exceeded_replies()
            .iter()
            .map(|r| r.reply_src_addr)
            .collect();

        info!(
            "round={} links_found={} total_ip={} probes={} expected_time={:.1}s",
            round,
            total_links,
            total_ips.len(),
            probes.len(),
            args.receiver_wait_time as f64 + (probes.len() as f64 / (args.probing_rate as f64)),
        );
    }

    let end_time = Utc::now();

    let mut ips_by_ttl: HashMap<TTL, HashSet<IpAddr>> = alg
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

    // add the echo replies to the table if the ip is the destination

    for reply in alg.replies() {
        if reply.reply_src_addr == dst_addr {
            let ttl = reply.probe_ttl;
            let table = ips_by_ttl.entry(ttl).or_default();
            table.insert(reply.reply_src_addr);
        }
    }

    for ttl in min_ttl..=max_ttl {
        let table = ips_by_ttl.entry(ttl).or_default();
        debug!("[TTL: {}] -> {:?}", ttl, table);
        if table.contains(&dst_addr) {
            break;
        }
    }

    // let pantrace_flows = replies_to_pantrace_flows(&alg.time_exceeded_replies());
    let pantrace_flows = replies_to_pantrace_flows(&alg.replies());

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

    println!(
        ">>> total probes in flows: {}",
        traceroute
            .flows
            .iter()
            .map(|f| f.hops.iter().map(|h| h.probes.len()).sum::<usize>())
            .sum::<usize>()
    );

    match args.output_format {
        OutputFormat::Traceroute => {
            debug!("--- Traceroute output ---");
            let stdout = std::io::stdout();
            let total_flows = traceroute.flows.len();
            let mut traceroute_writer =
                ClassicTracerouteWriter::new(stdout, min_ttl, max_ttl, dst_addr, total_flows);
            traceroute_writer.write_traceroute(&traceroute)?;
        }
        OutputFormat::Atlas => {
            debug!("--- ATLAS output ---");
            let stdout = std::io::stdout();
            let mut atlas_writer = AtlasWriter::new(stdout);
            atlas_writer.write_traceroute(&traceroute)?;
        }
        OutputFormat::Iris => {
            debug!("--- Iris output ---");
            let stdout = std::io::stdout();
            let mut iris_writer = pantrace::formats::iris::IrisWriter::new(stdout);
            iris_writer.write_traceroute(&traceroute)?;
        }
        OutputFormat::Flat => {
            debug!("--- flat / MetaTrace output ---");
            let stdout = std::io::stdout();
            let mut flat_writer = pantrace::formats::flat::FlatWriter::new(stdout);
            flat_writer.write_traceroute(&traceroute)?;
        }
        OutputFormat::Internal => {
            debug!("--- internal / Pantrace output ---");
            let stdout = std::io::stdout();
            let mut internal_writer = pantrace::formats::internal::InternalWriter::new(stdout);
            internal_writer.write_traceroute(&traceroute)?;
        }
        OutputFormat::Scamper => {
            println!("--- Scamper / warts output (binary) ---");
            let stdout = std::io::stdout();
            let mut scamper_writer =
                pantrace::formats::scamper_trace_warts::ScamperTraceWartsWriter::new(stdout);
            scamper_writer.write_traceroute(&traceroute)?;
        }
        OutputFormat::Quiet => {
            debug!("Links");
            // print all links found
            let mut end = false;
            for ttl in min_ttl..=max_ttl {
                if !end {
                    debug!("[TTL: {}]", ttl);
                } else {
                    break;
                }
                for link in alg
                    .links_by_ttl()
                    .get(&ttl)
                    .unwrap_or(&vec![])
                    .iter()
                    .unique()
                {
                    let (near, far) = match (link.near_ip, link.far_ip) {
                        (Some(near), Some(far)) => (format!("{}", near), format!("{}", far)),
                        (Some(near), None) => (format!("{}", near), "*".to_string()),
                        (None, Some(far)) => ("*".to_string(), format!("{}", far)),
                        (None, None) => ("*".to_string(), "*".to_string()),
                    };
                    debug!("|  {} -- {}", near, far);
                    if link.far_ip == Some(dst_addr) {
                        end = true;
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
