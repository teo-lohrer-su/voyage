use std::collections::HashMap;

use chrono::{DateTime, NaiveDate, Utc};
use itertools::Itertools;
use pantrace::formats::internal::Traceroute;
use serde::{Deserialize, Serialize};

/// https://www.measurementlab.net/tests/traceroute/scamper1/

#[derive(Debug, Serialize, Deserialize)]
pub struct Scamper1 {
    /// UUID of the connection under consideration.
    pub id: String,

    /// Metadata about how the parser processed this measurement row.
    pub parser: Parser,

    /// Date is used by BigQuery to partition data to improve query performance.
    pub date: NaiveDate,

    /// Fields from the raw data.
    pub raw: Raw,
}

impl From<&Traceroute> for Scamper1 {
    fn from(traceroute: &Traceroute) -> Self {
        let raw = Raw {
            metadata: Some(Metadata {
                uuid: Some(traceroute.measurement_id.clone()),
                traceroute_caller_version: None,
                cached_result: None,
                cached_uuid: None,
            }),
            cycle_start: Some(CycleStart {
                type_: Some("cycle-start".to_string()),
                list_name: None,
                id: None,
                hostname: None,
                start_time: Some(traceroute.start_time.timestamp() as f64),
            }),
            tracelb: Some(Tracelb::from(traceroute)),
            cycle_stop: Some(CycleStop {
                type_: Some("cycle-stop".to_string()),
                list_name: None,
                id: None,
                hostname: None,
                stop_time: Some(traceroute.end_time.timestamp() as f64),
            }),
        };
        let id = String::from(&traceroute.measurement_id);

        Self {
            id,
            parser: Parser {
                version: None,
                time: None,
                archive_url: None,
                filename: None,
                priority: None,
                git_commit: None,
            },
            date: traceroute.start_time.naive_utc().date(),
            raw,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Parser {
    /// Version is the symbolic version (if any) of the running server code that produced this measurement.
    #[serde(rename = "Version")]
    pub version: Option<String>,

    /// The time that the parser processed this row.
    #[serde(rename = "Time")]
    pub time: Option<DateTime<Utc>>,

    /// The Google Cloud Storage URL to the archive containing the Filename for this row.
    #[serde(rename = "ArchiveURL")]
    pub archive_url: Option<String>,

    /// The name of the file within the ArchiveURL originally created by the measurement service. Results in the raw record are derived from measurements in this file.
    #[serde(rename = "Filename")]
    pub filename: Option<String>,

    #[serde(rename = "Priority")]
    pub priority: Option<i32>,

    /// The git commit of this build of the parser.
    #[serde(rename = "GitCommit")]
    pub git_commit: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Raw {
    #[serde(rename = "Metadata")]
    pub metadata: Option<Metadata>,

    #[serde(rename = "CycleStart")]
    pub cycle_start: Option<CycleStart>,

    #[serde(rename = "Tracelb")]
    pub tracelb: Option<Tracelb>,

    #[serde(rename = "CycleStop")]
    pub cycle_stop: Option<CycleStop>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(rename = "UUID")]
    pub uuid: Option<String>,

    /// The version of traceroute-caller.
    #[serde(rename = "TracerouteCallerVersion")]
    pub traceroute_caller_version: Option<String>,

    /// Traceroute data was found in the cache.
    #[serde(rename = "CachedResult")]
    pub cached_result: Option<bool>,

    /// UUID of the cached traceroute data.
    #[serde(rename = "CachedUUID")]
    pub cached_uuid: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CycleStart {
    /// The string “cycle-start”.
    #[serde(rename = "Type")]
    pub type_: Option<String>,

    /// The name of the IP list file (“/tmp/scamperctl:" for daemon mode, "default" for CLI).
    #[serde(rename = "list_name")]
    pub list_name: Option<String>,

    /// Some ID assigned to identify the list by a person (deprecated).
    #[serde(rename = "ID")]
    pub id: Option<f64>,

    /// The hostname of the machine running the traceroute.
    #[serde(rename = "Hostname")]
    pub hostname: Option<String>,

    /// When traceroute started in Unix epoch.
    #[serde(rename = "start_time")]
    pub start_time: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Tracelb {
    /// The string “tracelb”.
    #[serde(rename = "type")]
    pub type_: String,

    /// The version of tracelb.
    pub version: Option<String>,

    /// The user ID passed via -U flag of the tracelb command (not set by M-Lab).
    pub userid: Option<f64>,

    /// The trace method used by tracelb (“icmp-echo” for MDA traceroutes).
    pub method: Option<String>,

    /// Source address.
    pub src: String,

    /// Destination address.
    pub dst: String,

    /// A timestamp when the traceroute starte
    pub start: TracelbStart,

    /// Size of the probe to send.
    pub probe_size: f64,

    /// Where to start probing.
    pub firsthop: Option<f64>,

    /// Number of attempts per probe.
    pub attempts: Option<f64>,

    /// Confidence level to attain.
    pub confidence: f64,

    /// Type-of-service byte to use.
    pub tos: Option<f64>,

    /// Maximum consecutive unresponsive hops.
    pub gaplimit: Option<f64>,

    /// Seconds to wait before timeout.
    pub wait_timeout: Option<f64>,

    /// Minimum inter-probe time in 1/100th of seconds per TTL.
    pub wait_probe: Option<f64>,

    /// Count of probes sent, including retries.
    pub probec: f64,

    /// Maximum number of probes to send.
    pub probec_max: Option<f64>,

    /// The number of nodes in the traceroute.
    pub nodec: Option<f64>,

    /// The number of links in the traceroute.
    pub linkc: Option<f64>,

    pub nodes: Vec<TracelbNode>,
}

impl From<&Traceroute> for Tracelb {
    fn from(traceroute: &Traceroute) -> Self {
        let probe_size = traceroute
            .flows
            .first()
            .unwrap()
            .hops
            .first()
            .unwrap()
            .probes
            .first()
            .unwrap()
            .size as f64;
        let probec = traceroute
            .flows
            .iter()
            .map(|flow| flow.hops.iter().map(|hop| hop.probes.len()).sum::<usize>())
            .sum::<usize>() as f64;

        let mut nodes: Vec<TracelbNode> = vec![];
        let mut links_by_ttl_by_addr: HashMap<String, HashMap<u8, Vec<TracelbLinkDetails>>> =
            HashMap::new();

        for (_flow_id, flow) in traceroute.flows.iter().enumerate() {
            // For each flow we will collect the links, per node
            for ((_hop_id, hop), (_next_hop_id, _next_hop)) in
                flow.hops.iter().enumerate().tuple_windows()
            {
                // For all couples of successive hops
                // let's build links
                hop.probes
                    .iter()
                    .map(|probe| {
                        let reply = probe.reply.as_ref().unwrap();
                        let addr = reply.addr.to_string();
                        let ttl = reply.quoted_ttl;
                        let tracelb_link_probe = TracelbLinkProbe::from(probe);
                        (addr, ttl, tracelb_link_probe)
                    })
                    .for_each(
                        // populate links_by_ttl_by_addr
                        |(addr, ttl, tracelb_link_probe)| {
                            let link = TracelbLinkDetails {
                                addr: addr.clone(),
                                probes: Some(vec![tracelb_link_probe]),
                            };
                            links_by_ttl_by_addr
                                .entry(addr.clone())
                                .or_default()
                                .entry(ttl)
                                .or_default()
                                .push(link);
                        },
                    );
            }
        }

        fn first_icmp_q_ttl(tracelb_links: &Vec<TracelbNodeLinks>) -> Option<u8> {
            // TODO: revise this code when options are removed from structs
            tracelb_links
                .first()?
                .links
                .first()?
                .probes
                .as_ref()?
                .first()?
                .replies
                .as_ref()?
                .first()
                .map(|reply| reply.icmp_q_ttl)
        }

        for (i, (addr, links_by_ttl)) in links_by_ttl_by_addr.into_iter().enumerate() {
            let mut tracelb_links: Vec<TracelbNodeLinks> = vec![];
            for (_ttl, links_at_ttl) in links_by_ttl {
                let links = TracelbNodeLinks {
                    links: links_at_ttl,
                };
                tracelb_links.push(links);
            }
            let q_ttl = first_icmp_q_ttl(&tracelb_links).unwrap_or(0);

            let node = TracelbNode {
                hop_id: i as u8,
                addr,
                name: None,
                q_ttl,
                linkc: tracelb_links.len(),
                links: Some(tracelb_links),
            };
            nodes.push(node);
        }

        let linkc = Some(nodes.iter().map(|node| node.linkc).sum::<usize>() as f64);

        Self {
            type_: "tracelb".to_string(),
            version: None,
            userid: None,
            method: None,
            src: traceroute.src_addr.to_string(),
            dst: traceroute.dst_addr.to_string(),
            start: traceroute.start_time.into(),
            probe_size,
            firsthop: None,
            attempts: None,
            confidence: 0.95,
            tos: None,
            gaplimit: None,
            wait_timeout: None,
            wait_probe: None,
            probec,
            probec_max: None,
            nodec: Some(nodes.len() as f64),
            linkc,
            nodes,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TracelbStart {
    /// Number of seconds since Unix epoch when the traceroute started.
    #[serde(rename = "Sec")]
    pub sec: i32,

    /// Microseconds elapsed within the second when this traceroute started.
    #[serde(rename = "Usec")]
    pub usec: i32,
}

impl From<DateTime<Utc>> for TracelbStart {
    fn from(dt: DateTime<Utc>) -> Self {
        Self {
            sec: dt.timestamp() as i32,
            usec: dt.timestamp_subsec_micros() as i32,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TracelbNode {
    pub hop_id: u8,

    /// The IP address of the node.
    pub addr: String,

    /// The hostname for the IP address.
    pub name: Option<String>,

    /// The TTL value of the quoted traceroute probe.
    pub q_ttl: u8,

    /// The number of links for this node.
    pub linkc: usize,

    /// An array of sets of links for this node.
    pub links: Option<Vec<TracelbNodeLinks>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TracelbNodeLinks {
    /// A set of links for this node.
    /// The links share their TTL
    #[serde(rename = "Links")]
    pub links: Vec<TracelbLinkDetails>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TracelbLinkDetails {
    /// The address in a link (“*” for unresponsive hosts).
    #[serde(rename = "Addr")]
    pub addr: String,

    /// The probes that observed this link.
    #[serde(rename = "Probes")]
    pub probes: Option<Vec<TracelbLinkProbe>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TracelbLinkProbe {
    /// The timestamp of a probe.
    #[serde(rename = "Tx")]
    pub tx: ProbeTimestamp,

    /// The number of replies this probe received from this address.
    #[serde(rename = "Replyc")]
    pub replyc: usize,

    /// The TTL of the probe sent.
    #[serde(rename = "TTL")]
    pub ttl: i32,

    /// The attempt number of this probe.
    #[serde(rename = "Attempt")]
    pub attempt: Option<i32>,

    /// The flow identifier of this probe.
    #[serde(rename = "Flowid")]
    pub flowid: Option<i32>,

    #[serde(rename = "Replies")]
    pub replies: Option<Vec<ProbeReply>>,
}

impl From<&pantrace::formats::internal::TracerouteProbe> for TracelbLinkProbe {
    fn from(probe: &pantrace::formats::internal::TracerouteProbe) -> Self {
        Self {
            tx: probe.timestamp.into(),
            replyc: if probe.reply.is_some() { 1 } else { 0 },
            ttl: probe.size as i32,
            attempt: None,
            flowid: None,
            replies: probe.reply.as_ref().map(|reply| vec![reply.into()]),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProbeTimestamp {
    /// The seconds portion of the timestamp of the probe.
    #[serde(rename = "Sec")]
    pub sec: i32,

    /// The microseconds portion of the timestamp of the probe.
    #[serde(rename = "Usec")]
    pub usec: i32,
}

impl From<DateTime<Utc>> for ProbeTimestamp {
    fn from(dt: DateTime<Utc>) -> Self {
        Self {
            sec: dt.timestamp() as i32,
            usec: dt.timestamp_subsec_micros() as i32,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProbeReply {
    /// The timestamp of a response.
    #[serde(rename = "Rx")]
    pub rx: ProbeTimestamp,

    /// The TTL of the received response packet.
    #[serde(rename = "TTL")]
    pub ttl: i32,

    /// The round trip time in milliseconds.
    #[serde(rename = "RTT")]
    pub rtt: f64,

    /// The type of ICMP response.
    pub icmp_type: u8,

    /// The code of the ICMP response.
    pub icmp_code: u8,

    /// The "type of service" byte in the quoted IP packet probe.
    pub icmp_q_tos: Option<i32>,

    /// The "time to live" byte in the quoted IP packet probe.
    pub icmp_q_ttl: u8,
}

impl From<&pantrace::formats::internal::TracerouteReply> for ProbeReply {
    fn from(reply: &pantrace::formats::internal::TracerouteReply) -> Self {
        Self {
            rx: reply.timestamp.into(),
            ttl: reply.ttl as i32,
            rtt: reply.rtt,
            icmp_type: reply.icmp_type,
            icmp_code: reply.icmp_code,
            // TODO: What is the type of service byte?
            icmp_q_tos: None,
            icmp_q_ttl: reply.quoted_ttl,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CycleStop {
    /// The string “cycle-stop”.
    #[serde(rename = "Type")]
    pub type_: Option<String>,

    /// The name of the IP list file (“/tmp/scamperctl:" for daemon mode, "default" for CLI).
    pub list_name: Option<String>,

    /// Some ID assigned to identify the list by a person (deprecated).
    #[serde(rename = "ID")]
    pub id: Option<f64>,

    /// The hostname of the system that this traceroute was collected on.
    #[serde(rename = "Hostname")]
    pub hostname: Option<String>,

    /// When traceroute finished in Unix epoch.
    pub stop_time: Option<f64>,
}
