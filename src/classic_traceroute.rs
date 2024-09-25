use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;

use anyhow::Result;

use itertools::Itertools;
use pantrace::formats::internal::{Traceroute, TracerouteHop};
use pantrace::traits::TracerouteWriter;

pub struct ClassicTracerouteWriter<W: Write> {
    output: W,
    min_ttl: u8,
    max_ttl: u8,
    dst_addr: IpAddr,
    total_flows: usize,
}

impl<W: Write> ClassicTracerouteWriter<W> {
    pub fn new(
        output: W,
        min_ttl: u8,
        max_ttl: u8,
        dst_addr: IpAddr,
        total_flows: usize,
    ) -> ClassicTracerouteWriter<W> {
        ClassicTracerouteWriter {
            output,
            min_ttl,
            max_ttl,
            dst_addr,
            total_flows,
        }
    }
}

impl<W> TracerouteWriter for ClassicTracerouteWriter<W>
where
    W: Write,
{
    fn write_traceroute(&mut self, traceroute: &Traceroute) -> Result<()> {
        let packet_size = traceroute.flows[0].hops[0].probes[0].size;
        write!(
            self.output,
            "traceroute to {}({}), {} hops max, {} bytes packets, flow {}/{}\n",
            traceroute.dst_addr,
            traceroute.dst_addr,
            self.max_ttl,
            packet_size,
            1,
            self.total_flows
        )
        .unwrap();

        let all_hops = traceroute
            .flows
            .iter()
            .flat_map(|flow| flow.hops.iter())
            // .map(|flow| &flow.hops)
            // .flatten()
            .collect::<Vec<_>>();

        let hops_by_ttl = all_hops
            .into_iter()
            .group_by(|hop| hop.ttl)
            .into_iter()
            .fold(
                HashMap::<u8, Vec<&TracerouteHop>>::new(),
                |mut acc, (ttl, group)| {
                    acc.entry(ttl)
                        .or_insert_with(Vec::new)
                        .extend(group.into_iter());
                    acc
                },
            );

        let mut found_dst = false;

        for ttl in self.min_ttl..=self.max_ttl {
            if found_dst {
                break;
            }
            write!(self.output, "{}", ttl).unwrap();
            if let Some(hops) = hops_by_ttl.get(&ttl) {
                let all_probes = hops
                    .into_iter()
                    .flat_map(|hop| hop.probes.iter())
                    .collect::<Vec<_>>();
                let all_replies_by_host = all_probes
                    .into_iter()
                    .filter_map(|probe| probe.reply.as_ref().map(|reply| (reply.addr, reply.rtt)))
                    .fold(
                        HashMap::<IpAddr, Vec<f64>>::new(),
                        |mut acc, (addr, rtt)| {
                            acc.entry(addr).or_insert_with(Vec::new).push(rtt);
                            acc
                        },
                    );

                for (ip, rtts) in all_replies_by_host.into_iter() {
                    found_dst |= ip == self.dst_addr;

                    write!(self.output, "   {} ({})", ip, ip).unwrap();
                    let mean_rtt = rtts.iter().sum::<f64>() / rtts.len() as f64;
                    write!(
                        self.output,
                        "  {:.3} ms ({} probes)",
                        mean_rtt / 10.0,
                        rtts.len()
                    )
                    .unwrap();
                    write!(self.output, "\n").unwrap();
                }
                // write!(self.output, "\n").unwrap();
            } else {
                write!(self.output, "   *\n").unwrap();
            }
            write!(self.output, "\n").unwrap();
        }

        Ok(())
    }
}
