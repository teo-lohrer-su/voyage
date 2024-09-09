use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;

use anyhow::Result;

use itertools::Itertools;
use pantrace::formats::internal::Traceroute;
use pantrace::traits::TracerouteWriter;

pub struct ClassicTracerouteWriter<W: Write> {
    output: W,
    min_ttl: u8,
    max_ttl: u8,
    dst_addr: IpAddr,
}

impl<W: Write> ClassicTracerouteWriter<W> {
    pub fn new(
        output: W,
        min_ttl: u8,
        max_ttl: u8,
        dst_addr: IpAddr,
    ) -> ClassicTracerouteWriter<W> {
        ClassicTracerouteWriter {
            output,
            min_ttl,
            max_ttl,
            dst_addr,
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
            "traceroute to {}({}), {} hops max, {} bytes packets",
            traceroute.dst_addr, traceroute.dst_addr, self.max_ttl, packet_size
        )
        .unwrap();
        let flow = &traceroute.flows[0];
        let hops_by_ttl = flow.hops.iter().group_by(|hop| hop.ttl);
        let hops_by_ttl = hops_by_ttl
            .into_iter()
            .fold(HashMap::new(), |mut acc, (ttl, hops)| {
                acc.insert(ttl, hops.collect_vec());
                acc
            });

        write!(self.output, "\n").unwrap();

        let mut found_dst = false;

        for ttl in self.min_ttl..=self.max_ttl {
            if found_dst {
                break;
            }
            write!(self.output, "{}", ttl).unwrap();
            if let Some(hops) = hops_by_ttl.get(&ttl) {
                let hop = &hops[0];
                let probes_by_host = hop
                    .probes
                    .iter()
                    .filter(|probe| probe.reply.is_some())
                    .group_by(|probe| probe.reply.as_ref().map(|r| r.addr));
                for (ip, probes) in probes_by_host.into_iter() {
                    let probes = probes.collect_vec();
                    if let Some(ip) = ip {
                        write!(self.output, "   {} ({})", ip, ip).unwrap();
                        for probe in probes.iter() {
                            let reply = probe.reply.as_ref().unwrap();
                            write!(self.output, "  {:.3} ms", reply.rtt / 10.0).unwrap();
                            found_dst = found_dst || (ip == self.dst_addr);
                        }
                        write!(self.output, "\n").unwrap();
                    } else {
                        write!(self.output, "   *\n").unwrap();
                    }
                }
            } else {
                write!(self.output, "   *\n").unwrap();
            }
        }

        Ok(())
    }
}
