use anyhow::Result;
use core::fmt::Display;
use log::{error, info, trace};
use std::fmt::Formatter;
use std::sync::{Arc, Mutex};

use caracat::{models::Probe, rate_limiter::RateLimiter, sender::Sender};

pub struct SendLoop {
    batch_size: u64,
    instance_id: u16,
    min_ttl: Option<u8>,
    max_ttl: Option<u8>,
    max_probes: Option<u64>,
    packets: u64,
    rate_limiter: RateLimiter,
    sender: Sender,
    statistics: Arc<Mutex<SendStatistics>>,
}

impl SendLoop {
    pub fn new(
        batch_size: u64,
        instance_id: u16,
        min_ttl: Option<u8>,
        max_ttl: Option<u8>,
        max_probes: Option<u64>,
        packets: u64,
        rate_limiter: RateLimiter,
        sender: Sender,
    ) -> Self {
        let statistics = Arc::new(Mutex::new(SendStatistics::default()));
        SendLoop {
            batch_size,
            instance_id,
            min_ttl,
            max_ttl,
            max_probes,
            packets,
            rate_limiter,
            sender,
            statistics,
        }
    }

    pub fn probe<T: Iterator<Item = Probe>>(&mut self, probes: T) -> Result<()> {
        for probe in probes {
            let mut statistics = self.statistics.lock().unwrap();
            statistics.read += 1;

            if let Some(ttl) = self.min_ttl {
                if probe.ttl < ttl {
                    trace!("{:?} filter=ttl_too_low", probe);
                    statistics.filtered_low_ttl += 1;
                    continue;
                }
            }

            if let Some(ttl) = self.max_ttl {
                if probe.ttl > ttl {
                    trace!("{:?} filter=ttl_too_high", probe);
                    statistics.filtered_high_ttl += 1;
                    continue;
                }
            }

            for i in 0..self.packets {
                trace!(
                    "{:?} id={} packet={}",
                    probe,
                    probe.checksum(self.instance_id),
                    i + 1
                );
                match self.sender.send(&probe) {
                    Ok(_) => statistics.sent += 1,
                    Err(error) => {
                        statistics.failed += 1;
                        error!("{}", error);
                    }
                }
                // Rate limit every `batch_size` packets sent.
                if (statistics.sent + statistics.failed) % self.batch_size == 0 {
                    self.rate_limiter.wait();
                }
            }

            if let Some(max_probes) = self.max_probes {
                if statistics.sent >= max_probes {
                    info!("max_probes reached, exiting...");
                    break;
                }
            }
        }

        Ok(())
    }

    pub fn statistics(&self) -> &Arc<Mutex<SendStatistics>> {
        &self.statistics
    }

    pub fn rate_limiter_statistics(&self) -> RateLimiterStatistics {
        let rate_limiter_statistics = self.rate_limiter.statistics().lock().unwrap();
        RateLimiterStatistics {
            average_utilization: rate_limiter_statistics.average_utilization(),
            average_rate: rate_limiter_statistics.average_rate(),
        }
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub struct SendStatistics {
    pub read: u64,
    pub sent: u64,
    pub failed: u64,
    pub filtered_low_ttl: u64,
    pub filtered_high_ttl: u64,
}

impl Display for SendStatistics {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "probes_read={} packets_sent={} packets_failed={} filtered_low_ttl={} filtered_high_ttl={}",
               self.read, self.sent, self.failed, self.filtered_low_ttl, self.filtered_high_ttl)
    }
}

pub struct RateLimiterStatistics {
    pub average_utilization: f64,
    pub average_rate: f64,
}

impl Display for RateLimiterStatistics {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "average_rate={} average_utilization={}",
            self.average_rate, self.average_utilization
        )
    }
}
