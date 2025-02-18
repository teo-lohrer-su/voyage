use std::{thread::sleep, time::Duration};

use log::info;

use anyhow::Result;
use caracat::{
    // high_level::{Config, SendLoop},
    models::{Probe, Reply},
    rate_limiter::RateLimiter,
    sender::Sender,
    // utilities::prefix_filter_from_file,
};

use crate::{caracat_config::CaracatConfig, receiver::ReceiveCache, send_loop::SendLoop};

pub fn probe<T: Iterator<Item = Probe>>(
    config: &CaracatConfig,
    wait_time: Duration,
    probes: T,
) -> Result<Vec<Reply>> {
    let rate_limiter = RateLimiter::new(
        config.probing_rate,
        config.batch_size,
        config.rate_limiting_method,
    );
    let mut receiver = ReceiveCache::new(config.interface.clone());

    let mut prober = SendLoop::new(
        config.batch_size,
        config.instance_id,
        config.min_ttl,
        config.max_ttl,
        config.max_probes,
        config.packets,
        rate_limiter,
        Sender::new(
            &config.interface,
            config.src_ipv4_addr,
            config.src_ipv6_addr,
            config.instance_id,
            config.dry_run,
        )?,
    );

    prober.probe(probes)?;
    info!("Waiting {:?} for last replies...", wait_time);
    sleep(wait_time);

    let replies = receiver.stop();

    Ok(replies)
}
