use std::thread::sleep;

use log::info;

use anyhow::Result;
use caracat::{
    high_level::{Config, SendLoop},
    models::{Probe, Reply},
    rate_limiter::RateLimiter,
    sender::Sender,
    utilities::prefix_filter_from_file,
};

use crate::receiver::ReceiveCache;

pub fn probe<T: Iterator<Item = Probe>>(config: Config, probes: T) -> Result<Vec<Reply>> {
    let allowed_prefixes = match config.allowed_prefixes_file {
        None => None,
        Some(path) => Some(prefix_filter_from_file(&path)?),
    };

    let blocked_prefixes = match config.blocked_prefixes_file {
        None => None,
        Some(path) => Some(prefix_filter_from_file(&path)?),
    };

    let rate_limiter = RateLimiter::new(
        config.probing_rate,
        config.batch_size,
        config.rate_limiting_method,
    );
    // let rate_statistics = rate_limiter.statistics().clone();

    // let receiver = ReceiveLoop::new(
    let mut receiver = ReceiveCache::new(
        config.interface.clone(),
        // config.output_file_csv,
        // config.instance_id,
        // config.extra_string,
        // config.integrity_check,
    );
    // let receiver_statistics = receiver.statistics().clone();

    let mut prober = SendLoop::new(
        config.batch_size,
        config.instance_id,
        config.min_ttl,
        config.max_ttl,
        config.max_probes,
        config.packets,
        allowed_prefixes,
        blocked_prefixes,
        rate_limiter,
        Sender::new(&config.interface, config.instance_id, config.dry_run)?,
    );
    // let prober_statistics = prober.statistics().clone();

    // let logger = StatisticsLogger::new(prober_statistics, rate_statistics, receiver_statistics);

    prober.probe(probes)?;
    info!(
        "Waiting {:?} for last replies...",
        config.receiver_wait_time
    );
    sleep(config.receiver_wait_time);

    // TODO: Cleaner way?
    // let final_prober_statistics = *prober.statistics().lock().unwrap();
    // let final_receiver_statistics = receiver.statistics().lock().unwrap().clone();

    let replies = receiver.stop();
    // logger.stop();

    Ok(replies)

    // Ok((final_prober_statistics, final_receiver_statistics))
}
