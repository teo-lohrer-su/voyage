use crate::algorithms::diamond_miner::types;

pub const DEFAULT_PREFIX_LEN_V4: u8 = 24;
pub const DEFAULT_PREFIX_SIZE_V4: types::PrefixSize = 1 << (32 - DEFAULT_PREFIX_LEN_V4);

pub const DEFAULT_PREFIX_LEN_V6: u8 = 64;
// pub const DEFAULT_PREFIX_SIZE_V6: PrefixSize = 1 << (128 - DEFAULT_PREFIX_LEN_V4);

pub const DEFAULT_PROBE_SRC_PORT: u16 = 24000;
pub const DEFAULT_PROBE_DST_PORT: u16 = 33434;

pub struct SequentialFlowMapper {
    prefix_size: types::PrefixSize,
}

impl SequentialFlowMapper {
    pub fn new(prefix_size: types::PrefixSize) -> Self {
        assert!(prefix_size > 0, "prefix_size must be positive.");
        Self { prefix_size }
    }

    pub fn flow_id(&self, addr_offset: types::Offset, port_offset: types::Offset) -> types::FlowId {
        addr_offset + port_offset
    }

    pub fn offset(&self, flow_id: types::FlowId) -> (types::Offset, types::Offset) {
        // The returned offset is a tuple of offsets (offset on address, offset on port)
        if flow_id < self.prefix_size {
            return (flow_id, 0);
        }
        (self.prefix_size - 1, flow_id - self.prefix_size + 1)
    }
}

impl Default for SequentialFlowMapper {
    fn default() -> Self {
        SequentialFlowMapper::new(DEFAULT_PREFIX_SIZE_V4)
    }
}

#[cfg(test)]
mod tests;
