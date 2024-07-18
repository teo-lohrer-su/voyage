use super::*;

#[test]
fn test_sequential_flow_mapper() {
    for &prefix_len in &[23, 24, 28, 32] {
        let mapper = SequentialFlowMapper::new(1 << (32 - prefix_len));
        let prefix_size = 1 << (32 - prefix_len);
        for flow_id in 0..(prefix_size + 1024) {
            let (addr_offset, port_offset) = mapper.offset(flow_id);
            let id = mapper.flow_id(addr_offset, port_offset);

            assert_eq!(id, flow_id);
        }
    }
}
