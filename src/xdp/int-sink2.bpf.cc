extern "C" {
	#include <shared/filter_defs.h>
	#include <shared/int_defs.h>
	#include <shared/net_defs.h>
}

#include "bpf_helpers.hh"

// Needed to name these structs as anonymous structs
// in C++ can not have global linkage
struct map_a {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct counter_set);
} counters_map [[gnu::section(".maps")]];

struct map_b {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
} int_dscp_map [[gnu::section(".maps")]];

struct headers {
	header<struct ethhdr> ethernet;
	header<struct vlanhdr> vlan;
	header<struct vlanhdr> qinq;
	header<struct iphdr> ip;
	header<struct udphdr> udp;
	header<struct tcphdr> tcp;
	header<struct int10_shim_t> shim;
};

static inline bool export_int_metadata(Parser &parser, struct headers &hdr);

extern "C"
[[gnu::section("xdp")]]
int ebpf_filter(struct xdp_md *ctx) {
	Parser parser = {ctx};
	struct headers hdr = {};
	const __u64 packetSize = parser.packet_size();
	goto start;
// Goto reject, if packet malformed
	reject: { return XDP_DROP; }
// Goto pass, if processing complete
	pass: { return XDP_PASS; }
// Goto accept, if packet needs to be updated on egress
start: {
		__u32 key = 0; // Count all packets received
		auto counter_set_ptr = lookup(&counters_map, &key);
		if (counter_set_ptr != nullptr)
		{
			__sync_fetch_and_add(&(counter_set_ptr->packets), 1);
			__sync_fetch_and_add(&(counter_set_ptr->bytes), packetSize);
		}
		goto parse_ether;
	}
parse_ether: {
		hdr.ethernet = parser.extract_header<struct ethhdr>();
		if (hdr.ethernet.valid == false) { goto reject; }
		switch (hdr.ethernet.hdr.h_proto) {
			case bpf_htons(ETH_P_8021Q): goto parse_vlan;
			case bpf_htons(ETH_P_IP): goto parse_ipv4;
			default: goto pass;
		}
	}
parse_vlan: {
		hdr.vlan = parser.extract_header<struct vlanhdr>();
		if (hdr.vlan.valid == false) { goto reject; }
		switch (hdr.vlan.hdr.h_proto) {
			case bpf_htons(ETH_P_8021Q): goto parse_qinq;
			case bpf_htons(ETH_P_IP): goto parse_ipv4;
			default: goto pass;
		}
	}
parse_qinq: {
		hdr.qinq = parser.extract_header<struct vlanhdr>();
		if (hdr.qinq.valid == false) { goto reject; }
		switch (hdr.qinq.hdr.h_proto) {
			case bpf_htons(ETH_P_IP): goto parse_ipv4;
			default: goto pass;
		}
	}
parse_ipv4: {
		hdr.ip = parser.extract_header<struct iphdr>();
		if (hdr.ip.valid == false) { goto reject; }
		__u32 dscp = hdr.ip.hdr.dscp;
		if (lookup(&int_dscp_map, &dscp) == nullptr) { goto pass; }
		switch (hdr.ip.hdr.protocol) {
			case 0x6: goto parse_tcp;
			case 0x11: goto parse_udp;
			default: goto pass;
		}
	}
parse_udp: {
		hdr.udp = parser.extract_header<struct udphdr>();
		if (hdr.udp.valid == false) { goto reject; }
		goto parse_int;
	}
parse_tcp: {
		hdr.tcp = parser.extract_header<struct tcphdr>();
		if (hdr.tcp.valid == false) { goto reject; }
		goto parse_int;
	}
parse_int: {
		if (export_int_metadata(parser, hdr) == false) { goto reject; };
		__u32 key = 1; // Count all packets received
		auto counter_set_ptr = lookup(&counters_map, &key);
		if (counter_set_ptr != nullptr)
		{
			__sync_fetch_and_add(&(counter_set_ptr->packets), 1);
			__sync_fetch_and_add(&(counter_set_ptr->bytes), packetSize);
		}
		goto accept;
	}
accept: {
		if (hdr.shim.valid)
		{
			__u16 int_len = (__u16)hdr.shim.hdr.len * 4;
			if (hdr.udp.valid)
			{
				hdr.udp.hdr.len = bpf_htons(bpf_ntohs(hdr.udp.hdr.len) - int_len);
				hdr.udp.hdr.check = 0;
			}
			if (hdr.ip.valid)
			{
				hdr.ip.hdr.check = bpf_htons(csum_replace2(
					bpf_ntohs(hdr.ip.hdr.check),
					bpf_ntohs(hdr.ip.hdr.tot_len),
					bpf_ntohs(hdr.ip.hdr.tot_len) - int_len
				));
				hdr.ip.hdr.tot_len = bpf_htons(bpf_ntohs(hdr.ip.hdr.tot_len) - int_len);
				hdr.ip.hdr.check = bpf_htons(csum_replace2(
					bpf_ntohs(hdr.ip.hdr.check),
					((__u16)hdr.ip.hdr.version << 12) | ((__u16)hdr.ip.hdr.ihl << 8) | ((__u16)hdr.ip.hdr.dscp << 2)   | ((__u16)hdr.ip.hdr.ecn),
					((__u16)hdr.ip.hdr.version << 12) | ((__u16)hdr.ip.hdr.ihl << 8) | ((__u16)hdr.shim.hdr.dscp << 2) | ((__u16)hdr.ip.hdr.ecn)
				));
				hdr.ip.hdr.dscp = hdr.shim.hdr.dscp;
			}
		}
		goto deparser;
	}
deparser: {
		// Couldn't get unpacking to be inlined to ignore arg count limits
		//if (parser.deparse(hdr.ethernet, hdr.vlan, hdr.qinq, hdr.ip, hdr.udp, hdr.tcp) == false) { goto reject; }

		// Able to be inlined, likely because of simplicity.
		parser.prepare_insert_header(hdr.ethernet, hdr.vlan, hdr.qinq, hdr.ip, hdr.udp, hdr.tcp);
		if (parser.adjust_head() != 0) { goto reject; }
		if (parser.insert_header(hdr.ethernet) == false) { goto reject; }
		if (parser.insert_header(hdr.vlan) == false) { goto reject; }
		if (parser.insert_header(hdr.qinq) == false) { goto reject; }
		if (parser.insert_header(hdr.ip) == false) { goto reject; }
		if (parser.insert_header(hdr.udp) == false) { goto reject; }
		if (parser.insert_header(hdr.tcp) == false) { goto reject; }

		goto pass;
	}
}

struct map_c {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, struct flow_key);
	__type(value, struct counter_set);
} flow_counters_map [[gnu::section(".maps")]];

struct map_d{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, struct flow_key);
	__type(value, struct flow_thresholds);
} flow_thresholds_map [[gnu::section(".maps")]];

struct map_e {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, struct hop_key);
	__type(value, struct hop_thresholds);
} hop_thresholds_map [[gnu::section(".maps")]];

struct map_f{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} perf_output_map [[gnu::section(".maps")]];


#define MAX_HOPS 20

struct flow_accumulator {
	struct hop_key hop_key;
	__u32 latency;
	__u32 sink_time;
};

static inline bool within_threshold(const struct flow_thresholds &thresholds, const struct flow_accumulator &acc)
{
	if (abs(acc.latency, thresholds.hop_latency_threshold) > thresholds.hop_latency_delta ) return false;
	if ( (acc.sink_time - thresholds.sink_time_threshold ) > thresholds.sink_time_delta ) return false;
	if ( acc.hop_key.hop_index != thresholds.total_hops ) return false;
	return true;
}

static inline bool within_threshold(const struct hop_thresholds &thresholds, const struct int_hop_metadata &hop)
{
	if (bpf_ntohl(hop.switch_id) != thresholds.switch_id) return false;
	if (abs((bpf_ntohl(hop.queue_info) & 0xffffff), thresholds.queue_occupancy_threshold ) > thresholds.queue_occupancy_delta) return false;
	if (abs((bpf_ntohl(hop.egress_time) - bpf_ntohl(hop.ingress_time)), thresholds.hop_latency_threshold ) > thresholds.hop_latency_delta) return false;
	return true;
}

static inline bool export_int_metadata(Parser &parser, struct headers &hdr)
{
	int metadata_length = 0;
	int packetSize = parser.packet_size();
	struct flow_accumulator accumulator = {{{0, 0, bpf_ntohs(hdr.vlan.hdr.h_vlan_tag)}, 0}, 0, 0};
	goto parse_shim;
reject: { return false; }
accept: {
		parser.adjust_offset(metadata_length);
		return true;
	}
parse_shim: {
		hdr.shim = parser.extract_header<struct int10_shim_t>();
		if (hdr.shim.valid == false) { goto reject; }
		metadata_length = hdr.shim.hdr.len * 4;
		metadata_length -= sizeof(struct int10_shim_t);
		goto parse_metadata_header;
	}
parse_metadata_header: {
		auto metadata_hdr_ptr = parser.extract<struct INT_md_fix_v10_t>();
		if (metadata_hdr_ptr == nullptr) { goto reject; }
		metadata_length -= sizeof(struct INT_md_fix_v10_t);
		goto parse_metadata;
	}
parse_metadata: {
		if (parser.adjust_head() != 0) { goto reject; }
		for (int i = 0; i < MAX_HOPS; i++)
		{
			if (metadata_length < sizeof(struct int_hop_metadata)) { goto evaluate_flow; }
			auto hop_metadata_ptr = parser.extract<struct int_hop_metadata>();
			if (hop_metadata_ptr == nullptr) { goto reject; }
			metadata_length -= sizeof(struct int_hop_metadata);
			if (accumulator.hop_key.hop_index == 0)
			{
				accumulator.hop_key.flow_key.egress_port = bpf_ntohs(hop_metadata_ptr->egress_port_id);
				accumulator.hop_key.flow_key.switch_id = bpf_ntohl(hop_metadata_ptr->switch_id);
				accumulator.sink_time = bpf_ntohl(hop_metadata_ptr->ingress_time);

				auto counter_set_ptr = lookup(&flow_counters_map, &accumulator.hop_key.flow_key);
				if (counter_set_ptr == nullptr) { goto export_meta; }
				__sync_fetch_and_add(&(counter_set_ptr->packets), 1);
				__sync_fetch_and_add(&(counter_set_ptr->bytes), packetSize);
			}
			auto hop_threshold_ptr = lookup(&hop_thresholds_map, &accumulator.hop_key);
			if (hop_threshold_ptr == nullptr) { goto export_meta; }
			if (within_threshold(*hop_threshold_ptr, *hop_metadata_ptr) == false) { goto export_meta; }
			accumulator.latency += bpf_ntohl(hop_metadata_ptr->egress_time) - bpf_ntohl(hop_metadata_ptr->ingress_time);
			accumulator.hop_key.hop_index += 1;
		}
	}
evaluate_flow: {
		auto flow_thresholds_ptr = lookup(&flow_thresholds_map, &accumulator.hop_key.flow_key);
		if (flow_thresholds_ptr == nullptr) { goto export_meta; }
		if (within_threshold(*flow_thresholds_ptr, accumulator) == false) { goto export_meta; }
	}	goto accept;
export_meta: {
		parser.adjust_offset(metadata_length);
		metadata_length = 0;
		parser.perf_output(&perf_output_map, &accumulator.hop_key);
		goto accept;
	}
}

char _license[] SEC("license") = "GPL";