#pragma once

#include <linux/errno.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>

static void *(*bpf_map_lookup_elem)(void *map, const void * key) = reinterpret_cast<void*(*)(void*,const void*)>(BPF_FUNC_map_lookup_elem);

static long (*bpf_xdp_adjust_head)(struct xdp_md *xdp_md, int delta) = reinterpret_cast<long(*)(struct xdp_md*, int)>(BPF_FUNC_xdp_adjust_head);

static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = reinterpret_cast<long(*)(void *, void *, __u64, void *, __u64)>(BPF_FUNC_perf_event_output);

/*
template<class Key, class T,
	 enum bpf_map_type map_type = BPF_MAP_TYPE_UNSPEC,
	 int entries = 1>
struct map
{
	using key_type = Key;
	using mapped_type = T;
	int (*type)[map_type];
	int (*max_entries)[entries];
	key_type *key;
	mapped_type *value;
};
*/

#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define __array(name, val) val *name[]

template<class Map>
auto lookup(Map *map, const decltype(map->key) key)
{
	return (decltype(map->value)) bpf_map_lookup_elem(map, key);
}
