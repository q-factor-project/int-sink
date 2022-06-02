#pragma once

#include <linux/errno.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>


#ifndef memset
# define memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
# define memmove(dest, src, n)  __builtin_memmove((dest), (src), (n))
#endif

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


#define SEC(name) \
	_Pragma("GCC diagnostic push")						\
	_Pragma("GCC diagnostic ignored \"-Wignored-attributes\"")		\
	__attribute__((section(name), used))					\
	_Pragma("GCC diagnostic pop")						\

template<class T>
struct header
{
	T hdr;
	bool valid;
};

class Parser {
public:
	Parser(struct xdp_md *ctx) :
	ctx(ctx),
	packetStart((void*)(long)ctx->data),
	packetEnd((void*)(long)ctx->data_end),
	offset(0) {}

	long long packet_size() const
	{
		return (char*)packetEnd - (char*)packetStart;
	}

	template<class T>
	T* peek() const
	{
		T* ptr = (T*)((char*)packetStart + offset);
		if ((ptr + 1) > packetEnd)
			ptr = nullptr;
		return ptr;
	}

	template<class T>
	T* extract()
	{
		T* ptr = peek<T>();
		if (ptr != nullptr)
			offset += sizeof(T);
		return ptr;
	}

	template<class T>
	header<T> extract_header()
	{
		header<T> header = {};
		T* ptr = extract<T>();
		if (ptr != nullptr)
		{
			header.valid = true;
			header.hdr = *ptr;
		}
		return header;
	}

	long adjust_head()
	{
		long result = bpf_xdp_adjust_head(ctx, offset);
		if (result == 0)
		{
			offset = 0;
			packetStart = (void*)(long)ctx->data;
			packetEnd = (void*)(long)ctx->data_end;
		}
		return result;
	}

	void adjust_offset(int val)
	{
		offset += val;
	}

	template<class... Types>
	void prepare_insert_header(const Types&... hdrs)
	{
		(prepare_insert_header(hdrs) , ...);
	}

	template<class T>
	void prepare_insert_header(const header<T> &hdr)
	{
		if (hdr.valid)
			offset -= sizeof(T);
	}

	template<class T>
	bool insert_header(const header<T> &hdr)
	{
		T* ptr = nullptr;
		if (hdr.valid == true)
		{
			ptr = extract<T>();
			if (ptr != nullptr)
				*ptr = hdr.hdr;
		}
		return ((hdr.valid == true) && (ptr != nullptr)) || ((hdr.valid == false) && (ptr == nullptr));
	}

	template<class...Types>
	bool deparse(const Types&... hdrs)
	{
		(prepare_insert_header(hdrs), ...);
		if (adjust_head() != 0)
			return false;
		return (insert_header(hdrs) && ...);
	}

	template<class T>
	int perf_output(void *map, T *data)
	{
		if (offset < 0)
			return -EINVAL;
		__u64 perf_flags = BPF_F_CURRENT_CPU | (((__u64)offset << 32) & BPF_F_CTXLEN_MASK);
		return bpf_perf_event_output(ctx, map, perf_flags, data, sizeof(T));
	} 
private:
	struct xdp_md *ctx;
	void *packetStart;
	void *packetEnd;
	int offset;
};

constexpr static inline __u16 csum16_add(__u16 csum, __u16 addend) {
	__u16 res = csum;
	res += addend;
	return (res + (res < addend));
}
constexpr static inline __u16 csum16_sub(__u16 csum, __u16 addend) {
	return csum16_add(csum, ~addend);
}
constexpr static inline __u16 csum_replace2(__u16 csum, __u16 old, __u16 next) {
	return (~csum16_add(csum16_sub(~csum, old), next));
}

template<typename T>
constexpr static inline
T abs(const T a, const T b)
{
	if (a > b)
		return a - b;
	else
		return b - a;
}
