#ifndef UTILS_SHARED_MAPS_H
#define UTILS_SHARED_MAPS_H

// generic bpf map
#define BPF_MAP(_map_name, _map_type, _key_type, _value_type, _max_entries)    \
  struct {                                                                     \
    __uint(type, _map_type);                                                   \
    __uint(max_entries, _max_entries);                                         \
    __type(key, _key_type);                                                    \
    __type(value, _value_type);                                                \
  } _map_name SEC(".maps");

// perf event array
#define BPF_PERF_EVENT_ARRAY(_map_name, _key_type, _value_type, _max_entries)  \
  BPF_MAP(_map_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, _key_type, _value_type,    \
          _max_entries);

// percpu array
#define BPF_PERCPU_ARRAY(_map_name, _value_type, _max_entries)                 \
  BPF_MAP(_map_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries);

// LRU Hash map
#define BPF_LRU_HASH(_map_name, _key_type, _value_type, _max_entries)          \
  BPF_MAP(_map_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type,            \
          _max_entries);

#define BPF_ARRAY_OF_MAPS(_map_name, _key_type, _array_value_type, _values,    \
                          _max_entries)                                        \
  struct {                                                                     \
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);                                  \
    __uint(max_entries, _max_entries);                                         \
    __type(key, _key_type);                                                    \
    __array(values, _array_value_type);                                        \
  } _map_name SEC(".maps") = {.values = _values};

// Ringbuf helpers
#define BPF_RINGBUF_SUBMIT(__var__) bpf_ringbuf_submit(__var__, 0)
#define BPF_RINGBUF_DISCARD(__var__) bpf_ringbuf_discard(__var__, 0)
#define BPF_RINGBUF_RESERVE(__map_name__, __size__)                            \
  bpf_ringbuf_reserve(&__map_name__, __size__, 0)

struct statistics{
__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
__uint(max_entries, 1);
__type(key, uint32_t);
__type(value, tarian_stats_t);
} tarian_stats SEC(".maps");

stain void *get__stats_counter() {
  uint32_t index = 0;
  return bpf_map_lookup_elem(&tarian_stats, &index);
}

struct scratch{
__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
__uint(max_entries, 1);
__type(key, uint32_t);
__type(value, scratch_space_t);
} scratch_space SEC(".maps");

stain void *get__scratch_space() {
  uint32_t index = 0;
  return bpf_map_lookup_elem(&scratch_space, &index);
}
/*
* 
* PER_CPU_ARRAY
* This map is used a temporary space before pushing
* it into perf event array
* 
*/
struct {
__uint(type, BPF_MAP_TYPE_ARRAY);
__uint(max_entries, 16);
__type(key, uint32_t);
__type(value, per_cpu_buffer_t);
} pea_per_cpu_array SEC(".maps");

stain void *get__current_cpu_buf(void *map) {
    uint32_t cpu_id = (uint32_t)bpf_get_smp_processor_id();
    return bpf_map_lookup_elem(map, &cpu_id);
}

stain void *map__allocate_space(void *map) {
  return get__current_cpu_buf(map);
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  /*
  *
  * RINGBUF
  * This map is used for sending events to
  * userspace
  *
  */
  struct ringbuf {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_MAX_ENTRIES);
  };

  #define BPF_RINGBUF(_map_name) struct ringbuf _map_name SEC(".maps");

  BPF_RINGBUF(erb_cpu0);
  BPF_RINGBUF(erb_cpu1);
  BPF_RINGBUF(erb_cpu2);
  BPF_RINGBUF(erb_cpu3);
  BPF_RINGBUF(erb_cpu4);
  BPF_RINGBUF(erb_cpu5);
  BPF_RINGBUF(erb_cpu6);
  BPF_RINGBUF(erb_cpu7);
  BPF_RINGBUF(erb_cpu8);
  BPF_RINGBUF(erb_cpu9);
  BPF_RINGBUF(erb_cpu10);
  BPF_RINGBUF(erb_cpu11);
  BPF_RINGBUF(erb_cpu12);
  BPF_RINGBUF(erb_cpu13);
  BPF_RINGBUF(erb_cpu14);
  BPF_RINGBUF(erb_cpu15);

  struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, ARRAY_OF_MAPS_MAX_ENTRIES);
    __type(key, u32);
    __array(values, struct ringbuf);
  } events SEC(".maps") = {.values = {
                              &erb_cpu0,
                              &erb_cpu1,
                              &erb_cpu2,
                              &erb_cpu3,
                              &erb_cpu4,
                              &erb_cpu5,
                              &erb_cpu6,
                              &erb_cpu7,
                              &erb_cpu8,
                              &erb_cpu9,
                              &erb_cpu10,
                              &erb_cpu11,
                              &erb_cpu12,
                              &erb_cpu13,
                              &erb_cpu14,
                              &erb_cpu15,
                          }};

  stain struct ringbuffer *get_cpu_ringbuffer(void *map) {
    uint32_t cpu_id = (uint32_t)bpf_get_smp_processor_id();
	  return (struct ringbuffer *)bpf_map_lookup_elem(map, &cpu_id);
  }

  stain void *map__reserve_space(void *map, u64 size) {
    struct ringbuffer *rbuf = get_cpu_ringbuffer(map);
    if (!rbuf) return NULL;

    return bpf_ringbuf_reserve(rbuf, size, 0);
  };

  stain int map__reserve_submit(void *data) {
    if (!data) return TDCE_NULL_POINTER;
    
    bpf_ringbuf_submit(data, 0);

    return TDC_SUCCESS;
  };

  stain int map__submit(void *map, void *data, u64 size) {
    if (!map || !data) return TDCE_NULL_POINTER;
    
    if (bpf_ringbuf_output(map, data, size, 0) != 0) return TDCE_MAP_SUBMIT;

    return TDC_SUCCESS;
  }

  stain int map__pringbuf_submit(void *map, void *data, u64 size) {
    if (!data) return TDCE_NULL_POINTER;
    
    struct ringbuffer *rbuf = get_cpu_ringbuffer(map);
    if (!rbuf) return TDCE_MAP_SUBMIT;

    return map__submit(rbuf, data, size);
  }

  stain int map__discard(void *data) {
    if (!data) return TDCE_NULL_POINTER;
    
    bpf_ringbuf_discard(data, 0);

    return TDC_SUCCESS;
  };

#else
  /*
  * 
  * PERF_EVENT_ARRAY
  * This map is used as an fallback map 
  * on kernel version which do not support ringbuf
  * 
  */
  struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
  } events SEC(".maps");

  stain int map__submit(void *ctx, void *map, void *data, u64 size) {
    if (!map || !data) return TDCE_NULL_POINTER;

    if (bpf_perf_event_output(ctx, map, BPF_F_CURRENT_CPU, data, size) != 0) return TDCE_MAP_SUBMIT;

    return TDC_SUCCESS;
  };
#endif

#endif