#ifndef __UTILS_C_SHARED_MAPS_H__
#define __UTILS_C_SHARED_MAPS_H__

// generic map defintion
#define BPF_MAP(_map_name_, _map_type_, _key_type_, _value_type_, _max_entries_)                                                 \
  struct {                                                                     \
    __uint(type, _map_type_);                                                  \
    __type(key, _key_type_);                                                   \
    __uint(value, _value_type_);                                               \
    __uint(max_entries, _max_entries_);                                        \
  } _map_name_ SEC(".maps");

// perf event
#define BPF_PERF_EVENT_ARRAY(__name__, __key__, __value__) \
  BPF_MAP(__name__, BPF_MAP_TYPE_PERF_EVENT_ARRAY,__key__, __value__, 1024);

// percpu map defintion
#define BPF_PERCPU_ARRAY(__name__, __value__, __max_entries__)                 \
  BPF_MAP(__name__, BPF_MAP_TYPE_PERCPU_ARRAY, u32, __value__, __max_entries__);

// hash map defintion
#define BPF_HASH(__name__, __key__, __value__)                                 \
  BPF_MAP(__name__, BPF_MAP_TYPE_HASH, __key__, __value__, 10240);

// ringbuf map definition
#define BPF_RINGBUF_MAP(__name__)                                              \
  struct {                                                                     \
    __uint(type, BPF_MAP_TYPE_RINGBUF);                                        \
    __uint(max_entries, RINGBUF_MAX_ENTRIES);                                   \
  } __name__ SEC(".maps");

// Ringbuf helpers
#define BPF_RINGBUF_SUBMIT(__var__) bpf_ringbuf_submit(__var__, 0)
#define BPF_RINGBUF_DISCARD(__var__) bpf_ringbuf_discard(__var__, 0)
#define BPF_RINGBUF_RESERVE(__map_name__, __size__)                             \
  bpf_ringbuf_reserve(&__map_name__, __size__, 0)


BPF_RINGBUF_MAP(EVENT_RINGBUF_MAP_NAME);
// BPF_PERCPU_ARRAY(heap, sizeof(struct event_data), 1);
// BPF_PERF_EVENT_ARRAY(perf_events, int, sizeof(u32));


struct ringbuffer{                                                                     
__uint(type, BPF_MAP_TYPE_RINGBUF);                                       
__uint(max_entries, 16 * 1024 * 1024);                                   
} rb_cpu0 SEC(".maps"), rb_cpu1 SEC(".maps"), rb_cpu2 SEC(".maps"), rb_cpu3 SEC(".maps"), rb_cpu4 SEC(".maps"),
rb_cpu5 SEC(".maps"), rb_cpu6 SEC(".maps"), rb_cpu7 SEC(".maps"), rb_cpu8 SEC(".maps"),
rb_cpu9 SEC(".maps"), rb_cpu10 SEC(".maps"), rb_cpu11 SEC(".maps"), rb_cpu12 SEC(".maps"),
rb_cpu13 SEC(".maps"), rb_cpu14 SEC(".maps"), rb_cpu15 SEC(".maps");

/**
 * This array of maps will contain a variable number of ring buffers
 * according to the user-provided configuration. It could also contain only
 * one buffer shared between all CPUs. 
 */
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __uint(max_entries, 16);                                   
	__type(key, uint32_t);
	__array(values, struct ringbuffer);
} percpu_rb SEC(".maps") = {
  .values = {
    &rb_cpu0,
    &rb_cpu1,
    &rb_cpu2,
    &rb_cpu3,
    &rb_cpu4,
    &rb_cpu5,
    &rb_cpu6,
    &rb_cpu7,
    &rb_cpu8,
    &rb_cpu9,
    &rb_cpu10,
    &rb_cpu11,
    &rb_cpu12,
    &rb_cpu13,
    &rb_cpu14,
    &rb_cpu15,
  }
};

#endif