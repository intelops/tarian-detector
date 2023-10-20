#ifndef __UTILS_C_SHARED_MAPS_H__
#define __UTILS_C_SHARED_MAPS_H__

// generic map defintion
#define BPF_MAP(_map_name_, _map_type_, _key_type_, _value_type_,              \
                _max_entries_)                                                 \
  struct {                                                                     \
    __uint(type, _map_type_);                                                  \
    __type(key, _key_type_);                                                   \
    __uint(value, _value_type_);                                               \
    __uint(max_entries, _max_entries_);                                        \
  } _map_name_ SEC(".maps");

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
    __uint(max_entries, RINGBUF_MAX_ENTRIES);                                              \
  } __name__ SEC(".maps");

// Ringbuf helpers
#define BPF_RINGBUF_SUBMIT(__var__) bpf_ringbuf_submit(__var__, 0)
#define BPF_RINGBUF_DISCARD(__var__) bpf_ringbuf_discard(__var__, 0)
#define BPF_RINGBUF_RESERVE(__map_name__, __var__)                             \
  bpf_ringbuf_reserve(&__map_name__, sizeof(__var__), 0)


BPF_RINGBUF_MAP(EVENT_RINGBUF_MAP_NAME);
#endif