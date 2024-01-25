#ifndef __UTLIS_TARIAN_H__
#define __UTLIS_TARIAN_H__

enum allocation_type{
    FIXED,
    VARIABLE
};

stain int tdf_reserve_space(tarian_event_t *, enum allocation_type, u64);
stain int tdf_submit_event(tarian_event_t *);
stain int tdf_discard_event(tarian_event_t *);
stain int tdf_save(tarian_event_t *, int, void *);

stain int tdf_reserve_space(tarian_event_t *te, enum allocation_type at, u64 size) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    u64 sz = 0;
    u8 *store = NULL;

    if (at == FIXED) {
        te->allocation_mode = 2;
        store = map__reserve_space(&events, size);
        if (!store) return TDCE_RESERVE_SPACE;
        
        sz = size;
    } else if ( at == VARIABLE) {
        te->allocation_mode = 3;
        store = map__allocate_space(&pea_per_cpu_array);
        if (!store) return TDCE_RESERVE_SPACE;

        sz = MAX_EVENT_SIZE;
    }

#else
    te->allocation_mode = 1;
    u8 *store = map__allocate_space(&pea_per_cpu_array);
    if (!store) return TDCE_RESERVE_SPACE;

    u64 sz = MAX_EVENT_SIZE;
#endif

    te->buf.reserved_space = sz;
    te->buf.pos = 0;
    te->buf.data = store;

    bpf_printk("Execve reserve %s %ld", "success", sz);
    return TDC_SUCCESS;
}

stain int tdf_submit_event(tarian_event_t *te) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    int resp = 0;
    if (te->allocation_mode == 2) {
        resp = map__reserve_submit(te->buf.data);
    } else if (te->allocation_mode == 3) {
        resp = map__pringbuf_submit(&events, te->buf.data, te->buf.pos);
    }
#else
    int resp = map__submit(te->ctx, &events, te->buf.data, te->buf.pos);
#endif
    if (resp != TDC_SUCCESS) return resp;

    return TDC_SUCCESS;
}

stain int tdf_discard_event(tarian_event_t *te) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    int resp = map__discard(te->buf.data);
    if (resp != TDC_SUCCESS) return resp;
#endif

    return TDC_SUCCESS;
};

stain int tdf_save(tarian_event_t *te, int type, void *src) {
    /*
      Data save format: [...data...sizeB]
    */

    switch (type)
    {
    case TDT_U8:
        write_u8(te->buf.data, &te->buf.pos, *((uint8_t *)src));
        break;
    case TDT_U16:
        write_u16(te->buf.data, &te->buf.pos, *((uint16_t *)src));
        break;
    case TDT_U32:
        write_u32(te->buf.data, &te->buf.pos, *((uint32_t *)src));
        break;
    case TDT_U64:
        write_u64(te->buf.data, &te->buf.pos, *((uint64_t *)src));
        break;
    case TDT_S8:
        write_s8(te->buf.data, &te->buf.pos, *((int8_t *)src));
        break;
    case TDT_S16:
        write_s16(te->buf.data, &te->buf.pos, *((int16_t *)src));
        break;
    case TDT_S32:
        write_s32(te->buf.data, &te->buf.pos, *((int32_t *)src));
        break;
    case TDT_S64:
        write_s64(te->buf.data, &te->buf.pos, *((int64_t *)src));
        break;
    case TDT_IPV6:
        // write_ipv6(te->buf.data, te->buf.pos, *((int32_t *)src));
        break;
    default:
        return TDCE_UNKNOWN_TYPE;
    }

    te->tarian->meta_data.nparams++;
    return TDC_SUCCESS;
};

stain int tdf_flex_save(tarian_event_t *te, int type, unsigned long src, enum memory mem) {
    /*
      Data save format: [len 2B][...data...sizeB]
    */
    switch(type) {
        case TDT_STR:
            write_str(te->buf.data, &te->buf.pos, src, MAX_STRING_SIZE, mem);
            break;
        case TDT_STR_ARR:
            write_str_arr(te->buf.data, &te->buf.pos, te->buf.reserved_space,(char **)src, 0);
            break;
        case TDT_BYTE_ARR:
            write_byte_arr(te->buf.data, &te->buf.pos, src, MAX_STRING_SIZE, mem);
            break;
        default:
            return TDCE_UNKNOWN_TYPE;
    }
    
    te->tarian->meta_data.nparams++;
    return TDC_SUCCESS;
};

#endif