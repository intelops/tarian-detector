#ifndef __UTILS_STATS_H__
#define __UTILS_STATS_H__

#include "index.h"

stain void stats__add_trigger() {
    tarian_stats_t *ts = (tarian_stats_t *)get__stats_counter();
    if (!ts) return;

    ts->n_trgs++;
}

stain void stats_add_read() {
    tarian_stats_t *ts = (tarian_stats_t *)get__stats_counter();
    if (!ts) return;

    ts->n_trgs_read_error++;
}

stain void stats__add_buffer() {
    tarian_stats_t *ts = (tarian_stats_t *)get__stats_counter();
    if (!ts) return;

    ts->n_trgs_dropped_max_buffer_size++;
}

stain void stats__add(int error_code) {
    tarian_stats_t *ts = (tarian_stats_t *)get__stats_counter();
    if (!ts) return;

    switch (error_code)
    {
    case TDC_SUCCESS:
        ts->n_trgs_sent++;
        break;
    case TDCE_RESERVE_SPACE:
    case TDCE_MAP_SUBMIT:
        ts->n_trgs_dropped_max_map_capacity++;
        ts->n_trgs_dropped++;
        break;
    case TDCE_WRITE_CWD:
        ts->n_trgs_dropped_max_buffer_size++;
        ts->n_trgs_dropped++;
    default:
        ts->n_trgs_unknown++;
        ts->n_trgs_dropped++;
        break;
    }
}
#endif