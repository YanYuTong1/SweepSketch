#ifndef DPU_H
#define DPU_H

#include <stdint.h>

#define L1_SLOTS 4096u
#define L2_SLOTS 1024u
#define RING_SLOTS 128u

typedef struct {
    uint32_t key;
    uint8_t epoch;
    uint8_t win;
    uint8_t n_new;
    uint8_t n_ewma;
    uint16_t c;
    uint16_t pkt;
    uint16_t pkt_ewma;
    uint8_t held;
    uint8_t hll[32];
    uint8_t pad;
} bucket;

_Static_assert(sizeof(bucket) == 48, "");

typedef struct {
    uint32_t key;
    uint32_t epoch;
    uint16_t n_new;
    uint16_t c;
    uint8_t flags;
    uint8_t pad[19];
} alarm_record;

_Static_assert(sizeof(alarm_record) == 32, "");

void dpu_reset(void);
int dpu_packet(uint32_t dst, uint64_t ts_ns);
uint64_t dpu_l1_alarms(void);
uint64_t dpu_l2_alarms(void);
uint64_t dpu_ring_count(void);
uint64_t dpu_state_sum(void);

#endif
