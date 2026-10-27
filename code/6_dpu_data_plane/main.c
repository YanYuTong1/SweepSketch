#include <stdio.h>
#include <stdint.h>
#include "dpu.h"

int main(void) {
    const uint32_t packets = 1000000u;
    uint32_t i;
    dpu_reset();
    for (i = 0u; i < packets; i++) {
        uint32_t dst = 0x0A000000u | (((i / 256u) & 0xFFu) << 8) | (i & 0xFFu);
        uint64_t ts = (uint64_t)i * 1000000u;
        dpu_packet(dst, ts);
    }
    printf("packets=%u l1_raw=%llu l2_raw=%llu ring=%llu state_sum=%llu\n",
           packets,
           (unsigned long long)dpu_l1_alarms(),
           (unsigned long long)dpu_l2_alarms(),
           (unsigned long long)dpu_ring_count(),
           (unsigned long long)dpu_state_sum());
    return 0;
}
