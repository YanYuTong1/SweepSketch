#include "dpu.h"
#include <string.h>

static bucket l1[L1_SLOTS];
static bucket l2[L2_SLOTS];
static alarm_record ring[RING_SLOTS];
static uint32_t ring_head;
static uint64_t l1_alarms;
static uint64_t l2_alarms;
static uint64_t ring_records;

static uint32_t hash32(uint32_t x) {
    x ^= x >> 16;
    x += x << 3;
    x ^= x >> 5;
    x += x << 7;
    x ^= x >> 11;
    x += x << 13;
    return x;
}

static uint8_t rho_of(uint32_t x) {
    uint8_t r = 1;
    if (x == 0u) return 31u;
    while ((x & 0x80000000u) == 0u) {
        x <<= 1;
        r++;
    }
    return r > 31u ? 31u : r;
}

static uint32_t l1_key(uint32_t dst) {
    return dst & 0xFFFFFF00u;
}

static uint32_t l2_key(uint32_t dst) {
    return dst & 0xFFFF0000u;
}

static void ring_push(uint32_t key, uint32_t epoch, uint16_t n_new, uint16_t c, uint8_t flags) {
    alarm_record *r = &ring[ring_head];
    r->key = key;
    r->epoch = epoch;
    r->n_new = n_new;
    r->c = c;
    r->flags = flags;
    memset(r->pad, 0, sizeof(r->pad));
    ring_head = (ring_head + 1u) % RING_SLOTS;
    ring_records++;
}

static int update(bucket *b, uint32_t key, uint32_t epoch, uint32_t seed, uint32_t dst,
                  uint16_t *out_n, uint16_t *out_c) {
    if (b->key != key || b->win == 0u) {
        memset(b, 0, sizeof(*b));
        b->key = key;
        b->epoch = (uint8_t)epoch;
        b->win = 1u;
    } else if (b->epoch != (uint8_t)epoch) {
        uint32_t d2n = 2u * b->n_ewma;
        uint8_t held = 0u;
        int32_t dn;
        int32_t dp;
        if (d2n < 6u) d2n = 6u;
        if (b->pkt >= 200u && b->pkt >= 3u * b->pkt_ewma && b->n_new >= d2n) {
            held = 1u;
        }
        dn = (int32_t)b->n_new - (int32_t)b->n_ewma;
        b->n_ewma = (uint8_t)(b->n_ewma + (dn >> 3));
        dp = (int32_t)b->pkt - (int32_t)b->pkt_ewma;
        b->pkt_ewma = (uint16_t)(b->pkt_ewma + (dp >> 3));
        b->held = held;
        b->n_new = 0u;
        b->pkt = 0u;
        b->win = (uint8_t)(b->win + 1u);
        b->epoch = (uint8_t)epoch;
    }

    {
        uint32_t h = hash32(dst ^ seed);
        uint32_t r = h & 31u;
        uint8_t tag = (uint8_t)(b->win & 7u);
        uint8_t rho = rho_of(h >> 5);
        uint8_t old = b->hll[r];
        uint8_t old_tag = (uint8_t)(old >> 5);
        uint8_t old_rho = (uint8_t)(old & 31u);
        uint8_t event = 0u;
        int32_t c;
        uint32_t gate = 8u;
        uint32_t g2 = 2u * b->n_ewma;
        uint32_t d2n = 6u;
        uint32_t t2 = 2u * b->n_ewma;
        uint8_t a1;
        uint8_t a2;

        if (old_tag != tag || rho > old_rho) {
            event = 1u;
            b->hll[r] = (uint8_t)((tag << 5) | rho);
            if (b->n_new < 255u) b->n_new++;
        }
        if (b->pkt < 65535u) b->pkt++;

        c = (int32_t)b->c + (event ? 38 : -26);
        if (c < 0) c = 0;
        if (c > 65535) c = 65535;
        b->c = (uint16_t)c;

        if (g2 > gate) gate = g2;
        if (b->n_ewma < 4u && gate < 12u) gate = 12u;
        a1 = (b->c >= 74u && b->n_new >= gate) ? 1u : 0u;

        if (t2 > d2n) d2n = t2;
        a2 = (b->pkt >= 200u && b->pkt >= 3u * b->pkt_ewma && b->n_new >= d2n && b->held) ? 1u : 0u;

        *out_n = b->n_new;
        *out_c = b->c;
        return (int)((a1 ? 1u : 0u) | (a2 ? 2u : 0u));
    }
}

void dpu_reset(void) {
    memset(l1, 0, sizeof(l1));
    memset(l2, 0, sizeof(l2));
    memset(ring, 0, sizeof(ring));
    ring_head = 0u;
    l1_alarms = 0u;
    l2_alarms = 0u;
    ring_records = 0u;
}

int dpu_packet(uint32_t dst, uint64_t ts_ns) {
    uint32_t epoch = (uint32_t)(ts_ns >> 32);
    uint32_t k1 = l1_key(dst);
    uint32_t k2 = l2_key(dst);
    uint16_t n1 = 0u;
    uint16_t c1 = 0u;
    uint16_t n2 = 0u;
    uint16_t c2 = 0u;
    int f1 = update(&l1[hash32(k1 ^ 0x11111111u) & (L1_SLOTS - 1u)], k1, epoch,
                    0x11111111u, dst, &n1, &c1);
    int f2 = update(&l2[hash32(k2 ^ 0x22222222u) & (L2_SLOTS - 1u)], k2, epoch,
                    0x22222222u, dst, &n2, &c2);

    if (f1 != 0) {
        l1_alarms++;
        ring_push(k1, epoch, n1, c1, (uint8_t)f1);
    }
    if (f2 != 0) {
        l2_alarms++;
        ring_push(k2, epoch, n2, c2, (uint8_t)f2);
    }
    return (f1 != 0 ? 1 : 0) | (f2 != 0 ? 2 : 0);
}

uint64_t dpu_l1_alarms(void) {
    return l1_alarms;
}

uint64_t dpu_l2_alarms(void) {
    return l2_alarms;
}

uint64_t dpu_ring_count(void) {
    return ring_records;
}

uint64_t dpu_state_sum(void) {
    uint64_t s = 0u;
    uint32_t i;
    for (i = 0u; i < L1_SLOTS; i++) {
        const bucket *b = &l1[i];
        s += b->key + b->c + b->n_new + b->n_ewma + b->pkt + b->pkt_ewma + b->held;
    }
    for (i = 0u; i < L2_SLOTS; i++) {
        const bucket *b = &l2[i];
        s += b->key + b->c + b->n_new + b->n_ewma + b->pkt + b->pkt_ewma + b->held;
    }
    return s;
}
