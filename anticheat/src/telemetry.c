#define _GNU_SOURCE

#include "telemetry.h"

#include <math.h>
#include <stdio.h>

static float shortest_angle(float a) {
    while (a > 180.0f) {
        a -= 360.0f;
    }
    while (a < -180.0f) {
        a += 360.0f;
    }
    return a;
}

float telemetry_speed(const PlayerTick *a, const PlayerTick *b) {
    double dt = b->timestamp - a->timestamp;
    if (dt <= 0.0) {
        return 0.0f;
    }
    float dx = b->x - a->x;
    float dy = b->y - a->y;
    float dz = b->z - a->z;
    float dist = sqrtf(dx * dx + dy * dy + dz * dz);
    return (float)(dist / dt);
}

float telemetry_view_change(const PlayerTick *a, const PlayerTick *b) {
    double dt = b->timestamp - a->timestamp;
    if (dt <= 0.0) {
        return 0.0f;
    }
    float dyaw = fabsf(shortest_angle(b->yaw - a->yaw));
    float dpitch = fabsf(shortest_angle(b->pitch - a->pitch));
    float max_change = (dyaw > dpitch) ? dyaw : dpitch;
    return (float)(max_change / dt);
}

int telemetry_check_speed(const PlayerTick *a, const PlayerTick *b,
                          reporter_t *rep) {
    float v = telemetry_speed(a, b);
    if (v > TELEMETRY_MAX_SPEED) {
        char detail[128];
        snprintf(detail, sizeof(detail), "velocity=%.2f u/s (limit %.1f u/s)",
                 v, TELEMETRY_MAX_SPEED);
        report_add(rep, SEV_HIGH, "telemetry",
                   "speedhack: movement velocity exceeds maximum", detail);
        return 1;
    }
    return 0;
}

int telemetry_check_aimbot(const PlayerTick *prev, const PlayerTick *cur,
                           const PlayerTick *next, reporter_t *rep) {
    float snap = telemetry_view_change(prev, cur);
    float lock = telemetry_view_change(cur, next);
    if (snap > TELEMETRY_SNAP_RATE && lock < TELEMETRY_LOCK_RATE) {
        char detail[128];
        snprintf(detail, sizeof(detail),
                 "snap=%.1f deg/s then locked at %.1f deg/s (no decay curve)",
                 snap, lock);
        report_add(rep, SEV_MEDIUM, "telemetry",
                   "aimbot: instantaneous view snap with no natural decay",
                   detail);
        return 1;
    }
    return 0;
}

int telemetry_run_simulation(reporter_t *rep) {
    int flags = 0;
    report_add(rep, SEV_INFO, "telemetry",
               "simulating anomaly dataset", NULL);

    /* Speedhack anomaly: 5 u in 0.1 s = 50 u/s (limit 15). */
    PlayerTick s0 = {0.0f, 0.0f, 0.0f, 0.0, 0.0f, 0.0f};
    PlayerTick s1 = {5.0f, 0.0f, 0.0f, 0.1, 0.0f, 0.0f};
    flags += telemetry_check_speed(&s0, &s1, rep);

    /* Aimbot anomaly: instant 90 deg snap, then locked (no decay). */
    PlayerTick a0 = {0.0f, 0.0f, 0.0f, 0.0, 0.0f, 0.0f};
    PlayerTick a1 = {0.0f, 0.0f, 0.0f, 0.1, 0.0f, 90.0f};
    PlayerTick a2 = {0.0f, 0.0f, 0.0f, 0.2, 0.0f, 90.0f};
    flags += telemetry_check_aimbot(&a0, &a1, &a2, rep);

    /* Clean control: 10 u/s with a gradual turn (must not flag). */
    PlayerTick c0 = {0.0f, 0.0f, 0.0f, 0.0, 0.0f, 0.0f};
    PlayerTick c1 = {1.0f, 0.0f, 0.0f, 0.1, 0.0f, 10.0f};
    PlayerTick c2 = {2.0f, 0.0f, 0.0f, 0.2, 0.0f, 20.0f};
    telemetry_check_speed(&c0, &c1, rep);
    telemetry_check_aimbot(&c0, &c1, &c2, rep);

    char detail[64];
    snprintf(detail, sizeof(detail), "anomalies flagged=%d", flags);
    report_add(rep, SEV_INFO, "telemetry", "simulation complete", detail);
    return flags;
}