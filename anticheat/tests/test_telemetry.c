#define _GNU_SOURCE
#include "telemetry.h"
#include "report.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static PlayerTick tick(double t, float x, float y, float z,
                       float pitch, float yaw) {
    PlayerTick p;
    p.timestamp = t;
    p.x = x;
    p.y = y;
    p.z = z;
    p.pitch = pitch;
    p.yaw = yaw;
    return p;
}

static int reporter_has(const reporter_t *rep, severity_t sev,
                        const char *module) {
    for (size_t i = 0; i < rep->count; i++) {
        if (rep->findings[i].severity == sev &&
            strcmp(rep->findings[i].module, module) == 0) {
            return 1;
        }
    }
    return 0;
}

static void expect_speed(const char *label, float delta, double expected) {
    PlayerTick a = tick(0, 0, 0, 0, 0, 0);
    PlayerTick b = tick(0.1, delta, 0, 0, 0, 0);
    float got = telemetry_speed(&a, &b);
    if (fabsf(got - (float)expected) > 1e-3f) {
        fprintf(stderr, "FAIL %s: expected ~%.3f, got %.3f\n", label, expected, got);
        failures++;
    } else {
        printf("ok   %s (speed=%.3f)\n", label, got);
    }
}

static void expect_check_speed(const char *label, float delta, int expected) {
    reporter_t rep;
    report_init(&rep, NULL);
    report_set_quiet(1);
    PlayerTick a = tick(0, 0, 0, 0, 0, 0);
    PlayerTick b = tick(0.1, delta, 0, 0, 0, 0);
    int got = telemetry_check_speed(&a, &b, &rep);
    if (got != expected) {
        fprintf(stderr, "FAIL %s: expected %d, got %d\n", label, expected, got);
        failures++;
    } else {
        printf("ok   %s (check_speed=%d)\n", label, got);
    }
}

static void expect_aimbot(const char *label, PlayerTick prev,
                          PlayerTick cur, PlayerTick next, int expected) {
    reporter_t rep;
    report_init(&rep, NULL);
    report_set_quiet(1);
    int got = telemetry_check_aimbot(&prev, &cur, &next, &rep);
    if (got != expected) {
        fprintf(stderr, "FAIL %s: expected %d, got %d\n", label, expected, got);
        failures++;
    } else {
        printf("ok   %s (aimbot=%d)\n", label, got);
    }
}

int main(void) {
    printf("== telemetry: speed boundary (max 15.0 u/s, strict >) ==\n");
    expect_speed("speed exact 15.0", 1.5f, 15.0);
    expect_check_speed("speed under 15 (14.9)", 1.49f, 0);
    expect_check_speed("speed at 15.0 (no flag)", 1.5f, 0);
    expect_check_speed("speed over 15 (15.1)", 1.51f, 1);

    printf("== telemetry: aimbot snap/lock (snap>360, lock<30) ==\n");
    /* Natural gradual turn: no snap. */
    expect_aimbot("natural gradual curve",
                  tick(0.0, 0, 0, 0, 0, 0),
                  tick(0.1, 0, 0, 0, 0, 3),
                  tick(0.2, 0, 0, 0, 0, 6), 0);
    /* Instant snap onto a static target then hold: classic aimbot. */
    expect_aimbot("instant snap + lock",
                  tick(0.0, 0, 0, 0, 0, 0),
                  tick(0.1, 0, 0, 0, 0, 40),
                  tick(0.2, 0, 0, 0, 0, 40), 1);
    /* Fast continuous tracking (decaying aim): not a locked snap. */
    expect_aimbot("fast-but-natural continuous turn (no false positive)",
                  tick(0.0, 0, 0, 0, 0, 0),
                  tick(0.1, 0, 0, 0, 0, 40),
                  tick(0.2, 0, 0, 0, 0, 80), 0);
    /* Boundary: snap exactly 360 deg/s (dt=0.2, dYaw=72) is not >360. */
    expect_aimbot("snap exactly 360 deg/s (boundary, no flag)",
                  tick(0.0, 0, 0, 0, 0, 0),
                  tick(0.2, 0, 0, 0, 0, 72),
                  tick(0.4, 0, 0, 0, 0, 72), 0);
    /* Boundary: just over 360 deg/s triggers. */
    expect_aimbot("snap just over 360 deg/s (flag)",
                  tick(0.0, 0, 0, 0, 0, 0),
                  tick(0.2, 0, 0, 0, 0, 72.1f),
                  tick(0.4, 0, 0, 0, 0, 72.1f), 1);

    printf("== telemetry: bundled simulation dataset ==\n");
    reporter_t sim;
    report_init(&sim, NULL);
    report_set_quiet(1);
    int rc = telemetry_run_simulation(&sim);
    if (rc != 2) {
        fprintf(stderr, "FAIL run_simulation returned %d (expected 2)\n", rc);
        failures++;
    } else {
        printf("ok   run_simulation returned 2 anomalies\n");
    }
    if (!reporter_has(&sim, SEV_HIGH, "telemetry")) {
        fprintf(stderr, "FAIL run_simulation missing HIGH telemetry finding\n");
        failures++;
    } else {
        printf("ok   run_simulation reports HIGH (speedhack)\n");
    }
    if (!reporter_has(&sim, SEV_MEDIUM, "telemetry")) {
        fprintf(stderr, "FAIL run_simulation missing MEDIUM telemetry finding\n");
        failures++;
    } else {
        printf("ok   run_simulation reports MEDIUM (aimbot)\n");
    }

    if (failures) {
        fprintf(stderr, "\n%d test(s) failed\n", failures);
        return 1;
    }
    printf("\nall telemetry tests passed\n");
    return 0;
}
