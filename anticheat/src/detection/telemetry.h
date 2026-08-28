#ifndef TELEMETRY_H
#define TELEMETRY_H

#include "report.h"

typedef struct {
    float x;
    float y;
    float z;
    double timestamp;
    float pitch;
    float yaw;
} PlayerTick;

#define TELEMETRY_MAX_SPEED 15.0f
#define TELEMETRY_SNAP_RATE 360.0f
#define TELEMETRY_LOCK_RATE 30.0f

float telemetry_speed(const PlayerTick *a, const PlayerTick *b);
float telemetry_view_change(const PlayerTick *a, const PlayerTick *b);
int telemetry_check_speed(const PlayerTick *a, const PlayerTick *b,
                          reporter_t *rep);
int telemetry_check_aimbot(const PlayerTick *prev, const PlayerTick *cur,
                           const PlayerTick *next, reporter_t *rep);
int telemetry_run_simulation(reporter_t *rep);

#endif