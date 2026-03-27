/**
 * @file perf_monitor.h
 * @brief Performance monitoring for CCSDS inspection (cFS port)
 */

#ifndef GS_PERF_MONITOR_H
#define GS_PERF_MONITOR_H

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Performance metrics snapshot
 */
typedef struct {
    uint64_t timestamp_ms;
    uint64_t free_heap_bytes;
    uint64_t used_heap_bytes;
    uint64_t total_heap_bytes;
    uint8_t  valid;
} gs_perf_metrics_t;

/**
 * @brief Performance measurement context
 */
typedef struct {
    gs_perf_metrics_t start_metrics;
    gs_perf_metrics_t end_metrics;
    char operation_name[64];
    uint64_t duration_ms;
    int64_t heap_delta;
    uint32_t start_total_runtime;
    uint32_t end_total_runtime;
    uint32_t start_idle_runtime;
    uint32_t end_idle_runtime;
    uint16_t cpu_usage_permille;
    uint8_t runtime_stats_valid;
    int16_t start_temp_eps0;
    int16_t end_temp_eps0;
    int16_t temp_delta_eps0;
    uint8_t temp_start_valid;
    uint8_t temp_end_valid;
    uint8_t is_active;
} gs_perf_measurement_t;

/**
 * @brief Trend sample for continuous monitoring
 */
typedef struct {
    uint64_t timestamp_ms;
    uint64_t free_heap_bytes;
    uint16_t cpu_usage_permille;
    uint8_t  cpu_valid;
    int16_t  temp_eps0;
    uint8_t  temp_valid;
} gs_perf_trend_sample_t;

void gs_perf_monitor_init(void);
void gs_perf_monitor_start(const char *name, FILE *out);
void gs_perf_monitor_stop(FILE *out);
bool gs_perf_monitor_get_snapshot(gs_perf_metrics_t *metrics);
void gs_perf_monitor_print_metrics(const gs_perf_metrics_t *metrics, const char *label, FILE *out);
void gs_perf_monitor_print_results(FILE *out);
bool gs_perf_monitor_is_active(void);

bool gs_perf_trend_start(uint32_t period_ms, uint32_t max_samples);
void gs_perf_trend_stop(void);
bool gs_perf_trend_is_active(void);
void gs_perf_trend_dump(FILE *out);

#ifdef __cplusplus
}
#endif

#endif /* GS_PERF_MONITOR_H */
