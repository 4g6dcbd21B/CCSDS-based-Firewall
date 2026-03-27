/**
 * @file perf_monitor.h
 * @brief Performance monitoring for GomSpace operations
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

typedef struct {
    uint64_t timestamp_ms;
    uint32_t free_heap_bytes;
    uint32_t used_heap_bytes;
    uint32_t total_heap_bytes;
    uint8_t valid;
} gs_perf_metrics_t;

typedef struct {
    gs_perf_metrics_t start_metrics;
    gs_perf_metrics_t end_metrics;
    char operation_name[64];
    char measured_task_name[16];
    uint64_t duration_ms;
    uint16_t cpu_usage_permille;
    uint16_t measured_task_usage_permille;
    uint8_t runtime_stats_valid;
    uint8_t measured_task_valid;
    uint8_t is_active;
} gs_perf_measurement_t;

typedef struct {
    uint64_t timestamp_ms;
    uint32_t free_heap_bytes;
    uint16_t cpu_usage_permille;
    uint8_t cpu_valid;
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