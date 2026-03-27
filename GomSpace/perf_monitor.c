/**
 * @file perf_monitor.c
 * @brief Performance monitor (duration and fixed 10 ms CPU sampling)
 */

#include "perf_monitor.h"

#include <gs/util/log.h>
#include <gs/util/clock.h>

#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"

GS_LOG_GROUP(perf_log, "perf", GS_LOG_CAT_DEFAULT, GS_LOG_DEFAULT_MASK);
#define LOG_DEFAULT perf_log

#define GS_PERF_CPU_SAMPLE_PERIOD_MS  10U
#define GS_PERF_SAMPLER_TASK_STACK    (configMINIMAL_STACK_SIZE + 256)

typedef struct {
    TaskHandle_t sampler_task;
    TaskHandle_t target_task;
    char target_name[16];

    volatile uint8_t running;
    volatile uint8_t stop_requested;

    uint64_t start_timestamp_ms;
    uint64_t end_timestamp_ms;
    uint64_t total_samples;

    uint64_t cpu_sum;
    uint32_t cpu_valid_samples;
    uint16_t cpu_min;
    uint16_t cpu_max;

    uint8_t runtime_valid;
    uint32_t prev_total_runtime;
    uint32_t prev_task_runtime;
} gs_perf_sampler_state_t;

static gs_perf_measurement_t gs_perf_ctx;
static gs_perf_sampler_state_t gs_perf_sampler;
static TaskHandle_t gs_perf_measured_task_handle;

static uint64_t gs_perf_get_time_ms(void)
{
    return gs_clock_get_nsec() / 1000000ULL;
}

static uint32_t gs_perf_get_free_heap(void)
{
    return (uint32_t)xPortGetFreeHeapSize();
}

static TickType_t gs_perf_ms_to_ticks_ceil(uint32_t time_ms)
{
#ifdef pdMS_TO_TICKS
    TickType_t ticks = pdMS_TO_TICKS(time_ms);
#else
    TickType_t ticks = (TickType_t)((((uint64_t)time_ms * (uint64_t)configTICK_RATE_HZ) + 999ULL) / 1000ULL);
#endif
    return (ticks == 0U) ? 1U : ticks;
}

static TickType_t gs_perf_sample_period_ticks(void)
{
    return gs_perf_ms_to_ticks_ceil((uint32_t)GS_PERF_CPU_SAMPLE_PERIOD_MS);
}

static UBaseType_t gs_perf_sampler_task_priority(TaskHandle_t target_task)
{
    UBaseType_t target_priority = tskIDLE_PRIORITY + 1U;

#if (INCLUDE_uxTaskPriorityGet == 1)
    if (target_task != NULL) {
        target_priority = uxTaskPriorityGet(target_task);
    }
#endif

    if (target_priority < (configMAX_PRIORITIES - 1U)) {
        return target_priority + 1U;
    }

    return (configMAX_PRIORITIES - 1U);
}

#if (configGENERATE_RUN_TIME_STATS == 1) && (configUSE_TRACE_FACILITY == 1)
static bool gs_perf_read_runtime(TaskHandle_t target_task, uint32_t *total_runtime, uint32_t *task_runtime)
{
    TaskStatus_t task_status;

    if ((target_task == NULL) || (total_runtime == NULL) || (task_runtime == NULL)) {
        return false;
    }

    *total_runtime = portGET_RUN_TIME_COUNTER_VALUE();
    vTaskGetInfo(target_task, &task_status, pdFALSE, eReady);
    *task_runtime = task_status.ulRunTimeCounter;
    return true;
}
#else
static bool gs_perf_read_runtime(TaskHandle_t target_task, uint32_t *total_runtime, uint32_t *task_runtime)
{
    (void)target_task;
    (void)total_runtime;
    (void)task_runtime;
    return false;
}
#endif

static void gs_perf_sampler_take_sample(void)
{
    uint32_t total_runtime = 0U;
    uint32_t task_runtime = 0U;
    uint32_t total_delta;
    uint32_t task_delta;
    uint16_t cpu = 0U;

    if ((gs_perf_sampler.runtime_valid == 0U) ||
        !gs_perf_read_runtime(gs_perf_sampler.target_task, &total_runtime, &task_runtime)) {
        return;
    }

    total_delta = total_runtime - gs_perf_sampler.prev_total_runtime;
    task_delta = task_runtime - gs_perf_sampler.prev_task_runtime;

    gs_perf_sampler.prev_total_runtime = total_runtime;
    gs_perf_sampler.prev_task_runtime = task_runtime;

    if (total_delta > 0U) {
        cpu = (uint16_t)(((uint64_t)task_delta * 1000ULL) / (uint64_t)total_delta);
        if (cpu > 1000U) {
            cpu = 1000U;
        }
    }

    gs_perf_sampler.cpu_sum += cpu;
    gs_perf_sampler.cpu_valid_samples++;
    gs_perf_sampler.total_samples++;
    if ((gs_perf_sampler.cpu_valid_samples == 1U) || (cpu < gs_perf_sampler.cpu_min)) {
        gs_perf_sampler.cpu_min = cpu;
    }
    if ((gs_perf_sampler.cpu_valid_samples == 1U) || (cpu > gs_perf_sampler.cpu_max)) {
        gs_perf_sampler.cpu_max = cpu;
    }

    gs_perf_sampler.end_timestamp_ms = gs_perf_get_time_ms();
}

static void gs_perf_sampler_task(void *arg)
{
    TickType_t last_wake = xTaskGetTickCount();
    const TickType_t period_ticks = gs_perf_sample_period_ticks();

    (void)arg;

    while (1) {
        if (gs_perf_sampler.stop_requested != 0U) {
            break;
        }
        gs_perf_sampler_take_sample();
        vTaskDelayUntil(&last_wake, period_ticks);
        if (gs_perf_sampler.stop_requested != 0U) {
            break;
        }
    }

    gs_perf_sampler.end_timestamp_ms = gs_perf_get_time_ms();
    gs_perf_sampler.running = 0U;
    gs_perf_sampler.sampler_task = NULL;
    vTaskDelete(NULL);
}

static bool gs_perf_sampler_start(TaskHandle_t target_task)
{
    BaseType_t rc;
    const char *task_name;
    UBaseType_t sampler_priority;

    if (gs_perf_sampler.running != 0U) {
        return true;
    }
    if (target_task == NULL) {
        return false;
    }

    memset(&gs_perf_sampler, 0, sizeof(gs_perf_sampler));
    gs_perf_sampler.target_task = target_task;
    gs_perf_sampler.start_timestamp_ms = gs_perf_get_time_ms();
    gs_perf_sampler.end_timestamp_ms = gs_perf_sampler.start_timestamp_ms;

    task_name = pcTaskGetTaskName(target_task);
    if (task_name != NULL) {
        strncpy(gs_perf_sampler.target_name, task_name, sizeof(gs_perf_sampler.target_name) - 1U);
        gs_perf_sampler.target_name[sizeof(gs_perf_sampler.target_name) - 1U] = '\0';
    }

    if (gs_perf_read_runtime(target_task,
                             &gs_perf_sampler.prev_total_runtime,
                             &gs_perf_sampler.prev_task_runtime)) {
        gs_perf_sampler.runtime_valid = 1U;
    }

    gs_perf_sampler.running = 1U;
    gs_perf_sampler.stop_requested = 0U;
    sampler_priority = gs_perf_sampler_task_priority(target_task);

    rc = xTaskCreate(gs_perf_sampler_task,
                     "perf_cpu_10ms",
                     GS_PERF_SAMPLER_TASK_STACK,
                     NULL,
                     sampler_priority,
                     &gs_perf_sampler.sampler_task);
    if (rc != pdPASS) {
        memset(&gs_perf_sampler, 0, sizeof(gs_perf_sampler));
        return false;
    }

    return true;
}

static void gs_perf_sampler_stop(void)
{
    if (gs_perf_sampler.running == 0U) {
        return;
    }

    gs_perf_sampler.stop_requested = 1U;
    while (gs_perf_sampler.running != 0U) {
        vTaskDelay(gs_perf_ms_to_ticks_ceil(1U));
    }
}

void gs_perf_monitor_init(void)
{
    memset(&gs_perf_ctx, 0, sizeof(gs_perf_ctx));
    memset(&gs_perf_sampler, 0, sizeof(gs_perf_sampler));
    gs_perf_measured_task_handle = NULL;
    log_info("Performance monitor initialized");
}

void gs_perf_monitor_start(const char *name, FILE *out)
{
    FILE *stream = (out != NULL) ? out : stdout;
    const char *task_name;

    if (gs_perf_ctx.is_active != 0U) {
        gs_perf_monitor_stop(stream);
    }

    memset(&gs_perf_ctx, 0, sizeof(gs_perf_ctx));

    if ((name != NULL) && (name[0] != '\0')) {
        strncpy(gs_perf_ctx.operation_name, name, sizeof(gs_perf_ctx.operation_name) - 1U);
    } else {
        strncpy(gs_perf_ctx.operation_name, "unnamed", sizeof(gs_perf_ctx.operation_name) - 1U);
    }
    gs_perf_ctx.operation_name[sizeof(gs_perf_ctx.operation_name) - 1U] = '\0';

    gs_perf_measured_task_handle = xTaskGetCurrentTaskHandle();
    task_name = pcTaskGetTaskName(gs_perf_measured_task_handle);
    if (task_name != NULL) {
        strncpy(gs_perf_ctx.measured_task_name, task_name, sizeof(gs_perf_ctx.measured_task_name) - 1U);
        gs_perf_ctx.measured_task_name[sizeof(gs_perf_ctx.measured_task_name) - 1U] = '\0';
    }

    gs_perf_ctx.start_metrics.timestamp_ms = gs_perf_get_time_ms();
    gs_perf_ctx.start_metrics.valid = 1U;
    gs_perf_ctx.is_active = 1U;

    if (!gs_perf_sampler_start(gs_perf_measured_task_handle)) {
        log_warning("CPU 10 ms sampler start failed");
    }

    fprintf(stream, "=== PERFORMANCE START ===\r\n");
    fprintf(stream, "Operation: %s\r\n", gs_perf_ctx.operation_name);
    fprintf(stream, "Task: %s\r\n", gs_perf_ctx.measured_task_name);
    fprintf(stream, "Start Time: %" PRIu64 " ms\r\n", gs_perf_ctx.start_metrics.timestamp_ms);
    fprintf(stream, "CPU sampling: fixed %" PRIu32 " ms thread\r\n", (uint32_t)GS_PERF_CPU_SAMPLE_PERIOD_MS);
    fprintf(stream, "=========================\r\n");
    fflush(stream);
}

void gs_perf_monitor_stop(FILE *out)
{
    FILE *stream = (out != NULL) ? out : stdout;

    if (gs_perf_ctx.is_active == 0U) {
        return;
    }

    gs_perf_sampler_stop();

    gs_perf_ctx.end_metrics.timestamp_ms = gs_perf_get_time_ms();
    gs_perf_ctx.end_metrics.valid = 1U;
    gs_perf_ctx.duration_ms = gs_perf_ctx.end_metrics.timestamp_ms - gs_perf_ctx.start_metrics.timestamp_ms;

    if (gs_perf_sampler.cpu_valid_samples > 0U) {
        uint16_t avg = (uint16_t)(gs_perf_sampler.cpu_sum / gs_perf_sampler.cpu_valid_samples);
        gs_perf_ctx.cpu_usage_permille = avg;
        gs_perf_ctx.measured_task_usage_permille = avg;
        gs_perf_ctx.runtime_stats_valid = 1U;
        gs_perf_ctx.measured_task_valid = 1U;
    }

    gs_perf_ctx.is_active = 0U;
    gs_perf_monitor_print_results(stream);
}

bool gs_perf_monitor_get_snapshot(gs_perf_metrics_t *metrics)
{
    if (metrics == NULL) {
        return false;
    }

    metrics->timestamp_ms = gs_perf_get_time_ms();
    metrics->free_heap_bytes = gs_perf_get_free_heap();
    metrics->used_heap_bytes = 0U;
    metrics->total_heap_bytes = 0U;
    metrics->valid = 1U;
    return true;
}

void gs_perf_monitor_print_metrics(const gs_perf_metrics_t *metrics, const char *label, FILE *out)
{
    FILE *stream = (out != NULL) ? out : stdout;

    if ((metrics == NULL) || (metrics->valid == 0U)) {
        fprintf(stream, "Invalid metrics\r\n");
        return;
    }

    if (label == NULL) {
        label = "Metrics";
    }

    fprintf(stream, "--- %s ---\r\n", label);
    fprintf(stream, "Timestamp: %" PRIu64 " ms\r\n", metrics->timestamp_ms);
    fprintf(stream, "Free Heap: %" PRIu32 " bytes\r\n", metrics->free_heap_bytes);
    fflush(stream);
}

void gs_perf_monitor_print_results(FILE *out)
{
    FILE *stream = (out != NULL) ? out : stdout;

    if ((gs_perf_ctx.start_metrics.valid == 0U) || (gs_perf_ctx.end_metrics.valid == 0U)) {
        fprintf(stream, "Invalid measurement state\r\n");
        return;
    }

    fprintf(stream, "===== PERFORMANCE RESULTS =====\r\n");
    fprintf(stream, "Operation: %s\r\n", gs_perf_ctx.operation_name);
    fprintf(stream, "Task: %s\r\n", gs_perf_ctx.measured_task_name);
    fprintf(stream, "Timing: start=%" PRIu64 " ms, end=%" PRIu64 " ms, duration=%" PRIu64 " ms\r\n",
            gs_perf_ctx.start_metrics.timestamp_ms,
            gs_perf_ctx.end_metrics.timestamp_ms,
            gs_perf_ctx.duration_ms);

    if (gs_perf_sampler.cpu_valid_samples > 0U) {
        uint32_t avg = (uint32_t)(gs_perf_sampler.cpu_sum / gs_perf_sampler.cpu_valid_samples);
        fprintf(stream, "CPU(%s): avg=%" PRIu32 ".%" PRIu32 "%%, min=%" PRIu16 ".%" PRIu16 "%%, max=%" PRIu16 ".%" PRIu16 "%%\r\n",
                gs_perf_ctx.measured_task_name,
                avg / 10U, avg % 10U,
                (uint16_t)(gs_perf_sampler.cpu_min / 10U), (uint16_t)(gs_perf_sampler.cpu_min % 10U),
                (uint16_t)(gs_perf_sampler.cpu_max / 10U), (uint16_t)(gs_perf_sampler.cpu_max % 10U));
    } else {
        fprintf(stream, "CPU: N/A (runtime stats disabled)\r\n");
    }

    fprintf(stream, "CPU samples: %" PRIu64 " (fixed %" PRIu32 " ms)\r\n",
            gs_perf_sampler.total_samples, (uint32_t)GS_PERF_CPU_SAMPLE_PERIOD_MS);
    fprintf(stream, "==============================\r\n");
    fflush(stream);
}

bool gs_perf_monitor_is_active(void)
{
    return gs_perf_ctx.is_active != 0U;
}

bool gs_perf_trend_start(uint32_t period_ms, uint32_t max_samples)
{
    TaskHandle_t target = gs_perf_measured_task_handle;

    (void)period_ms;
    (void)max_samples;

    if (target == NULL) {
        target = xTaskGetCurrentTaskHandle();
    }

    return gs_perf_sampler_start(target);
}

void gs_perf_trend_stop(void)
{
    gs_perf_sampler_stop();
}

bool gs_perf_trend_is_active(void)
{
    return gs_perf_sampler.running != 0U;
}

void gs_perf_trend_dump(FILE *out)
{
    FILE *stream = (out != NULL) ? out : stdout;
    uint64_t duration_ms = 0U;

    if (gs_perf_sampler.end_timestamp_ms >= gs_perf_sampler.start_timestamp_ms) {
        duration_ms = gs_perf_sampler.end_timestamp_ms - gs_perf_sampler.start_timestamp_ms;
    }

    fprintf(stream, "===== PERFORMANCE TREND =====\r\n");
    fprintf(stream, "Task: %s\r\n", gs_perf_sampler.target_name);
    fprintf(stream, "Period: %" PRIu32 " ms (fixed)\r\n", (uint32_t)GS_PERF_CPU_SAMPLE_PERIOD_MS);
    fprintf(stream, "Duration: %" PRIu64 " ms\r\n", duration_ms);
    fprintf(stream, "Samples: total=%" PRIu64 "\r\n", gs_perf_sampler.total_samples);

    if (gs_perf_sampler.cpu_valid_samples > 0U) {
        uint32_t avg = (uint32_t)(gs_perf_sampler.cpu_sum / gs_perf_sampler.cpu_valid_samples);
        fprintf(stream, "CPU(task): avg=%" PRIu32 ".%" PRIu32 "%%, min=%" PRIu16 ".%" PRIu16 "%%, max=%" PRIu16 ".%" PRIu16 "%%\r\n",
                avg / 10U, avg % 10U,
                (uint16_t)(gs_perf_sampler.cpu_min / 10U), (uint16_t)(gs_perf_sampler.cpu_min % 10U),
                (uint16_t)(gs_perf_sampler.cpu_max / 10U), (uint16_t)(gs_perf_sampler.cpu_max % 10U));
    } else {
        fprintf(stream, "CPU(task): N/A\r\n");
    }

    fprintf(stream, "=============================\r\n");
    fflush(stream);
}