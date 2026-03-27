/**
 * @file perf_monitor.c
 * @brief Performance monitoring implementation (cFS port, Linux)
 */

#include "perf_monitor.h"
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <time.h>
#include <errno.h>
#include "osapi.h"

/* Global measurement context */
static gs_perf_measurement_t gs_perf_ctx;

#define GS_PERF_TREND_MAX_SAMPLES       2048U
#define GS_PERF_TREND_DEFAULT_PERIOD_MS 10U
#define GS_PERF_TREND_MIN_PERIOD_MS     1U
#define GS_PERF_TREND_MAX_PERIOD_MS     10000U
#define GS_PERF_TREND_TASK_STACK_SIZE   OSAL_SIZE_C(4096)
#define GS_PERF_TREND_TASK_PRIORITY     OSAL_PRIORITY_C(40)
#define GS_PERF_TREND_IDLE_DELAY_MS     100U

typedef struct
{
    uint64_t cpu_time_ns;
    uint64_t wall_time_ns;
} gs_perf_cpu_sample_t;

typedef struct
{
    uint8_t  enabled;
    uint8_t  overflow;
    uint32_t period_ms;
    uint32_t max_samples;
    uint32_t sample_count;
    uint32_t head;
    uint64_t start_timestamp_ms;
    uint64_t end_timestamp_ms;
    uint64_t next_sample_due_ms;

    uint64_t total_samples;
    uint64_t cpu_valid_samples;
    uint64_t cpu_sum;
    uint16_t cpu_min;
    uint16_t cpu_max;

    gs_perf_cpu_sample_t last_sample;
    uint8_t              last_sample_valid;
} gs_perf_trend_state_t;

static gs_perf_trend_sample_t gs_perf_trend_samples[GS_PERF_TREND_MAX_SAMPLES];
static gs_perf_trend_state_t  gs_perf_trend_state;
static osal_id_t              gs_perf_trend_task_id;
static volatile uint8_t       gs_perf_trend_task_running = 0U;

static gs_perf_cpu_sample_t gs_perf_measure_start_sample;
static uint8_t              gs_perf_measure_start_valid;

static void gs_perf_trend_task(void);
static bool gs_perf_trend_ensure_task(void);

static uint64_t gs_perf_get_time_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    {
        return 0ULL;
    }

    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

static uint64_t gs_perf_timespec_to_ns(const struct timespec *ts)
{
    if (ts == NULL)
    {
        return 0ULL;
    }

    return ((uint64_t)ts->tv_sec * 1000000000ULL) + (uint64_t)ts->tv_nsec;
}

static void gs_perf_sleep_until_ms(uint64_t target_ms)
{
    struct timespec wake_ts;
    int status;

    wake_ts.tv_sec = (time_t)(target_ms / 1000ULL);
    wake_ts.tv_nsec = (long)((target_ms % 1000ULL) * 1000000ULL);

    do
    {
        status = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &wake_ts, NULL);
    } while (status == EINTR);
}

static bool gs_perf_read_process_cpu_sample(gs_perf_cpu_sample_t *sample)
{
    struct timespec cpu_ts;
    struct timespec wall_ts;

    if (sample == NULL)
    {
        return false;
    }

#if defined(CLOCK_PROCESS_CPUTIME_ID)
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_ts) != 0)
    {
        return false;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &wall_ts) != 0)
    {
        return false;
    }

    sample->cpu_time_ns = gs_perf_timespec_to_ns(&cpu_ts);
    sample->wall_time_ns = gs_perf_timespec_to_ns(&wall_ts);
    return true;
#else
    (void)cpu_ts;
    (void)wall_ts;
    return false;
#endif
}

static bool gs_perf_compute_cpu_usage_permille(const gs_perf_cpu_sample_t *start_sample,
                                                const gs_perf_cpu_sample_t *end_sample,
                                                uint16_t *usage_permille)
{
    uint64_t cpu_delta_ns;
    uint64_t wall_delta_ns;
    uint64_t usage;

    if (start_sample == NULL || end_sample == NULL || usage_permille == NULL)
    {
        return false;
    }

    if (end_sample->cpu_time_ns < start_sample->cpu_time_ns ||
        end_sample->wall_time_ns <= start_sample->wall_time_ns)
    {
        return false;
    }

    cpu_delta_ns = end_sample->cpu_time_ns - start_sample->cpu_time_ns;
    wall_delta_ns = end_sample->wall_time_ns - start_sample->wall_time_ns;
    if (wall_delta_ns == 0U)
    {
        return false;
    }

    usage = (cpu_delta_ns * 1000ULL) / wall_delta_ns;
    if (usage > 1000ULL)
    {
        usage = 1000ULL;
    }

    *usage_permille = (uint16_t)usage;
    return true;
}

static uint32_t gs_perf_trend_clamp_period(uint32_t period_ms)
{
    if (period_ms == 0U)
    {
        return GS_PERF_TREND_DEFAULT_PERIOD_MS;
    }
    if (period_ms < GS_PERF_TREND_MIN_PERIOD_MS)
    {
        return GS_PERF_TREND_MIN_PERIOD_MS;
    }
    if (period_ms > GS_PERF_TREND_MAX_PERIOD_MS)
    {
        return GS_PERF_TREND_MAX_PERIOD_MS;
    }
    return period_ms;
}

static uint32_t gs_perf_trend_clamp_samples(uint32_t max_samples)
{
    if (max_samples == 0U)
    {
        return GS_PERF_TREND_MAX_SAMPLES;
    }
    if (max_samples > GS_PERF_TREND_MAX_SAMPLES)
    {
        return GS_PERF_TREND_MAX_SAMPLES;
    }
    return max_samples;
}

static void gs_perf_trend_sample_once(void)
{
    uint32_t idx;
    gs_perf_trend_sample_t *sample;
    gs_perf_cpu_sample_t current_sample;
    uint16_t usage_permille;

    idx = gs_perf_trend_state.head;
    sample = &gs_perf_trend_samples[idx];

    sample->timestamp_ms = gs_perf_get_time_ms();
    sample->free_heap_bytes = 0ULL;
    sample->temp_eps0 = 0;
    sample->temp_valid = 0U;
    sample->cpu_usage_permille = 0U;
    sample->cpu_valid = 0U;

    if (gs_perf_read_process_cpu_sample(&current_sample))
    {
        if (gs_perf_trend_state.last_sample_valid != 0U &&
            gs_perf_compute_cpu_usage_permille(&gs_perf_trend_state.last_sample, &current_sample, &usage_permille))
        {
            sample->cpu_usage_permille = usage_permille;
            sample->cpu_valid = 1U;
        }

        gs_perf_trend_state.last_sample = current_sample;
        gs_perf_trend_state.last_sample_valid = 1U;
    }

    gs_perf_trend_state.head = (gs_perf_trend_state.head + 1U) % gs_perf_trend_state.max_samples;
    if (gs_perf_trend_state.sample_count < gs_perf_trend_state.max_samples)
    {
        gs_perf_trend_state.sample_count++;
    }
    else
    {
        gs_perf_trend_state.overflow = 1U;
    }

    gs_perf_trend_state.total_samples++;
    if (sample->cpu_valid != 0U)
    {
        gs_perf_trend_state.cpu_valid_samples++;
        gs_perf_trend_state.cpu_sum += sample->cpu_usage_permille;

        if (gs_perf_trend_state.cpu_valid_samples == 1U || sample->cpu_usage_permille < gs_perf_trend_state.cpu_min)
        {
            gs_perf_trend_state.cpu_min = sample->cpu_usage_permille;
        }
        if (gs_perf_trend_state.cpu_valid_samples == 1U || sample->cpu_usage_permille > gs_perf_trend_state.cpu_max)
        {
            gs_perf_trend_state.cpu_max = sample->cpu_usage_permille;
        }
    }
}

static void gs_perf_trend_task(void)
{
    uint64_t now_ms;
    uint64_t due_ms;

    while (gs_perf_trend_task_running != 0U)
    {
        if (gs_perf_trend_state.enabled != 0U)
        {
            now_ms = gs_perf_get_time_ms();
            due_ms = gs_perf_trend_state.next_sample_due_ms;

            if (due_ms == 0U || now_ms >= due_ms)
            {
                gs_perf_trend_sample_once();

                now_ms = gs_perf_get_time_ms();
                if (due_ms == 0U)
                {
                    due_ms = now_ms;
                }

                do
                {
                    due_ms += gs_perf_trend_state.period_ms;
                } while (due_ms <= now_ms);

                gs_perf_trend_state.next_sample_due_ms = due_ms;
                continue;
            }

            gs_perf_sleep_until_ms(due_ms);
        }
        else
        {
            gs_perf_trend_state.next_sample_due_ms = 0U;
            now_ms = gs_perf_get_time_ms();
            gs_perf_sleep_until_ms(now_ms + GS_PERF_TREND_IDLE_DELAY_MS);
        }
    }

    OS_TaskExit();
}

static bool gs_perf_trend_ensure_task(void)
{
    int32 os_status;

    if (OS_ObjectIdDefined(gs_perf_trend_task_id))
    {
        return true;
    }

    gs_perf_trend_task_running = 1U;
    os_status = OS_TaskCreate(&gs_perf_trend_task_id, "PERF_TREND",
                              gs_perf_trend_task,
                              OSAL_TASK_STACK_ALLOCATE,
                              GS_PERF_TREND_TASK_STACK_SIZE,
                              GS_PERF_TREND_TASK_PRIORITY,
                              0);
    if (os_status != OS_SUCCESS)
    {
        gs_perf_trend_task_running = 0U;
        gs_perf_trend_task_id = OS_OBJECT_ID_UNDEFINED;
        return false;
    }

    return true;
}

void gs_perf_monitor_init(void)
{
    memset(&gs_perf_ctx, 0, sizeof(gs_perf_ctx));
    memset(&gs_perf_trend_state, 0, sizeof(gs_perf_trend_state));
    memset(&gs_perf_measure_start_sample, 0, sizeof(gs_perf_measure_start_sample));

    gs_perf_trend_task_id = OS_OBJECT_ID_UNDEFINED;
    gs_perf_trend_task_running = 0U;
    gs_perf_measure_start_valid = 0U;
}

void gs_perf_monitor_start(const char *name, FILE *out)
{
    FILE *stream = (out != NULL) ? out : stdout;

    if (gs_perf_ctx.is_active != 0U)
    {
        gs_perf_monitor_stop(stream);
    }

    memset(&gs_perf_ctx, 0, sizeof(gs_perf_ctx));

    if (name != NULL)
    {
        strncpy(gs_perf_ctx.operation_name, name, sizeof(gs_perf_ctx.operation_name) - 1U);
        gs_perf_ctx.operation_name[sizeof(gs_perf_ctx.operation_name) - 1U] = '\0';
    }
    else
    {
        strcpy(gs_perf_ctx.operation_name, "unnamed");
    }

    gs_perf_ctx.start_metrics.timestamp_ms = gs_perf_get_time_ms();
    gs_perf_ctx.start_metrics.free_heap_bytes = 0ULL;
    gs_perf_ctx.start_metrics.used_heap_bytes = 0ULL;
    gs_perf_ctx.start_metrics.total_heap_bytes = 0ULL;
    gs_perf_ctx.start_metrics.valid = 1U;

    gs_perf_measure_start_valid = gs_perf_read_process_cpu_sample(&gs_perf_measure_start_sample) ? 1U : 0U;
    gs_perf_ctx.is_active = 1U;

    fprintf(stream, "=== PERFORMANCE MEASUREMENT START ===\n");
    fprintf(stream, "Operation: %s\n", gs_perf_ctx.operation_name);
    fprintf(stream, "Timestamp: %" PRIu64 " ms\n", gs_perf_ctx.start_metrics.timestamp_ms);
    fprintf(stream, "=====================================\n");
    fflush(stream);
}

void gs_perf_monitor_stop(FILE *out)
{
    FILE *stream = (out != NULL) ? out : stdout;
    gs_perf_cpu_sample_t end_sample;
    uint16_t usage_permille;

    if (gs_perf_ctx.is_active == 0U)
    {
        return;
    }

    gs_perf_ctx.end_metrics.timestamp_ms = gs_perf_get_time_ms();
    gs_perf_ctx.end_metrics.free_heap_bytes = 0ULL;
    gs_perf_ctx.end_metrics.used_heap_bytes = 0ULL;
    gs_perf_ctx.end_metrics.total_heap_bytes = 0ULL;
    gs_perf_ctx.end_metrics.valid = 1U;

    gs_perf_ctx.duration_ms = gs_perf_ctx.end_metrics.timestamp_ms - gs_perf_ctx.start_metrics.timestamp_ms;
    gs_perf_ctx.heap_delta = 0;

    gs_perf_ctx.cpu_usage_permille = 0U;
    if (gs_perf_measure_start_valid != 0U &&
        gs_perf_read_process_cpu_sample(&end_sample) &&
        gs_perf_compute_cpu_usage_permille(&gs_perf_measure_start_sample, &end_sample, &usage_permille))
    {
        gs_perf_ctx.cpu_usage_permille = usage_permille;
    }

    gs_perf_ctx.temp_start_valid = 0U;
    gs_perf_ctx.temp_end_valid = 0U;
    gs_perf_ctx.start_temp_eps0 = 0;
    gs_perf_ctx.end_temp_eps0 = 0;
    gs_perf_ctx.temp_delta_eps0 = 0;

    gs_perf_ctx.is_active = 0U;

    gs_perf_monitor_print_results(stream);
}

bool gs_perf_monitor_get_snapshot(gs_perf_metrics_t *metrics)
{
    if (metrics == NULL)
    {
        return false;
    }

    metrics->timestamp_ms = gs_perf_get_time_ms();
    metrics->free_heap_bytes = 0ULL;
    metrics->used_heap_bytes = 0ULL;
    metrics->total_heap_bytes = 0ULL;
    metrics->valid = 1U;

    return true;
}

void gs_perf_monitor_print_metrics(const gs_perf_metrics_t *metrics, const char *label, FILE *out)
{
    FILE *stream = (out != NULL) ? out : stdout;

    if (metrics == NULL || metrics->valid == 0U)
    {
        fprintf(stream, "Invalid metrics\n");
        return;
    }

    if (label == NULL)
    {
        label = "Metrics";
    }

    fprintf(stream, "--- %s ---\n", label);
    fprintf(stream, "  Timestamp:    %" PRIu64 " ms\n", metrics->timestamp_ms);
    fflush(stream);
}

void gs_perf_monitor_print_results(FILE *out)
{
    FILE *stream = (out != NULL) ? out : stdout;

    if (gs_perf_ctx.start_metrics.valid == 0U || gs_perf_ctx.end_metrics.valid == 0U)
    {
        fprintf(stream, "Invalid measurement state\n");
        return;
    }

    fprintf(stream, "===== PERFORMANCE MEASUREMENT RESULTS =====\n");
    fprintf(stream, "Operation: %s\n", gs_perf_ctx.operation_name);
    fprintf(stream, "Timing: Start: %" PRIu64 " ms, End: %" PRIu64 " ms, Duration: %" PRIu64 " ms\n",
            gs_perf_ctx.start_metrics.timestamp_ms,
            gs_perf_ctx.end_metrics.timestamp_ms,
            gs_perf_ctx.duration_ms);
    fprintf(stream, "CPU Usage: %u.%u%%\n",
            (unsigned int)(gs_perf_ctx.cpu_usage_permille / 10U),
            (unsigned int)(gs_perf_ctx.cpu_usage_permille % 10U));
    fprintf(stream, "==========================================\n");
    fprintf(stream, "Performance: %s completed in %" PRIu64 " ms\n",
            gs_perf_ctx.operation_name, gs_perf_ctx.duration_ms);
    fflush(stream);
}

bool gs_perf_monitor_is_active(void)
{
    return (gs_perf_ctx.is_active != 0U);
}

bool gs_perf_trend_start(uint32_t period_ms, uint32_t max_samples)
{
    if (!gs_perf_trend_ensure_task())
    {
        return false;
    }

    memset(&gs_perf_trend_state, 0, sizeof(gs_perf_trend_state));
    gs_perf_trend_state.period_ms = gs_perf_trend_clamp_period(period_ms);
    gs_perf_trend_state.max_samples = gs_perf_trend_clamp_samples(max_samples);
    gs_perf_trend_state.start_timestamp_ms = gs_perf_get_time_ms();
    gs_perf_trend_state.end_timestamp_ms = gs_perf_trend_state.start_timestamp_ms;
    gs_perf_trend_state.enabled = 1U;

    gs_perf_trend_sample_once();
    gs_perf_trend_state.next_sample_due_ms = gs_perf_trend_state.start_timestamp_ms + gs_perf_trend_state.period_ms;

    return true;
}

void gs_perf_trend_stop(void)
{
    if (gs_perf_trend_state.enabled != 0U)
    {
        gs_perf_trend_state.enabled = 0U;
        gs_perf_trend_state.end_timestamp_ms = gs_perf_get_time_ms();
        gs_perf_trend_state.next_sample_due_ms = 0U;
        gs_perf_trend_sample_once();
    }
}

bool gs_perf_trend_is_active(void)
{
    return (gs_perf_trend_state.enabled != 0U);
}

void gs_perf_trend_dump(FILE *out)
{
    FILE *stream = (out != NULL) ? out : stdout;

    fprintf(stream, "===== PERFORMANCE TREND =====\r\n");
    fprintf(stream, "Period: %" PRIu32 " ms, Buffer Size: %" PRIu32 ", Overflow: %" PRIu8 "\r\n",
            gs_perf_trend_state.period_ms,
            gs_perf_trend_state.sample_count,
            gs_perf_trend_state.overflow);
    fprintf(stream, "Start: %" PRIu64 " ms, End: %" PRIu64 " ms\r\n",
            gs_perf_trend_state.start_timestamp_ms,
            gs_perf_trend_state.end_timestamp_ms);
    fprintf(stream, "Total Samples: %" PRIu64 "\r\n", gs_perf_trend_state.total_samples);

    if (gs_perf_trend_state.cpu_valid_samples > 0U)
    {
        uint32_t cpu_avg = (uint32_t)(gs_perf_trend_state.cpu_sum / gs_perf_trend_state.cpu_valid_samples);

        fprintf(stream, "CPU(process): avg=%" PRIu32 ".%" PRIu32 "%%, min=%" PRIu32 ".%" PRIu32 "%%, max=%" PRIu32 ".%" PRIu32 "%%, valid=%" PRIu64 "\r\n",
                cpu_avg / 10U, cpu_avg % 10U,
                gs_perf_trend_state.cpu_min / 10U, gs_perf_trend_state.cpu_min % 10U,
                gs_perf_trend_state.cpu_max / 10U, gs_perf_trend_state.cpu_max % 10U,
                gs_perf_trend_state.cpu_valid_samples);
    }
    else
    {
        fprintf(stream, "CPU(process): no valid samples\r\n");
    }

    fprintf(stream, "=============================\r\n");
    fflush(stream);
}
