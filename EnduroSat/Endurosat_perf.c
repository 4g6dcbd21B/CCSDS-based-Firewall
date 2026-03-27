#include "Endurosat_perf.h"
#include "taskmon_stat.h"
#include "assertions.h"
#include "cmsis_os2.h"
#include "drv_mcu_temperature.h"

#include "FreeRTOS.h"
#include "FreeRTOSConfig.h"
#include "task.h"

#include <stdio.h>

extern void endurosat_uart_write(const uint8_t *data, uint16_t len, uint32_t timeout_ms);

#define ENDUROSAT_PERF_MAX_SAMPLES       2048U
#define ENDUROSAT_PERF_DEFAULT_PERIOD_MS 10U
#define ENDUROSAT_PERF_MIN_PERIOD_MS     1U
#define ENDUROSAT_PERF_MAX_PERIOD_MS     1000U
#define ENDUROSAT_PERF_IDLE_DELAY_MS     50U
#define ENDUROSAT_PERF_TX_TIMEOUT_MS     200U

typedef struct
{
    uint32_t delta_total;
    uint32_t delta_task;
    uint32_t free_heap;
} endurosat_perf_sample_t;

typedef struct
{
    volatile uint8_t     start_requested;
    volatile uint8_t     stop_requested;
    volatile task_mon_id_t target_id;
    volatile uint32_t    period_ms;
} endurosat_perf_request_t;

typedef struct
{
    volatile uint8_t enabled;
    uint8_t      overflow;
    uint8_t      dump_pending;
    task_mon_id_t target_id;
    TaskHandle_t target_handle;
    uint32_t     period_ms;
    uint32_t     sample_count;
    uint32_t     last_total;
    uint32_t     last_task;
    uint32_t     start_tick;
    uint32_t     end_tick;
    uint32_t     total_heap;
    uint32_t     agg_sample_count;
    uint64_t     agg_cpu_x100_sum;
    uint64_t     agg_heap_x100_sum;
    uint32_t     agg_cpu_min_x100;
    uint32_t     agg_cpu_max_x100;
    uint8_t      agg_cpu_valid;
    int32_t      start_temp_centi;
    int32_t      end_temp_centi;
    uint8_t      start_temp_ok;
    uint8_t      end_temp_ok;
} endurosat_perf_state_t;

static endurosat_perf_sample_t endurosat_perf_samples[ENDUROSAT_PERF_MAX_SAMPLES];
static volatile endurosat_perf_request_t endurosat_perf_request = { 0 };
static endurosat_perf_state_t   endurosat_perf_state   = { 0 };

static osThreadId_t         endurosat_perf_handle;
static const osThreadAttr_t endurosat_perf_task_attr = {
    .name       = "EndurosatPerf",
    .priority   = (osPriority_t)osPriorityNormal,
    .stack_size = 2048
};

static uint32_t endurosat_perf_clamp_period(uint32_t period_ms)
{
    if (period_ms == 0U) {
        return ENDUROSAT_PERF_DEFAULT_PERIOD_MS;
    }
    if (period_ms < ENDUROSAT_PERF_MIN_PERIOD_MS) {
        return ENDUROSAT_PERF_MIN_PERIOD_MS;
    }
    if (period_ms > ENDUROSAT_PERF_MAX_PERIOD_MS) {
        return ENDUROSAT_PERF_MAX_PERIOD_MS;
    }
    return period_ms;
}

#ifdef ES_TASK_STATS_ENABLED
static TaskHandle_t endurosat_perf_get_handle(task_mon_id_t task_id)
{
    task_stat_t stat = task_mon_stat_get_configuration_per_id((uint8_t)task_id);
    return stat.task_handle;
}
#endif

static uint32_t endurosat_perf_get_task_runtime(TaskHandle_t handle)
{
    TaskStatus_t task_status;

    if (handle == NULL) {
        return 0U;
    }

    vTaskGetInfo(handle, &task_status, pdFALSE, eReady);
    return task_status.ulRunTimeCounter;
}

static uint8_t endurosat_perf_read_temp_centi(int32_t *temp_centi)
{
    float temp_c = 0.0f;
    if ((temp_centi == NULL) || (drv_mcu_temp_get(&temp_c) != DRV_MCU_TEMP_STATUS_OK)) {
        return 0U;
    }

    {
        float scaled = temp_c * 100.0f;
        *temp_centi = (int32_t)((scaled >= 0.0f) ? (scaled + 0.5f) : (scaled - 0.5f));
    }
    return 1U;
}

static uint32_t endurosat_perf_calc_cpu_x100(uint32_t delta_total, uint32_t delta_task)
{
    if (delta_total == 0U) {
        return 0U;
    }
    return (uint32_t)(((uint64_t)delta_task * 10000U) / delta_total);
}

static uint32_t endurosat_perf_calc_heap_x100(uint32_t free_heap)
{
    if (endurosat_perf_state.total_heap == 0U) {
        return 0U;
    }

    {
        uint32_t used = endurosat_perf_state.total_heap - free_heap;
        return (uint32_t)(((uint64_t)used * 10000U) / endurosat_perf_state.total_heap);
    }
}

static void endurosat_perf_aggregate_samples(uint32_t count)
{
    for (uint32_t i = 0U; i < count; i++) {
        uint32_t cpu_x100 = endurosat_perf_calc_cpu_x100(endurosat_perf_samples[i].delta_total,
                                                      endurosat_perf_samples[i].delta_task);
        uint32_t heap_x100 = endurosat_perf_calc_heap_x100(endurosat_perf_samples[i].free_heap);

        endurosat_perf_state.agg_cpu_x100_sum += (uint64_t)cpu_x100;
        endurosat_perf_state.agg_heap_x100_sum += (uint64_t)heap_x100;
        if (endurosat_perf_state.agg_cpu_valid == 0U) {
            endurosat_perf_state.agg_cpu_min_x100 = cpu_x100;
            endurosat_perf_state.agg_cpu_max_x100 = cpu_x100;
            endurosat_perf_state.agg_cpu_valid = 1U;
        } else {
            if (cpu_x100 < endurosat_perf_state.agg_cpu_min_x100) {
                endurosat_perf_state.agg_cpu_min_x100 = cpu_x100;
            }
            if (cpu_x100 > endurosat_perf_state.agg_cpu_max_x100) {
                endurosat_perf_state.agg_cpu_max_x100 = cpu_x100;
            }
        }
    }

    endurosat_perf_state.agg_sample_count += count;
}

static void endurosat_perf_dump(void)
{
    char     buffer[128];
    uint32_t count = endurosat_perf_state.sample_count;
    int      written;
    uint32_t elapsed_ticks;
    uint32_t max_samples;
    uint64_t cpu_x100_sum;
    uint64_t heap_x100_sum;
    uint32_t total_count;
    uint32_t cpu_min_x100;
    uint32_t cpu_max_x100;
    uint8_t  cpu_valid;

    elapsed_ticks = endurosat_perf_state.end_tick - endurosat_perf_state.start_tick;
    max_samples = (endurosat_perf_state.period_ms > 0U)
                      ? ((elapsed_ticks / endurosat_perf_state.period_ms) + 1U)
                      : 0U;

    written = snprintf(buffer, sizeof(buffer), "PERF,%u,%lu,%lu,%u,%lu,%lu,%lu,%lu\r\n",
                       (unsigned int)endurosat_perf_state.target_id,
                       (unsigned long)count,
                       (unsigned long)endurosat_perf_state.period_ms,
                       (unsigned int)endurosat_perf_state.overflow,
                       (unsigned long)endurosat_perf_state.start_tick,
                       (unsigned long)endurosat_perf_state.end_tick,
                       (unsigned long)elapsed_ticks,
                       (unsigned long)max_samples);
    if ((written > 0) && ((size_t)written < sizeof(buffer))) {
        endurosat_uart_write((const uint8_t *)buffer, (uint16_t)written, ENDUROSAT_PERF_TX_TIMEOUT_MS);
    }

    written = snprintf(buffer, sizeof(buffer), "AGG_STATE,%lu,%lu\r\n",
                       (unsigned long)endurosat_perf_state.agg_sample_count,
                       (unsigned long)count);
    if ((written > 0) && ((size_t)written < sizeof(buffer))) {
        endurosat_uart_write((const uint8_t *)buffer, (uint16_t)written, ENDUROSAT_PERF_TX_TIMEOUT_MS);
    }

    for (uint32_t i = 0U; i < count; i++)
    {
        uint32_t delta_total = endurosat_perf_samples[i].delta_total;
        uint32_t delta_task  = endurosat_perf_samples[i].delta_task;
        uint32_t free_heap    = endurosat_perf_samples[i].free_heap;
        uint32_t pct_x100     = 0U;
        uint32_t pct_int      = 0U;
        uint32_t pct_frac     = 0U;
        uint32_t heap_x100    = 0U;
        uint32_t heap_int     = 0U;
        uint32_t heap_frac    = 0U;

        pct_x100 = endurosat_perf_calc_cpu_x100(delta_total, delta_task);
        pct_int  = pct_x100 / 100U;
        pct_frac = pct_x100 % 100U;
        heap_x100 = endurosat_perf_calc_heap_x100(free_heap);
        heap_int  = heap_x100 / 100U;
        heap_frac = heap_x100 % 100U;

        written = snprintf(buffer, sizeof(buffer), "S,%lu,%lu,%lu,%lu.%02lu,%lu,%lu.%02lu\r\n",
                           (unsigned long)i,
                           (unsigned long)delta_total,
                           (unsigned long)delta_task,
                           (unsigned long)pct_int,
                           (unsigned long)pct_frac,
                           (unsigned long)free_heap,
                           (unsigned long)heap_int,
                           (unsigned long)heap_frac);
        if ((written > 0) && ((size_t)written < sizeof(buffer))) {
            endurosat_uart_write((const uint8_t *)buffer, (uint16_t)written, ENDUROSAT_PERF_TX_TIMEOUT_MS);
        }
    }

    cpu_x100_sum = endurosat_perf_state.agg_cpu_x100_sum;
    heap_x100_sum = endurosat_perf_state.agg_heap_x100_sum;
    total_count = endurosat_perf_state.agg_sample_count;
    cpu_min_x100 = endurosat_perf_state.agg_cpu_min_x100;
    cpu_max_x100 = endurosat_perf_state.agg_cpu_max_x100;
    cpu_valid = endurosat_perf_state.agg_cpu_valid;
    for (uint32_t i = 0U; i < count; i++) {
        uint32_t cpu_x100 = endurosat_perf_calc_cpu_x100(endurosat_perf_samples[i].delta_total,
                                                      endurosat_perf_samples[i].delta_task);
        uint32_t heap_x100 = endurosat_perf_calc_heap_x100(endurosat_perf_samples[i].free_heap);
        cpu_x100_sum += (uint64_t)cpu_x100;
        heap_x100_sum += (uint64_t)heap_x100;
        if (cpu_valid == 0U) {
            cpu_min_x100 = cpu_x100;
            cpu_max_x100 = cpu_x100;
            cpu_valid = 1U;
        } else {
            if (cpu_x100 < cpu_min_x100) {
                cpu_min_x100 = cpu_x100;
            }
            if (cpu_x100 > cpu_max_x100) {
                cpu_max_x100 = cpu_x100;
            }
        }
    }
    total_count += count;
    if (total_count > 0U) {
        uint32_t cpu_avg_x100 = (uint32_t)(cpu_x100_sum / (uint64_t)total_count);
        uint32_t heap_avg_x100 = (uint32_t)(heap_x100_sum / (uint64_t)total_count);
        written = snprintf(buffer, sizeof(buffer), "AGG,%lu,%lu.%02lu,%lu.%02lu,%lu.%02lu,%lu.%02lu\r\n",
                           (unsigned long)total_count,
                           (unsigned long)(cpu_avg_x100 / 100U),
                           (unsigned long)(cpu_avg_x100 % 100U),
                           (unsigned long)(cpu_min_x100 / 100U),
                           (unsigned long)(cpu_min_x100 % 100U),
                           (unsigned long)(cpu_max_x100 / 100U),
                           (unsigned long)(cpu_max_x100 % 100U),
                           (unsigned long)(heap_avg_x100 / 100U),
                           (unsigned long)(heap_avg_x100 % 100U));
        if ((written > 0) && ((size_t)written < sizeof(buffer))) {
            endurosat_uart_write((const uint8_t *)buffer, (uint16_t)written, ENDUROSAT_PERF_TX_TIMEOUT_MS);
        }
    }

    if ((endurosat_perf_state.start_temp_ok != 0U) && (endurosat_perf_state.end_temp_ok != 0U)) {
        int32_t delta_centi = endurosat_perf_state.end_temp_centi - endurosat_perf_state.start_temp_centi;
        int32_t delta_int = delta_centi / 100;
        int32_t delta_frac = delta_centi % 100;
        if (delta_frac < 0) {
            delta_frac = -delta_frac;
        }
        written = snprintf(buffer, sizeof(buffer), "TEMP_DELTA,%ld.%02ld\r\n",
                           (long)delta_int,
                           (long)delta_frac);
    } else {
        written = snprintf(buffer, sizeof(buffer), "TEMP,ERR,%lu,%lu\r\n",
                           (unsigned long)endurosat_perf_state.start_temp_ok,
                           (unsigned long)endurosat_perf_state.end_temp_ok);
    }
    if ((written > 0) && ((size_t)written < sizeof(buffer))) {
        endurosat_uart_write((const uint8_t *)buffer, (uint16_t)written, ENDUROSAT_PERF_TX_TIMEOUT_MS);
    }
}

static void endurosat_perf_handle_start(void)
{
    endurosat_perf_state.enabled      = 0U;
    endurosat_perf_state.dump_pending = 0U;
    endurosat_perf_state.overflow     = 0U;
    endurosat_perf_state.sample_count = 0U;
    endurosat_perf_state.target_id    = endurosat_perf_request.target_id;
    endurosat_perf_state.period_ms    = endurosat_perf_clamp_period(endurosat_perf_request.period_ms);
    endurosat_perf_state.start_tick   = osKernelGetTickCount();
    endurosat_perf_state.end_tick     = endurosat_perf_state.start_tick;
    endurosat_perf_state.total_heap   = freertos_user_get_heap_size();
    endurosat_perf_state.agg_sample_count = 0U;
    endurosat_perf_state.agg_cpu_x100_sum = 0U;
    endurosat_perf_state.agg_heap_x100_sum = 0U;
    endurosat_perf_state.agg_cpu_min_x100 = 0U;
    endurosat_perf_state.agg_cpu_max_x100 = 0U;
    endurosat_perf_state.agg_cpu_valid = 0U;
    endurosat_perf_state.start_temp_centi = 0;
    endurosat_perf_state.end_temp_centi   = 0;
    endurosat_perf_state.start_temp_ok    = 0U;
    endurosat_perf_state.end_temp_ok      = 0U;

#ifdef ES_TASK_STATS_ENABLED
    endurosat_perf_state.target_handle = endurosat_perf_get_handle(endurosat_perf_state.target_id);
#else
    endurosat_perf_state.target_handle = NULL;
#endif

    if (endurosat_perf_state.target_handle == NULL) {
        const char msg[] = "PERF,ERR,no_handle\r\n";
        endurosat_uart_write((const uint8_t *)msg, (uint16_t)(sizeof(msg) - 1U), ENDUROSAT_PERF_TX_TIMEOUT_MS);
        return;
    }

    endurosat_perf_state.last_total = portGET_RUN_TIME_COUNTER_VALUE();
    endurosat_perf_state.last_task  = endurosat_perf_get_task_runtime(endurosat_perf_state.target_handle);
    endurosat_perf_state.start_temp_ok = endurosat_perf_read_temp_centi(&endurosat_perf_state.start_temp_centi);
    endurosat_perf_state.enabled    = 1U;
}

static void endurosat_perf_handle_stop(void)
{
    endurosat_perf_state.enabled      = 0U;
    endurosat_perf_state.dump_pending = 1U;
    endurosat_perf_state.end_temp_ok  = endurosat_perf_read_temp_centi(&endurosat_perf_state.end_temp_centi);
    endurosat_perf_state.end_tick     = osKernelGetTickCount();
}

static void endurosat_perf_sample_once(void)
{
    uint32_t total_now = portGET_RUN_TIME_COUNTER_VALUE();
    uint32_t task_now  = endurosat_perf_get_task_runtime(endurosat_perf_state.target_handle);
    uint32_t free_heap = xPortGetFreeHeapSize();
    uint32_t delta_total = total_now - endurosat_perf_state.last_total;
    uint32_t delta_task  = task_now - endurosat_perf_state.last_task;

    endurosat_perf_state.last_total = total_now;
    endurosat_perf_state.last_task  = task_now;

    if (endurosat_perf_state.sample_count < ENDUROSAT_PERF_MAX_SAMPLES) {
        endurosat_perf_samples[endurosat_perf_state.sample_count].delta_total = delta_total;
        endurosat_perf_samples[endurosat_perf_state.sample_count].delta_task  = delta_task;
        endurosat_perf_samples[endurosat_perf_state.sample_count].free_heap   = free_heap;
        endurosat_perf_state.sample_count++;
        if (endurosat_perf_state.sample_count >= ENDUROSAT_PERF_MAX_SAMPLES) {
            endurosat_perf_aggregate_samples(endurosat_perf_state.sample_count);
            endurosat_perf_state.sample_count = 0U;
        }
    }
}

static void endurosat_perf_task(void *argument)
{
    uint32_t next_wake = osKernelGetTickCount();
    (void)argument;

    while (true)
    {
        if (endurosat_perf_request.start_requested != 0U) {
            endurosat_perf_request.start_requested = 0U;
            endurosat_perf_handle_start();
            next_wake = osKernelGetTickCount() + endurosat_perf_state.period_ms;
        }

        if (endurosat_perf_request.stop_requested != 0U) {
            endurosat_perf_request.stop_requested = 0U;
            endurosat_perf_handle_stop();
        }

        if (endurosat_perf_state.enabled != 0U) {
            endurosat_perf_sample_once();
            if (endurosat_perf_state.enabled != 0U) {
                osDelayUntil(next_wake);
                next_wake += endurosat_perf_state.period_ms;
            }
            continue;
        }

        if (endurosat_perf_state.dump_pending != 0U) {
            endurosat_perf_state.dump_pending = 0U;
            endurosat_perf_dump();
        }

        osDelay(ENDUROSAT_PERF_IDLE_DELAY_MS);
    }
}

void endurosat_perf_init(void)
{
    endurosat_perf_handle = osThreadNew(endurosat_perf_task, NULL, &endurosat_perf_task_attr);
    CRIT_ASSERT(endurosat_perf_handle != NULL);
}

bool endurosat_perf_start(task_mon_id_t task_id, uint32_t period_ms)
{
    if (task_id >= TASK_ID_MAX) {
        return false;
    }
    endurosat_perf_request.target_id = task_id;
    endurosat_perf_request.period_ms = period_ms;
    endurosat_perf_request.start_requested = 1U;
    return true;
}

void endurosat_perf_stop(void)
{
    endurosat_perf_request.stop_requested = 1U;
}

bool endurosat_perf_is_active(void)
{
    return (endurosat_perf_state.enabled != 0U);
}
