/* Copyright (c) 2013-2017 GomSpace A/S. All rights reserved. */

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <gs/csp/error.h>
#include <gs/util/string.h>
#include <gs/util/gosh/command.h>
#include <gs/util/clock.h>
#include <gs/util/time.h>

#include "ccsds_packet_check.h"
#include "perf_monitor.h"

typedef void (*ccsds_run_fn_t)(void);

typedef struct {
    const char *label;
    const char *op_name;
    ccsds_run_fn_t fn;
} ccsds_scenario_t;

#define CCSDS_EXP1_DEFAULT_DURATION_S 3600U
#define CCSDS_EXP2_ITERATIONS         100000U
#define CCSDS_EXP2_DELAY_MS_DEFAULT   1U
#define CCSDS_EXP3_ITERATIONS         1U
#define CCSDS_EXP4_ITERATIONS         100000U
#define CCSDS_COLD_START_ITERATIONS   10000U

typedef struct {
    const char *label;
    uint32_t delay_ms;
} ccsds_delay_profile_t;

static void cmd_ccsds_warmup(gs_command_context_t *ctx)
{
    const uint32_t previous_iterations = ccsds_get_run_iterations();
    const uint32_t previous_delay_ms = ccsds_get_run_delay_ms();

    ccsds_set_run_iterations((uint32_t)CCSDS_COLD_START_ITERATIONS);
    ccsds_set_run_delay_ms(0U);
    fprintf(ctx->out, "Delete Cold Start ccsds_run_as1... (iterations=%" PRIu32 ")\r\n",
            (uint32_t)CCSDS_COLD_START_ITERATIONS);
    ccsds_run_as1();
    ccsds_set_run_iterations(previous_iterations);
    ccsds_set_run_delay_ms(previous_delay_ms);
    gs_time_sleep_ms(20);
}

static bool cmd_ccsds_parse_delay_profile(const char *arg, uint32_t *delay_ms_out)
{
    uint32_t delay_ms = 0U;

    if ((arg == NULL) || (delay_ms_out == NULL)) {
        return false;
    }

    if ((strcmp(arg, "non-sleep") == 0) || (strcmp(arg, "0") == 0)) {
        *delay_ms_out = 0U;
        return true;
    }
    if ((strcmp(arg, "sleep-1ms") == 0) || (strcmp(arg, "1") == 0)) {
        *delay_ms_out = 1U;
        return true;
    }
    if ((strcmp(arg, "sleep-10ms") == 0) || (strcmp(arg, "10") == 0)) {
        *delay_ms_out = 10U;
        return true;
    }
    if ((gs_string_to_uint32(arg, &delay_ms) == GS_OK) &&
        ((delay_ms == 0U) || (delay_ms == 1U) || (delay_ms == 10U))) {
        *delay_ms_out = delay_ms;
        return true;
    }

    return false;
}

static int cmd_ccsds_run_once_with_perf(gs_command_context_t *ctx, const ccsds_scenario_t *scenario)
{
    if ((scenario == NULL) || (scenario->fn == NULL)) {
        return GS_ERROR_ARG;
    }

    fprintf(ctx->out, "Running %s...\r\n", scenario->label);
    gs_perf_monitor_start(scenario->op_name, ctx->out);
    scenario->fn();
    gs_perf_monitor_stop(ctx->out);
    gs_time_sleep_ms(20);
    fprintf(ctx->out, "%s complete\r\n", scenario->label);
    return GS_OK;
}

static uint32_t cmd_ccsds_run_for_duration_with_delay(gs_command_context_t *ctx,
                                                      const ccsds_scenario_t *scenario,
                                                      uint32_t duration_s,
                                                      uint32_t delay_ms)
{
    uint32_t run_count = 0U;
    const uint64_t duration_ns = (uint64_t)duration_s * 1000000000ULL;
    const uint64_t start_ns = gs_clock_get_nsec();
    uint64_t now_ns = start_ns;

    if ((scenario == NULL) || (scenario->fn == NULL) || (duration_s == 0U)) {
        return 0U;
    }

    gs_perf_monitor_start(scenario->op_name, ctx->out);
    while ((now_ns - start_ns) < duration_ns) {
        scenario->fn();
        run_count++;

        if (delay_ms > 0U) {
            ccsds_delay_ms(delay_ms);
        }
        if (gs_command_wait_any_key(ctx, 0)) {
            break;
        }
        now_ns = gs_clock_get_nsec();
    }
    gs_perf_monitor_stop(ctx->out);
    gs_time_sleep_ms(20);

    fprintf(ctx->out,
            "%s run count: %" PRIu32 " (duration=%" PRIu32 " s, delay=%" PRIu32 " ms)\r\n",
            scenario->label, run_count, duration_s, delay_ms);

    return run_count;
}

static int cmd_ccsds_run_mode_exp1(gs_command_context_t *ctx,
                                   const ccsds_scenario_t *scenarios,
                                   uint32_t scenario_count,
                                   uint32_t duration_s)
{
    static const ccsds_delay_profile_t profiles[] = {
        { .label = "non-sleep", .delay_ms = 0U },
        { .label = "sleep-1ms", .delay_ms = 1U },
        { .label = "sleep-10ms", .delay_ms = 10U },
    };
    const uint32_t profile_count = (uint32_t)(sizeof(profiles) / sizeof(profiles[0]));
    const uint32_t previous_iterations = ccsds_get_run_iterations();
    const uint32_t previous_delay_ms = ccsds_get_run_delay_ms();

    ccsds_set_run_iterations(1U);
    ccsds_set_run_delay_ms(0U);
    fprintf(ctx->out,
            "EXP1 start: each scenario for %" PRIu32 " seconds with delay profiles (0/1/10 ms)\r\n",
            duration_s);
    fprintf(ctx->out,
            "Expected total duration ~= %" PRIu32 " hours (%" PRIu32 " scenarios x %" PRIu32 " profiles x %" PRIu32 " hour)\r\n",
            (scenario_count * profile_count * duration_s) / 3600U,
            scenario_count,
            profile_count,
            duration_s / 3600U);

    for (uint32_t p = 0U; p < profile_count; ++p) {
        fprintf(ctx->out, "=== Profile: %s (delay=%" PRIu32 " ms) ===\r\n", profiles[p].label, profiles[p].delay_ms);
        for (uint32_t i = 0U; i < scenario_count; ++i) {
            fprintf(ctx->out, "Running %s for %" PRIu32 " seconds...\r\n", scenarios[i].label, duration_s);
            (void)cmd_ccsds_run_for_duration_with_delay(ctx, &scenarios[i], duration_s, profiles[p].delay_ms);
        }
    }

    ccsds_set_run_iterations(previous_iterations);
    ccsds_set_run_delay_ms(previous_delay_ms);
    return GS_OK;
}

static int cmd_ccsds_run_mode_exp23(gs_command_context_t *ctx,
                                    const ccsds_scenario_t *scenarios,
                                    uint32_t scenario_count,
                                    uint32_t iterations,
                                    uint32_t delay_ms,
                                    const char *label)
{
    const uint32_t previous_iterations = ccsds_get_run_iterations();
    const uint32_t previous_delay_ms = ccsds_get_run_delay_ms();

    ccsds_set_run_iterations(iterations);
    ccsds_set_run_delay_ms(delay_ms);

    fprintf(ctx->out, "%s start: run_iterations=%" PRIu32 ", delay=%" PRIu32 " ms\r\n",
            label, iterations, delay_ms);
    for (uint32_t i = 0U; i < scenario_count; ++i) {
        (void)cmd_ccsds_run_once_with_perf(ctx, &scenarios[i]);
    }

    ccsds_set_run_iterations(previous_iterations);
    ccsds_set_run_delay_ms(previous_delay_ms);
    return GS_OK;
}

static int cmd_ccsds_run_mode_exp4(gs_command_context_t *ctx,
                                   const ccsds_scenario_t *scenarios,
                                   uint32_t scenario_count)
{
    static const ccsds_delay_profile_t profiles[] = {
        { .label = "non-sleep", .delay_ms = 0U },
        { .label = "sleep-1ms", .delay_ms = 1U },
        { .label = "sleep-10ms", .delay_ms = 10U },
    };
    const uint32_t profile_count = (uint32_t)(sizeof(profiles) / sizeof(profiles[0]));

    fprintf(ctx->out,
            "EXP4 start: run_iterations=%" PRIu32 " for delay profiles (0/1/10 ms)\r\n",
            (uint32_t)CCSDS_EXP4_ITERATIONS);

    for (uint32_t p = 0U; p < profile_count; ++p) {
        int result = GS_OK;
        fprintf(ctx->out, "=== Profile: %s (delay=%" PRIu32 " ms) ===\r\n",
                profiles[p].label, profiles[p].delay_ms);
        result = cmd_ccsds_run_mode_exp23(ctx, scenarios, scenario_count,
                                          CCSDS_EXP4_ITERATIONS, profiles[p].delay_ms, "EXP4");
        if (result != GS_OK) {
            return result;
        }
    }

    return GS_OK;
}

static int cmd_ccsds_inspection(gs_command_context_t *ctx)
{
    FILE *original_out = ctx->out;
    FILE *log_file = NULL;
    const char *log_path = NULL;
    uint32_t arg_index = 1U;
    int result = GS_OK;

    const ccsds_scenario_t scenarios[] = {
        { .label = "AS1", .op_name = "ccsds_as1", .fn = ccsds_run_as1 },
        { .label = "AS2", .op_name = "ccsds_as2", .fn = ccsds_run_as2 },
        { .label = "AS4", .op_name = "ccsds_as4", .fn = ccsds_run_as4 },
        { .label = "AS5", .op_name = "ccsds_as5", .fn = ccsds_run_as5 },
        { .label = "AS6", .op_name = "ccsds_as6", .fn = ccsds_run_as6 },
    };
    const uint32_t scenario_count = (uint32_t)(sizeof(scenarios) / sizeof(scenarios[0]));

    if ((ctx->argc > (int)arg_index) && (strcmp(ctx->argv[arg_index], "--log") == 0)) {
        if (ctx->argc <= (int)(arg_index + 1U)) {
            fprintf(original_out, "Usage: ccsds_inspection [--log <path>] [exp1 [seconds]|exp2 [iterations] [non-sleep|sleep-1ms|sleep-10ms]|exp3|exp4]\r\n");
            return GS_ERROR_ARG;
        }
        log_path = ctx->argv[arg_index + 1U];
        log_file = fopen(log_path, "a");
        if (log_file == NULL) {
            fprintf(original_out, "Failed to open log file '%s': %s\r\n", log_path, strerror(errno));
            return GS_ERROR_IO;
        }
        setvbuf(log_file, NULL, _IOLBF, 0);
        ctx->out = log_file;
        fprintf(original_out, "ccsds_inspection logging to: %s\r\n", log_path);
        fflush(original_out);
        arg_index += 2U;
    }

    cmd_ccsds_warmup(ctx);

    if (ctx->argc == (int)arg_index) {
        result = cmd_ccsds_run_mode_exp23(ctx, scenarios, scenario_count,
                                          CCSDS_EXP2_ITERATIONS, CCSDS_EXP2_DELAY_MS_DEFAULT, "EXP2");
        goto done;
    }

    if (strcmp(ctx->argv[arg_index], "exp1") == 0) {
        uint32_t duration_s = CCSDS_EXP1_DEFAULT_DURATION_S;
        if ((ctx->argc > (int)(arg_index + 1U)) &&
            (gs_string_to_uint32(ctx->argv[arg_index + 1U], &duration_s) != GS_OK)) {
            result = GS_ERROR_ARG;
            goto done;
        }
        if (duration_s == 0U) {
            result = GS_ERROR_RANGE;
            goto done;
        }
        result = cmd_ccsds_run_mode_exp1(ctx, scenarios, scenario_count, duration_s);
        goto done;
    }

    if (strcmp(ctx->argv[arg_index], "exp2") == 0) {
        uint32_t iterations = CCSDS_EXP2_ITERATIONS;
        uint32_t delay_ms = CCSDS_EXP2_DELAY_MS_DEFAULT;

        if (ctx->argc > (int)(arg_index + 1U)) {
            uint32_t parsed_iterations = 0U;
            if (gs_string_to_uint32(ctx->argv[arg_index + 1U], &parsed_iterations) == GS_OK) {
                if (parsed_iterations == 0U) {
                    result = GS_ERROR_RANGE;
                    goto done;
                }
                iterations = parsed_iterations;
                if (ctx->argc > (int)(arg_index + 2U)) {
                    if (!cmd_ccsds_parse_delay_profile(ctx->argv[arg_index + 2U], &delay_ms)) {
                        result = GS_ERROR_ARG;
                        goto done;
                    }
                    if (ctx->argc > (int)(arg_index + 3U)) {
                        result = GS_ERROR_ARG;
                        goto done;
                    }
                }
            } else {
                if (!cmd_ccsds_parse_delay_profile(ctx->argv[arg_index + 1U], &delay_ms)) {
                    result = GS_ERROR_ARG;
                    goto done;
                }
                if (ctx->argc > (int)(arg_index + 2U)) {
                    result = GS_ERROR_ARG;
                    goto done;
                }
            }
        }

        result = cmd_ccsds_run_mode_exp23(ctx, scenarios, scenario_count, iterations, delay_ms, "EXP2");
        goto done;
    }

    if (strcmp(ctx->argv[arg_index], "exp3") == 0) {
        result = cmd_ccsds_run_mode_exp23(ctx, scenarios, scenario_count,
                                          CCSDS_EXP3_ITERATIONS, 0U, "EXP3");
        goto done;
    }

    if (strcmp(ctx->argv[arg_index], "exp4") == 0) {
        if (ctx->argc > (int)(arg_index + 1U)) {
            result = GS_ERROR_ARG;
            goto done;
        }
        result = cmd_ccsds_run_mode_exp4(ctx, scenarios, scenario_count);
        goto done;
    }

    fprintf(ctx->out, "Usage: ccsds_inspection [--log <path>] [exp1 [seconds]|exp2 [iterations] [non-sleep|sleep-1ms|sleep-10ms]|exp3|exp4]\r\n");
    result = GS_ERROR_ARG;

done:
    if (log_file != NULL) {
        fflush(log_file);
        fclose(log_file);
        ctx->out = original_out;
        fprintf(original_out, "ccsds_inspection log saved: %s\r\n", log_path);
        fflush(original_out);
    }
    return result;
}

static const gs_command_t GS_COMMAND_ROOT csp_commands[] = {
    {
        .name = "ccsds_inspection",
        .help = "Run CCSDS packet inspection experiments",
        .usage = "[--log <path>] [exp1 [seconds]|exp2 [iterations] [non-sleep|sleep-1ms|sleep-10ms]|exp3|exp4]",
        .handler = cmd_ccsds_inspection,
        .mandatory_args = GS_COMMAND_NO_ARGS,
        .optional_args = 5,
    },
};

gs_error_t gs_csp_register_commands(void)
{
    return GS_COMMAND_REGISTER(csp_commands);
}
