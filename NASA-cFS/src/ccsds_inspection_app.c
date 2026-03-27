/*******************************************************************************
** File:
**   ccsds_inspection_app.c
**
** Purpose:
**   CCSDS inspection application for running packet checks with
**   performance monitoring.
**
*******************************************************************************/

#include <stdio.h>
#include <inttypes.h>
#include <time.h>
#include <stdarg.h>
#include "ccsds_inspection_app.h"
#include "ccsds_packet_check.h"
#include "perf_monitor.h"
#include "osapi.h"

/*
** Global Data
*/
CCSDS_Inspection_AppData_t CCSDS_Inspection_AppData;

#define CCSDS_INSPECTION_RUN_STACK_SIZE  OSAL_SIZE_C(8192)
#define CCSDS_INSPECTION_RUN_PRIORITY    OSAL_PRIORITY_C(50)
#define CCSDS_EXP1_DEFAULT_DURATION_S    3600U
#define CCSDS_EXP2_ITERATIONS            100000U
#define CCSDS_EXP3_ITERATIONS            10000000U
#define CCSDS_EXP4_ITERATIONS            100000U
#define CCSDS_EXP_DEFAULT_DELAY_MS       1U

typedef void (*CCSDS_Inspection_RunFn_t)(void);

typedef struct
{
    const char *Label;
    const char *OperationName;
    CCSDS_Inspection_RunFn_t Fn;
} CCSDS_Inspection_Scenario_t;

typedef struct
{
    const char *Label;
    uint32 DelayMs;
} CCSDS_Inspection_DelayProfile_t;

typedef enum
{
    CCSDS_INSPECTION_RUN_MODE_EXP2 = 0,
    CCSDS_INSPECTION_RUN_MODE_EXP1 = 1,
    CCSDS_INSPECTION_RUN_MODE_EXP3 = 2,
    CCSDS_INSPECTION_RUN_MODE_EXP4 = 3
} CCSDS_Inspection_RunMode_t;

static osal_id_t g_ccsds_run_task_id;
static volatile uint8 g_ccsds_run_task_active = 0U;
static volatile uint8 g_ccsds_run_mode = (uint8)CCSDS_INSPECTION_RUN_MODE_EXP2;
static FILE *g_ccsds_log_file = NULL;
static const char *g_ccsds_log_path = "/tmp/ccsds_inspection.log";

static void CCSDS_Inspection_RunTask(void);
static void CCSDS_Inspection_RunChecks(uint8 run_mode);
static void CCSDS_Inspection_LogOpen(void);
static void CCSDS_Inspection_LogClose(void);
static FILE *CCSDS_Inspection_GetOutputStream(void);
static void CCSDS_Inspection_LogPrintf(const char *fmt, ...);

static const CCSDS_Inspection_Scenario_t g_ccsds_scenarios[] = {
    { "AS1", "ccsds_as1", ccsds_run_as1 },
    { "AS2", "ccsds_as2", ccsds_run_as2 },
    { "AS4", "ccsds_as4", ccsds_run_as4 },
    { "AS5", "ccsds_as5", ccsds_run_as5 },
    { "AS6", "ccsds_as6", ccsds_run_as6 },
};

static uint64 CCSDS_Inspection_GetMonotonicMs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64)ts.tv_sec * 1000ULL) + ((uint64)ts.tv_nsec / 1000000ULL);
}

static void CCSDS_Inspection_LogOpen(void)
{
    if (g_ccsds_log_file != NULL)
    {
        return;
    }

    g_ccsds_log_file = fopen(g_ccsds_log_path, "a");
    if (g_ccsds_log_file != NULL)
    {
        setvbuf(g_ccsds_log_file, NULL, _IOLBF, 0);
        OS_printf("CCSDS_INSPECTION: log file enabled: %s\n", g_ccsds_log_path);
    }
    else
    {
        OS_printf("CCSDS_INSPECTION: failed to open log file: %s\n", g_ccsds_log_path);
    }
}

static void CCSDS_Inspection_LogClose(void)
{
    if (g_ccsds_log_file != NULL)
    {
        fflush(g_ccsds_log_file);
        fclose(g_ccsds_log_file);
        g_ccsds_log_file = NULL;
    }
}

static FILE *CCSDS_Inspection_GetOutputStream(void)
{
    if (g_ccsds_log_file != NULL)
    {
        return g_ccsds_log_file;
    }
    return stdout;
}

static void CCSDS_Inspection_LogPrintf(const char *fmt, ...)
{
    char buffer[512];
    va_list ap;
    int written;

    va_start(ap, fmt);
    written = vsnprintf(buffer, sizeof(buffer), fmt, ap);
    va_end(ap);

    if (written <= 0)
    {
        return;
    }

    OS_printf("%s", buffer);
    if (g_ccsds_log_file != NULL)
    {
        fputs(buffer, g_ccsds_log_file);
        fflush(g_ccsds_log_file);
    }
}

static void CCSDS_Inspection_RunScenarioOnce(const CCSDS_Inspection_Scenario_t *scenario)
{
    FILE *out = CCSDS_Inspection_GetOutputStream();

    if ((scenario == NULL) || (scenario->Fn == NULL))
    {
        return;
    }

    CCSDS_Inspection_LogPrintf("CCSDS_INSPECTION: Running %s...\n", scenario->Label);
    gs_perf_monitor_start(scenario->OperationName, out);
    if (!gs_perf_trend_start(10U, 0U))
    {
        CCSDS_Inspection_LogPrintf("CCSDS_INSPECTION: perftrend start failed\n");
    }
    scenario->Fn();
    gs_perf_monitor_stop(out);
    gs_perf_trend_stop();
    OS_TaskDelay(20);
    gs_perf_trend_dump(out);
    CCSDS_Inspection_LogPrintf("CCSDS_INSPECTION: %s complete\n\n", scenario->Label);
}

static uint32 CCSDS_Inspection_RunScenarioForDuration(const CCSDS_Inspection_Scenario_t *scenario, uint32 duration_s)
{
    FILE *out = CCSDS_Inspection_GetOutputStream();
    uint64 start_ms;
    uint64 now_ms;
    uint64 duration_ms;
    uint32 run_count;

    if ((scenario == NULL) || (scenario->Fn == NULL) || (duration_s == 0U))
    {
        return 0U;
    }

    duration_ms = (uint64)duration_s * 1000ULL;
    run_count = 0U;
    start_ms = CCSDS_Inspection_GetMonotonicMs();
    now_ms = start_ms;

    CCSDS_Inspection_LogPrintf("CCSDS_INSPECTION: Running %s for %" PRIu32 " s...\n", scenario->Label, duration_s);
    gs_perf_monitor_start(scenario->OperationName, out);
    if (!gs_perf_trend_start(10U, 0U))
    {
        CCSDS_Inspection_LogPrintf("CCSDS_INSPECTION: perftrend start failed\n");
    }

    while ((now_ms - start_ms) < duration_ms)
    {
        scenario->Fn();
        run_count++;
        now_ms = CCSDS_Inspection_GetMonotonicMs();
    }

    gs_perf_monitor_stop(out);
    gs_perf_trend_stop();
    OS_TaskDelay(20);
    gs_perf_trend_dump(out);
    CCSDS_Inspection_LogPrintf("CCSDS_INSPECTION: %s run count: %" PRIu32 " (duration=%" PRIu32 " s)\n\n",
                               scenario->Label, run_count, duration_s);

    return run_count;
}

static void CCSDS_Inspection_RunModeExp1(void)
{
    static const CCSDS_Inspection_DelayProfile_t profiles[] = {
        { "non-sleep", 0U },
        { "sleep-1ms", 1U },
        { "sleep-10ms", 10U },
    };
    const uint32 scenario_count = (uint32)(sizeof(g_ccsds_scenarios) / sizeof(g_ccsds_scenarios[0]));
    const uint32 profile_count = (uint32)(sizeof(profiles) / sizeof(profiles[0]));
    uint32 previous_iterations = ccsds_get_run_iterations();
    uint32 previous_delay_ms = ccsds_get_run_delay_ms();
    uint32 i;
    uint32 p;

    ccsds_set_run_iterations(1U);
    CCSDS_Inspection_LogPrintf("CCSDS_INSPECTION: EXP1 start (duration=%" PRIu32 " s, profiles=0/1/10ms)\n",
                               CCSDS_EXP1_DEFAULT_DURATION_S);
    CCSDS_Inspection_LogPrintf("CCSDS_INSPECTION: expected total duration ~= %" PRIu32 " hours (%" PRIu32 " scenarios x %" PRIu32 " profiles x %" PRIu32 " hour)\n\n",
                               (scenario_count * profile_count * CCSDS_EXP1_DEFAULT_DURATION_S) / 3600U,
                               scenario_count, profile_count, CCSDS_EXP1_DEFAULT_DURATION_S / 3600U);

    for (p = 0U; p < profile_count; ++p)
    {
        ccsds_set_run_delay_ms(profiles[p].DelayMs);
        CCSDS_Inspection_LogPrintf("CCSDS_INSPECTION: === Profile: %s (delay=%" PRIu32 " ms) ===\n",
                                   profiles[p].Label, profiles[p].DelayMs);
        for (i = 0U; i < scenario_count; ++i)
        {
            (void)CCSDS_Inspection_RunScenarioForDuration(&g_ccsds_scenarios[i], CCSDS_EXP1_DEFAULT_DURATION_S);
        }
    }

    ccsds_set_run_iterations(previous_iterations);
    ccsds_set_run_delay_ms(previous_delay_ms);
}

static void CCSDS_Inspection_RunModeExp23(uint32 iterations, uint32 delay_ms, const char *label)
{
    const uint32 scenario_count = (uint32)(sizeof(g_ccsds_scenarios) / sizeof(g_ccsds_scenarios[0]));
    uint32 previous_iterations = ccsds_get_run_iterations();
    uint32 previous_delay_ms = ccsds_get_run_delay_ms();
    uint32 i;

    ccsds_set_run_iterations(iterations);
    ccsds_set_run_delay_ms(delay_ms);
    CCSDS_Inspection_LogPrintf("CCSDS_INSPECTION: %s start (run_iterations=%" PRIu32 ", delay=%" PRIu32 " ms)\n\n",
                               label, iterations, delay_ms);

    for (i = 0U; i < scenario_count; ++i)
    {
        CCSDS_Inspection_RunScenarioOnce(&g_ccsds_scenarios[i]);
    }

    ccsds_set_run_iterations(previous_iterations);
    ccsds_set_run_delay_ms(previous_delay_ms);
}

static void CCSDS_Inspection_RunModeExp4(void)
{
    static const CCSDS_Inspection_DelayProfile_t profiles[] = {
        { "non-sleep", 0U },
        { "sleep-1ms", 1U },
        { "sleep-10ms", 10U },
    };
    const uint32 scenario_count = (uint32)(sizeof(g_ccsds_scenarios) / sizeof(g_ccsds_scenarios[0]));
    const uint32 profile_count = (uint32)(sizeof(profiles) / sizeof(profiles[0]));
    uint32 previous_iterations = ccsds_get_run_iterations();
    uint32 previous_delay_ms = ccsds_get_run_delay_ms();
    uint32 i;
    uint32 p;

    ccsds_set_run_iterations(CCSDS_EXP4_ITERATIONS);
    CCSDS_Inspection_LogPrintf("CCSDS_INSPECTION: EXP4 start (run_iterations=%" PRIu32 ", profiles=0/1/10ms)\n",
                               CCSDS_EXP4_ITERATIONS);
    CCSDS_Inspection_LogPrintf("CCSDS_INSPECTION: expected runs = %" PRIu32 " (%" PRIu32 " scenarios x %" PRIu32 " profiles)\n\n",
                               scenario_count * profile_count, scenario_count, profile_count);

    for (p = 0U; p < profile_count; ++p)
    {
        ccsds_set_run_delay_ms(profiles[p].DelayMs);
        CCSDS_Inspection_LogPrintf("CCSDS_INSPECTION: === Profile: %s (delay=%" PRIu32 " ms) ===\n",
                                   profiles[p].Label, profiles[p].DelayMs);

        for (i = 0U; i < scenario_count; ++i)
        {
            CCSDS_Inspection_RunScenarioOnce(&g_ccsds_scenarios[i]);
        }
    }

    ccsds_set_run_iterations(previous_iterations);
    ccsds_set_run_delay_ms(previous_delay_ms);
}

static void CCSDS_Inspection_RunChecks(uint8 run_mode)
{
    switch ((CCSDS_Inspection_RunMode_t)run_mode)
    {
        case CCSDS_INSPECTION_RUN_MODE_EXP1:
            CCSDS_Inspection_RunModeExp1();
            break;

        case CCSDS_INSPECTION_RUN_MODE_EXP3:
            CCSDS_Inspection_RunModeExp23(CCSDS_EXP3_ITERATIONS, 0U, "EXP3");
            break;

        case CCSDS_INSPECTION_RUN_MODE_EXP4:
            CCSDS_Inspection_RunModeExp4();
            break;

        case CCSDS_INSPECTION_RUN_MODE_EXP2:
        default:
            CCSDS_Inspection_RunModeExp23(CCSDS_EXP2_ITERATIONS, CCSDS_EXP_DEFAULT_DELAY_MS, "EXP2");
            break;
    }
}

static void CCSDS_Inspection_RunTask(void)
{
    uint8 run_mode = g_ccsds_run_mode;
    CCSDS_Inspection_RunChecks(run_mode);
    CCSDS_Inspection_AppData.HkTelemetryPkt.RunCount++;
    CCSDS_Inspection_AppData.HkTelemetryPkt.LastRunStatus = 0;
    g_ccsds_run_task_active = 0U;
    OS_TaskExit();
}

static void CCSDS_Inspection_StartRunTask(uint8 run_mode, const char *mode_label)
{
    int32 os_status;

    CFE_EVS_SendEvent(CCSDS_INSPECTION_CMD_RUN_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "CCSDS_INSPECTION: RUN %s command received", mode_label);

    if (g_ccsds_run_task_active != 0U)
    {
        CFE_EVS_SendEvent(CCSDS_INSPECTION_CMD_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CCSDS_INSPECTION: RUN already in progress");
        return;
    }

    g_ccsds_run_mode = run_mode;
    g_ccsds_run_task_active = 1U;
    os_status = OS_TaskCreate(&g_ccsds_run_task_id, "CCSDS_INSPECT",
                              CCSDS_Inspection_RunTask,
                              OSAL_TASK_STACK_ALLOCATE,
                              CCSDS_INSPECTION_RUN_STACK_SIZE,
                              CCSDS_INSPECTION_RUN_PRIORITY,
                              0);
    if (os_status != OS_SUCCESS)
    {
        g_ccsds_run_task_active = 0U;
        CCSDS_Inspection_AppData.HkTelemetryPkt.LastRunStatus = (uint32)os_status;
        CFE_EVS_SendEvent(CCSDS_INSPECTION_CMD_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CCSDS_INSPECTION: Failed to start run task, RC=0x%08X",
                          (unsigned int)os_status);
    }
}

void CCSDSI_AppMain(void)
{
    CCSDS_Inspection_AppMain();
}

/*
** Application entry point and main process loop
*/
void CCSDS_Inspection_AppMain(void)
{
    int32 status = OS_SUCCESS;

    /* Create the first Performance Log entry */
    CFE_ES_PerfLogEntry(CCSDS_INSPECTION_PERF_ID);

    /* Perform application initialization */
    status = CCSDS_Inspection_AppInit();
    if (status != CFE_SUCCESS)
    {
        CCSDS_Inspection_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    /* Main loop */
    while (CFE_ES_RunLoop(&CCSDS_Inspection_AppData.RunStatus) == true)
    {
        /* Performance log exit stamp */
        CFE_ES_PerfLogExit(CCSDS_INSPECTION_PERF_ID);

        /* Pend on the arrival of the next Software Bus message */
        status = CFE_SB_ReceiveBuffer((CFE_SB_Buffer_t **)&CCSDS_Inspection_AppData.MsgPtr,
                                      CCSDS_Inspection_AppData.CmdPipe,
                                      CFE_SB_PEND_FOREVER);

        /* Performance log entry */
        CFE_ES_PerfLogEntry(CCSDS_INSPECTION_PERF_ID);

        if (status == CFE_SUCCESS)
        {
            CCSDS_Inspection_ProcessCommandPacket();
        }
        else
        {
            CFE_EVS_SendEvent(CCSDS_INSPECTION_PIPE_ERR_EID, CFE_EVS_EventType_ERROR,
                              "CCSDS_INSPECTION: SB Pipe Read Error = %d", (int)status);
            CCSDS_Inspection_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }
    }

    /* Performance log exit stamp */
    CFE_ES_PerfLogExit(CCSDS_INSPECTION_PERF_ID);

    /* Exit the application */
    CCSDS_Inspection_LogClose();
    CFE_ES_ExitApp(CCSDS_Inspection_AppData.RunStatus);
}

/*
** Initialize application
*/
int32 CCSDS_Inspection_AppInit(void)
{
    int32 status = OS_SUCCESS;

    g_ccsds_run_task_id = OS_OBJECT_ID_UNDEFINED;

    CCSDS_Inspection_AppData.RunStatus = CFE_ES_RunStatus_APP_RUN;

    /* Register the events */
    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("CCSDS_INSPECTION: Error registering for event services: 0x%08X\n",
                             (unsigned int)status);
        return status;
    }

    /* Create the Software Bus command pipe */
    status = CFE_SB_CreatePipe(&CCSDS_Inspection_AppData.CmdPipe,
                               CCSDS_INSPECTION_PIPE_DEPTH,
                               CCSDS_INSPECTION_PIPE_NAME);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(CCSDS_INSPECTION_PIPE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CCSDS_INSPECTION: Error creating SB Pipe, RC=0x%08X",
                          (unsigned int)status);
        return status;
    }

    /* Subscribe to ground commands */
    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(CCSDS_INSPECTION_CMD_MID),
                              CCSDS_Inspection_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(CCSDS_INSPECTION_SUBSCRIBE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CCSDS_INSPECTION: Error subscribing to CMD MID=0x%04X, RC=0x%08X",
                          CCSDS_INSPECTION_CMD_MID, (unsigned int)status);
        return status;
    }

    /* Subscribe to housekeeping requests */
    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(CCSDS_INSPECTION_REQ_HK_MID),
                              CCSDS_Inspection_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(CCSDS_INSPECTION_SUBSCRIBE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CCSDS_INSPECTION: Error subscribing to HK MID=0x%04X, RC=0x%08X",
                          CCSDS_INSPECTION_REQ_HK_MID, (unsigned int)status);
        return status;
    }

    /* Initialize the published HK message */
    CFE_MSG_Init(CFE_MSG_PTR(CCSDS_Inspection_AppData.HkTelemetryPkt.TlmHeader),
                 CFE_SB_ValueToMsgId(CCSDS_INSPECTION_HK_TLM_MID),
                 CCSDS_INSPECTION_HK_TLM_LNGTH);

    /* Reset counters */
    CCSDS_Inspection_ResetCounters();

    /* Initialize perf monitor */
    gs_perf_monitor_init();
    CCSDS_Inspection_LogOpen();

    /* Send startup event */
    status = CFE_EVS_SendEvent(CCSDS_INSPECTION_STARTUP_INF_EID, CFE_EVS_EventType_INFORMATION,
                               "CCSDS_INSPECTION App Initialized. Version %d.%d.%d.%d",
                               CCSDS_INSPECTION_MAJOR_VERSION,
                               CCSDS_INSPECTION_MINOR_VERSION,
                               CCSDS_INSPECTION_REVISION,
                               CCSDS_INSPECTION_MISSION_REV);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("CCSDS_INSPECTION: Error sending initialization event: 0x%08X\n",
                             (unsigned int)status);
    }

    return status;
}

/*
** Process packets received on the CCSDS_INSPECTION command pipe
*/
void CCSDS_Inspection_ProcessCommandPacket(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_GetMsgId(CFE_MSG_PTR(*CCSDS_Inspection_AppData.MsgPtr), &MsgId);

    switch (CFE_SB_MsgIdToValue(MsgId))
    {
        case CCSDS_INSPECTION_CMD_MID:
            CCSDS_Inspection_ProcessGroundCommand();
            break;

        case CCSDS_INSPECTION_REQ_HK_MID:
            CCSDS_Inspection_ProcessTelemetryRequest();
            break;

        default:
            CCSDS_Inspection_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(CCSDS_INSPECTION_MSGID_ERR_EID, CFE_EVS_EventType_ERROR,
                              "CCSDS_INSPECTION: Invalid command packet, MID=0x%x",
                              CFE_SB_MsgIdToValue(MsgId));
            break;
    }
}

/*
** Process ground commands
*/
void CCSDS_Inspection_ProcessGroundCommand(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t CommandCode = 0;

    CFE_MSG_GetMsgId(CFE_MSG_PTR(*CCSDS_Inspection_AppData.MsgPtr), &MsgId);
    CFE_MSG_GetFcnCode(CFE_MSG_PTR(*CCSDS_Inspection_AppData.MsgPtr), &CommandCode);

    switch (CommandCode)
    {
        case CCSDS_INSPECTION_NOOP_CC:
            if (CCSDS_Inspection_VerifyCmdLength((CFE_MSG_Message_t *)CCSDS_Inspection_AppData.MsgPtr,
                                                 sizeof(CCSDS_Inspection_NoArgsCmd_t)) == OS_SUCCESS)
            {
                CFE_EVS_SendEvent(CCSDS_INSPECTION_CMD_NOOP_INF_EID, CFE_EVS_EventType_INFORMATION,
                                  "CCSDS_INSPECTION: NOOP command received");
            }
            break;

        case CCSDS_INSPECTION_RESET_COUNTERS_CC:
            if (CCSDS_Inspection_VerifyCmdLength((CFE_MSG_Message_t *)CCSDS_Inspection_AppData.MsgPtr,
                                                 sizeof(CCSDS_Inspection_NoArgsCmd_t)) == OS_SUCCESS)
            {
                CCSDS_Inspection_ResetCounters();
                CFE_EVS_SendEvent(CCSDS_INSPECTION_CMD_RESET_INF_EID, CFE_EVS_EventType_INFORMATION,
                                  "CCSDS_INSPECTION: RESET counters command received");
            }
            break;

        case CCSDS_INSPECTION_RUN_CC:
            if (CCSDS_Inspection_VerifyCmdLength((CFE_MSG_Message_t *)CCSDS_Inspection_AppData.MsgPtr,
                                                 sizeof(CCSDS_Inspection_NoArgsCmd_t)) == OS_SUCCESS)
            {
                CCSDS_Inspection_StartRunTask((uint8)CCSDS_INSPECTION_RUN_MODE_EXP2, "EXP2");
            }
            break;

        case CCSDS_INSPECTION_RUN_EXP1_CC:
            if (CCSDS_Inspection_VerifyCmdLength((CFE_MSG_Message_t *)CCSDS_Inspection_AppData.MsgPtr,
                                                 sizeof(CCSDS_Inspection_NoArgsCmd_t)) == OS_SUCCESS)
            {
                CCSDS_Inspection_StartRunTask((uint8)CCSDS_INSPECTION_RUN_MODE_EXP1, "EXP1");
            }
            break;

        case CCSDS_INSPECTION_RUN_EXP2_CC:
            if (CCSDS_Inspection_VerifyCmdLength((CFE_MSG_Message_t *)CCSDS_Inspection_AppData.MsgPtr,
                                                 sizeof(CCSDS_Inspection_NoArgsCmd_t)) == OS_SUCCESS)
            {
                CCSDS_Inspection_StartRunTask((uint8)CCSDS_INSPECTION_RUN_MODE_EXP2, "EXP2");
            }
            break;

        case CCSDS_INSPECTION_RUN_EXP3_CC:
            if (CCSDS_Inspection_VerifyCmdLength((CFE_MSG_Message_t *)CCSDS_Inspection_AppData.MsgPtr,
                                                 sizeof(CCSDS_Inspection_NoArgsCmd_t)) == OS_SUCCESS)
            {
                CCSDS_Inspection_StartRunTask((uint8)CCSDS_INSPECTION_RUN_MODE_EXP3, "EXP3");
            }
            break;

        case CCSDS_INSPECTION_RUN_EXP4_CC:
            if (CCSDS_Inspection_VerifyCmdLength((CFE_MSG_Message_t *)CCSDS_Inspection_AppData.MsgPtr,
                                                 sizeof(CCSDS_Inspection_NoArgsCmd_t)) == OS_SUCCESS)
            {
                CCSDS_Inspection_StartRunTask((uint8)CCSDS_INSPECTION_RUN_MODE_EXP4, "EXP4");
            }
            break;

        default:
            CCSDS_Inspection_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(CCSDS_INSPECTION_CMD_ERR_EID, CFE_EVS_EventType_ERROR,
                              "CCSDS_INSPECTION: Invalid command code, MID=0x%x, CC=%d",
                              CFE_SB_MsgIdToValue(MsgId), CommandCode);
            break;
    }
}

/*
** Process Telemetry Request
*/
void CCSDS_Inspection_ProcessTelemetryRequest(void)
{
    CFE_MSG_FcnCode_t CommandCode = 0;
    CFE_MSG_GetFcnCode(CFE_MSG_PTR(*CCSDS_Inspection_AppData.MsgPtr), &CommandCode);

    switch (CommandCode)
    {
        case CCSDS_INSPECTION_REQ_HK_TLM:
            CCSDS_Inspection_ReportHousekeeping();
            break;

        default:
            CCSDS_Inspection_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(CCSDS_INSPECTION_CMD_ERR_EID, CFE_EVS_EventType_ERROR,
                              "CCSDS_INSPECTION: Invalid telemetry request CC=%d", CommandCode);
            break;
    }
}

/*
** Report Application Housekeeping
*/
void CCSDS_Inspection_ReportHousekeeping(void)
{
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&CCSDS_Inspection_AppData.HkTelemetryPkt);
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&CCSDS_Inspection_AppData.HkTelemetryPkt, true);
}

/*
** Reset all global counter variables
*/
void CCSDS_Inspection_ResetCounters(void)
{
    CCSDS_Inspection_AppData.HkTelemetryPkt.CommandErrorCount = 0;
    CCSDS_Inspection_AppData.HkTelemetryPkt.CommandCount = 0;
    CCSDS_Inspection_AppData.HkTelemetryPkt.RunCount = 0;
    CCSDS_Inspection_AppData.HkTelemetryPkt.LastRunStatus = 0;
}

/*
** Verify command packet length matches expected
*/
int32 CCSDS_Inspection_VerifyCmdLength(CFE_MSG_Message_t *msg, uint16 expected_length)
{
    int32 status = OS_SUCCESS;
    CFE_SB_MsgId_t msg_id = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t cmd_code = 0;
    size_t actual_length = 0;

    CFE_MSG_GetSize(msg, &actual_length);
    if (expected_length == actual_length)
    {
        CCSDS_Inspection_AppData.HkTelemetryPkt.CommandCount++;
    }
    else
    {
        CFE_MSG_GetMsgId(msg, &msg_id);
        CFE_MSG_GetFcnCode(msg, &cmd_code);

        CFE_EVS_SendEvent(CCSDS_INSPECTION_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                          "Invalid msg length: ID=0x%X, CC=%d, Len=%ld, Expected=%d",
                          CFE_SB_MsgIdToValue(msg_id), cmd_code, actual_length, expected_length);

        status = OS_ERROR;
        CCSDS_Inspection_AppData.HkTelemetryPkt.CommandErrorCount++;
    }

    return status;
}
