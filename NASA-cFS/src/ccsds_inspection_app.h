/*******************************************************************************
** File:
**   ccsds_inspection_app.h
**
** Purpose:
**  Define CCSDS_INSPECTION app data structures and prototypes
**
*******************************************************************************/
#ifndef _CCSDS_INSPECTION_APP_H_
#define _CCSDS_INSPECTION_APP_H_

#include "cfe.h"
#include "cfe_es.h"
#include "ccsds_inspection_platform_cfg.h"
#include "ccsds_inspection_msgids.h"
#include "ccsds_inspection_msg.h"
#include "ccsds_inspection_events.h"
#include "ccsds_inspection_perfids.h"
#include "ccsds_inspection_version.h"

/*
** CCSDS_INSPECTION application data
*/
typedef struct
{
    uint32 RunStatus;
    CFE_SB_PipeId_t    CmdPipe;
    CFE_SB_Buffer_t   *MsgPtr;
    CCSDS_Inspection_HkTlm_t HkTelemetryPkt;

} CCSDS_Inspection_AppData_t;

/*
** Application entry point and main process loop
*/
void CCSDSI_AppMain(void);
void CCSDS_Inspection_AppMain(void);

/*
** Application initialization
*/
int32 CCSDS_Inspection_AppInit(void);

/*
** Process packets received on the CCSDS_INSPECTION command pipe
*/
void CCSDS_Inspection_ProcessCommandPacket(void);

/*
** Process ground commands
*/
void CCSDS_Inspection_ProcessGroundCommand(void);

/*
** Process telemetry request
*/
void CCSDS_Inspection_ProcessTelemetryRequest(void);

/*
** Report Application Housekeeping
*/
void CCSDS_Inspection_ReportHousekeeping(void);

/*
** Reset counters
*/
void CCSDS_Inspection_ResetCounters(void);

/*
** Verify command packet length matches expected
*/
int32 CCSDS_Inspection_VerifyCmdLength(CFE_MSG_Message_t *msg, uint16 expected_length);

#endif /* _CCSDS_INSPECTION_APP_H_ */
