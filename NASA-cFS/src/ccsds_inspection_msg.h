/*******************************************************************************
** File:
**   ccsds_inspection_msg.h
**
** Purpose:
**  Define CCSDS_INSPECTION application commands and telemetry messages
**
*******************************************************************************/
#ifndef _CCSDS_INSPECTION_MSG_H_
#define _CCSDS_INSPECTION_MSG_H_

#include "cfe.h"

/*
** Ground Command Codes
*/
#define CCSDS_INSPECTION_NOOP_CC            0
#define CCSDS_INSPECTION_RESET_COUNTERS_CC  1
#define CCSDS_INSPECTION_RUN_CC             2
#define CCSDS_INSPECTION_RUN_EXP1_CC        3
#define CCSDS_INSPECTION_RUN_EXP2_CC        4
#define CCSDS_INSPECTION_RUN_EXP3_CC        5
#define CCSDS_INSPECTION_RUN_EXP4_CC        6

/*
** Telemetry Request Command Codes
*/
#define CCSDS_INSPECTION_REQ_HK_TLM         0

/*
** Generic "no arguments" command type definition
*/
typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;

} CCSDS_Inspection_NoArgsCmd_t;

/*
** CCSDS_INSPECTION housekeeping type definition
*/
typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint8   CommandErrorCount;
    uint8   CommandCount;
    uint32  RunCount;
    uint32  LastRunStatus;

} __attribute__((packed)) CCSDS_Inspection_HkTlm_t;
#define CCSDS_INSPECTION_HK_TLM_LNGTH sizeof ( CCSDS_Inspection_HkTlm_t )

#endif /* _CCSDS_INSPECTION_MSG_H_ */
