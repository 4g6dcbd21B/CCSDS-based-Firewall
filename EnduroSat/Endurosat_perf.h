#ifndef ENDUROSAT_PERF_H
#define ENDUROSAT_PERF_H

#include "taskmon_cfg.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void endurosat_perf_init(void);
bool endurosat_perf_start(task_mon_id_t task_id, uint32_t period_ms);
void endurosat_perf_stop(void);
bool endurosat_perf_is_active(void);

#ifdef __cplusplus
}
#endif

#endif
