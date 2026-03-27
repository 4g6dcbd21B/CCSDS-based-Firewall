# CCSDS-based-Firewall

CCSDS-based firewall research code prepared for private publication and paper artifacts.

## Repository Layout

- `Common/ccsds_inspection/`
  - Shared CCSDS inspection core (`ccsds_packet_check.c/.h`) for all platforms.
  - Includes a Linux build/run example in `examples/linux/`.
  - Linux demo compiles only this common core (not the FreeRTOS-based `GomSpace` source).
- `Common/Data/`
  - Performance measurement logs collected from each platform during firewall testing.
  - Subdirectories: `CFS/`, `Endrusat/`, `Gomspace/` — one per target platform.
  - Each file records CPU usage, timing, and (where available) temperature for a specific attack scenario (AS1–AS6) or normal traffic pattern (Beacon, Heartbeat, Alive) at varying sleep intervals (0/1/10 ms).
- `GomSpace/`
  - GomSpace-side performance monitoring module.
  - Uses FreeRTOS/runtime-stat interfaces for CPU/heap trend measurement.
  - Vendor-confidential code has been removed.
- `EnduroSat/`
  - EnduroSat-side integration module for performance monitoring.
  - Platform dependencies are intentionally kept (CMSIS-RTOS2, FreeRTOS, task monitor, MCU temperature, UART integration points).
- `NASA-cFS/`
  - cFS integration code and modified open-source components.
  - Full modification set is included.

## Publication Rules Applied

- `GomSpace` contains non-confidential performance-monitoring logic with vendor-confidential integration removed.
- `EnduroSat` keeps required platform integration points while removing vendor-confidential code.
- `ccsds_inspection`-related source/header files are centralized under `Common/ccsds_inspection`.
