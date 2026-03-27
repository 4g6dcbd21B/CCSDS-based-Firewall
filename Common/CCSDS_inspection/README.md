# CCSDS Inspection Common Core

This folder contains the platform-common CCSDS inspection core:

- `ccsds_packet_check.c`
- `ccsds_packet_check.h`

These files are intended to be shared by:

- `GomSpace`
- `EnduroSat`
- `Nasa-cFS`

## Linux Quick Start (Anyone Can Reproduce)

A minimal Linux demo is included at `examples/linux`.

Important:
- The Linux demo builds `Common/ccsds_inspection/ccsds_packet_check.c`.
- It does not build `GomSpace/ccsds_packet_check.c` (which includes FreeRTOS headers).

### 1) Build

```bash
cd examples/linux
make
```

### 2) Run

```bash
make run
```

Expected output includes:

- `Check_Packet_CLTU: 0`
- `Check_Packet_CADU: 0`
- `CCSDS_Randomize: 0`
- `CCSDS_DeRandomize: 0`
- `Round-trip randomize/de-randomize: PASS`
- attack-scenario demo run for `AS-1/2/4/5/6`

### 3) Clean

```bash
make clean
```

## Notes

- Build assumes a Linux environment with `gcc` and `make`.
- `-D_POSIX_C_SOURCE=200809L` is set in the Makefile for `clock_gettime` compatibility.
- Demo Makefile sets `-DCCSDS_AS_RUN_SECONDS=1` so each AS run completes quickly.
- This demo validates the core API only; platform integration remains in each platform folder.
