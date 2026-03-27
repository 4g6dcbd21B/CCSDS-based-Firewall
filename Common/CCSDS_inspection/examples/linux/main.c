#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../../ccsds_packet_check.h"

static void print_status(const char *label, int32_t status)
{
    printf("%s: %d (%s)\n", label, (int)status, CCSDS_GetErrorMessage(status));
}

int main(void)
{
    uint8_t cltu_ok[] = {0xEB, 0x90, 0xAA, 0x55};
    uint8_t cadu_ok[] = {0x1A, 0xCF, 0xFC, 0x1D, 0x11, 0x22, 0x33, 0x44};
    uint8_t payload[] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    uint8_t original[sizeof(payload)];
    int32_t status;

    memcpy(original, payload, sizeof(payload));

    status = Check_Packet_CLTU(cltu_ok, (uint16_t)sizeof(cltu_ok));
    print_status("Check_Packet_CLTU", status);

    status = Check_Packet_CADU(cadu_ok, (uint16_t)sizeof(cadu_ok));
    print_status("Check_Packet_CADU", status);

    status = CCSDS_Randomize(payload, (uint16_t)sizeof(payload));
    print_status("CCSDS_Randomize", status);

    status = CCSDS_DeRandomize(payload, (uint16_t)sizeof(payload));
    print_status("CCSDS_DeRandomize", status);

    if (memcmp(original, payload, sizeof(payload)) != 0) {
        printf("Round-trip randomize/de-randomize: FAIL\n");
        return 1;
    }
    printf("Round-trip randomize/de-randomize: PASS\n");

    printf("\nRunning attack-scenario demos (AS-1,2,4,5,6)...\n");
    ccsds_run_as1();
    ccsds_run_as2();
    ccsds_run_as4();
    ccsds_run_as5();
    ccsds_run_as6();
    printf("Scenario demo complete.\n");

    return 0;
}
