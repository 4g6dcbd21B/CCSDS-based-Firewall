CC ?= gcc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -D_POSIX_C_SOURCE=200809L -DCCSDS_AS_RUN_SECONDS=1
LDFLAGS ?= -lm

TARGET := ccsds_demo
SRC := ../../ccsds_packet_check.c main.c

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -I../.. -o $@ $(SRC) $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
