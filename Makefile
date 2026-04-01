# NetSniff - Makefile
#
# Targets:
#   make            — build with libpcap (default)
#   make nopcap     — build with raw sockets (no libpcap/Npcap dependency)
#   make debug      — debug build with sanitizers
#   make clean      — remove build artifacts

CC       ?= cc
CFLAGS    = -std=c11 -Wall -Wextra -O2
CFLAGS   += -Iinclude
LDFLAGS   =

# Platform detection
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
  CFLAGS += -D_DARWIN_C_SOURCE
  PCAP_CFLAGS := $(shell pcap-config --cflags 2>/dev/null)
  PCAP_LIBS   := $(shell pcap-config --libs 2>/dev/null || echo "-lpcap")
else ifeq ($(UNAME_S),Linux)
  CFLAGS += -D_POSIX_C_SOURCE=200809L
  PCAP_CFLAGS := $(shell pkg-config --cflags libpcap 2>/dev/null)
  PCAP_LIBS   := $(shell pkg-config --libs libpcap 2>/dev/null || echo "-lpcap")
else
  # Windows (MinGW)
  PCAP_CFLAGS =
  PCAP_LIBS   = -lwpcap -lPacket -lws2_32
  CFLAGS     += -D_WIN32_WINNT=0x0601
endif

# ── Common sources (everything except capture backend) ───────
COMMON_SRCS = src/main.c       \
              src/dissect.c     \
              src/filter.c      \
              src/ringbuf.c     \
              src/ui.c          \
              src/export_pcap.c \
              src/export_json.c \
              src/stats.c       \
              src/session.c     \
              src/syslog_out.c

TARGET  = snuffles

# ── Default: libpcap build ───────────────────────────────────
SRCS_PCAP = $(COMMON_SRCS) src/capture.c
OBJS_PCAP = $(SRCS_PCAP:.c=.o)

PCAP_CFLAGS_ALL = $(CFLAGS) $(PCAP_CFLAGS)
PCAP_LDFLAGS    = $(LDFLAGS) $(PCAP_LIBS) -lpthread -lm

# ── NO_PCAP: raw socket build ───────────────────────────────
SRCS_RAW  = $(COMMON_SRCS) src/capture_raw.c
OBJS_RAW  = $(SRCS_RAW:.c=.o)

RAW_CFLAGS_ALL = $(CFLAGS) -DNO_PCAP
ifeq ($(UNAME_S),Linux)
  RAW_LDFLAGS = $(LDFLAGS) -lpthread -lm
else
  # Windows (MinGW)
  RAW_LDFLAGS = $(LDFLAGS) -lws2_32 -liphlpapi -lpthread -lm
endif

.PHONY: all nopcap clean debug analyze

# ── Default target (libpcap) ─────────────────────────────────
all: $(TARGET)

$(TARGET): $(OBJS_PCAP)
	$(CC) $(PCAP_CFLAGS_ALL) -o $@ $^ $(PCAP_LDFLAGS)

# Pattern rule for pcap build
src/%.o: src/%.c
	$(CC) $(PCAP_CFLAGS_ALL) -c -o $@ $<

# ── NO_PCAP target (raw sockets) ────────────────────────────
nopcap: CFLAGS += -DNO_PCAP
nopcap: clean
	@echo "Building with raw sockets (no libpcap)..."
	$(CC) $(RAW_CFLAGS_ALL) -o $(TARGET) $(SRCS_RAW) $(RAW_LDFLAGS)
	@echo "Done: ./$(TARGET)  (raw socket backend)"

clean:
	rm -f src/*.o $(TARGET)

# Debug build with sanitizers
debug: CFLAGS += -g -fsanitize=address,undefined -fno-omit-frame-pointer -O0
debug: LDFLAGS += -fsanitize=address,undefined
debug: clean $(TARGET)

# Static analysis (clang)
analyze:
	scan-build $(MAKE) clean all
