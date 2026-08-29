# Snuffles - Makefile
#
# Targets:
#   make            — build with libpcap (default)
#   make nopcap     — build with raw sockets (no libpcap/Npcap dependency)
#   make debug      — debug build with ASan/UBSan (libpcap)
#   make analyze    — clang static analysis
#   make clean      — remove build artifacts
#
# Objects for each variant live under build/<variant>/ so switching targets
# never links stale objects from another configuration. Header dependencies
# are tracked (-MMD), so editing a header rebuilds what includes it.

CC     ?= cc
TARGET  = snuffles

# Internal flags are separate from user CFLAGS/LDFLAGS so a command-line
# CFLAGS=... doesn't drop -Iinclude or the feature-test macros.
BASE_CFLAGS = -std=c11 -Wall -Wextra -Iinclude -MMD -MP

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
  BASE_CFLAGS += -D_DARWIN_C_SOURCE
  PCAP_CFLAGS := $(shell pcap-config --cflags 2>/dev/null)
  PCAP_LIBS   := $(shell pcap-config --libs 2>/dev/null || echo "-lpcap")
  PCAP_LDLIBS  = $(PCAP_LIBS) -lpthread -lm
  RAW_LDLIBS   = -lpthread -lm
else ifeq ($(UNAME_S),Linux)
  # _DEFAULT_SOURCE: glibc hides struct ifreq/SO_BINDTODEVICE/IFF_PROMISC
  # behind it when strict _POSIX_C_SOURCE is defined.
  BASE_CFLAGS += -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
  PCAP_CFLAGS := $(shell pkg-config --cflags libpcap 2>/dev/null)
  PCAP_LIBS   := $(shell pkg-config --libs libpcap 2>/dev/null || echo "-lpcap")
  PCAP_LDLIBS  = $(PCAP_LIBS) -lpthread -lm
  RAW_LDLIBS   = -lpthread -lm
else
  # Windows (MinGW)
  BASE_CFLAGS += -D_WIN32_WINNT=0x0601
  PCAP_CFLAGS  =
  PCAP_LDLIBS  = -lwpcap -lPacket -lws2_32 -lpthread -lm
  RAW_LDLIBS   = -lws2_32 -liphlpapi -lpthread -lm
endif

COMMON_SRCS = src/main.c       \
              src/config.c      \
              src/dissect.c     \
              src/filter.c      \
              src/ringbuf.c     \
              src/ui.c          \
              src/export_pcap.c \
              src/export_json.c \
              src/stats.c       \
              src/session.c     \
              src/syslog_out.c  \
              src/output.c

SRCS_PCAP = $(COMMON_SRCS) src/capture.c
SRCS_RAW  = $(COMMON_SRCS) src/capture_raw.c src/cbpf.c src/rawring.c

RELEASE_FLAGS = -O2
DEBUG_FLAGS   = -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer

OBJDIR     = build
OBJS_PCAP  = $(SRCS_PCAP:src/%.c=$(OBJDIR)/pcap/%.o)
OBJS_RAW   = $(SRCS_RAW:src/%.c=$(OBJDIR)/raw/%.o)
OBJS_DEBUG = $(SRCS_PCAP:src/%.c=$(OBJDIR)/debug/%.o)

# ── Unit tests (also runnable via CTest; this target keeps them
#    available on the make-only path, e.g. macOS release builds) ──
TESTS      = filter ringbuf session dissect cbpf rawring config export_json syslog_out output ui
TEST_BINS  = $(TESTS:%=$(OBJDIR)/tests/test_%)
# make test SAN=1 -> run the suite under ASan/UBSan
ifdef SAN
  TEST_FLAGS   = -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer
  TEST_LDFLAGS = -fsanitize=address,undefined
else
  TEST_FLAGS   = -g -O2
  TEST_LDFLAGS =
endif
TEST_LDLIBS = -lpthread -lm

ALL_DEPS   = $(OBJS_PCAP:.o=.d) $(OBJS_RAW:.o=.d) $(OBJS_DEBUG:.o=.d) \
             $(TEST_BINS:=.d)

PREFIX ?= /usr/local

.PHONY: all nopcap debug clean analyze install uninstall test test-stress

# Each variant links its own binary under build/, then copies it to ./snuffles,
# so "make" after "make nopcap" can't leave a stale mixed binary in place.
all: $(OBJDIR)/pcap/$(TARGET)
	@cp -f $< $(TARGET)

$(OBJDIR)/pcap/$(TARGET): $(OBJS_PCAP)
	$(CC) -o $@ $^ $(LDFLAGS) $(PCAP_LDLIBS)

$(OBJDIR)/pcap/%.o: src/%.c | $(OBJDIR)/pcap
	$(CC) $(BASE_CFLAGS) $(RELEASE_FLAGS) $(PCAP_CFLAGS) $(CFLAGS) -c -o $@ $<

nopcap: $(OBJDIR)/raw/$(TARGET)
	@cp -f $< $(TARGET)
	@echo "Done: ./$(TARGET)  (raw socket backend)"

$(OBJDIR)/raw/$(TARGET): $(OBJS_RAW)
	$(CC) -o $@ $^ $(LDFLAGS) $(RAW_LDLIBS)

$(OBJDIR)/raw/%.o: src/%.c | $(OBJDIR)/raw
	$(CC) $(BASE_CFLAGS) $(RELEASE_FLAGS) -DNO_PCAP $(CFLAGS) -c -o $@ $<

debug: $(OBJDIR)/debug/$(TARGET)
	@cp -f $< $(TARGET)
	@echo "Done: ./$(TARGET)  (debug, ASan+UBSan)"

$(OBJDIR)/debug/$(TARGET): $(OBJS_DEBUG)
	$(CC) $(DEBUG_FLAGS) -o $@ $^ $(LDFLAGS) $(PCAP_LDLIBS)

$(OBJDIR)/debug/%.o: src/%.c | $(OBJDIR)/debug
	$(CC) $(BASE_CFLAGS) $(DEBUG_FLAGS) $(PCAP_CFLAGS) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/pcap $(OBJDIR)/raw $(OBJDIR)/debug:
	mkdir -p $@

# ── Tests ────────────────────────────────────────────────────
$(OBJDIR)/tests/test_%: tests/test_%.c src/%.c | $(OBJDIR)/tests
	$(CC) $(BASE_CFLAGS) $(TEST_FLAGS) -Isrc $(CFLAGS) -o $@ $^ \
	      $(TEST_LDFLAGS) $(LDFLAGS) $(TEST_LDLIBS)

# the display filter formats text columns on demand (summary_format)
$(OBJDIR)/tests/test_filter: tests/test_filter.c src/filter.c src/dissect.c \
                             | $(OBJDIR)/tests
	$(CC) $(BASE_CFLAGS) $(TEST_FLAGS) -Isrc $(CFLAGS) -o $@ $^ \
	      $(TEST_LDFLAGS) $(LDFLAGS) $(TEST_LDLIBS)

# export_json.c also walks the ring through the display filter
$(OBJDIR)/tests/test_export_json: tests/test_export_json.c src/export_json.c \
                                  src/filter.c src/dissect.c src/ringbuf.c \
                                  | $(OBJDIR)/tests
	$(CC) $(BASE_CFLAGS) $(TEST_FLAGS) -Isrc $(CFLAGS) -o $@ $^ \
	      $(TEST_LDFLAGS) $(LDFLAGS) $(TEST_LDLIBS)

# the output thread drives both sinks off the ring
$(OBJDIR)/tests/test_output: tests/test_output.c src/output.c src/ringbuf.c \
                             src/syslog_out.c src/export_pcap.c src/filter.c \
                             src/dissect.c \
                             | $(OBJDIR)/tests
	$(CC) $(BASE_CFLAGS) $(TEST_FLAGS) -Isrc $(CFLAGS) -o $@ $^ \
	      $(TEST_LDFLAGS) $(LDFLAGS) $(TEST_LDLIBS)

# test_ui.c includes src/ui.c (white-box access to the pacing counters)
# and stubs the capture/export entry points; it links what the UI uses.
$(OBJDIR)/tests/test_ui: tests/test_ui.c src/filter.c src/dissect.c src/stats.c \
                         src/session.c src/ringbuf.c | $(OBJDIR)/tests
	$(CC) $(BASE_CFLAGS) $(TEST_FLAGS) -Isrc $(CFLAGS) -o $@ $^ \
	      $(TEST_LDFLAGS) $(LDFLAGS) $(TEST_LDLIBS)

$(OBJDIR)/tests:
	mkdir -p $@

test: $(TEST_BINS)
	@fail=0; \
	for t in $(TEST_BINS); do \
	  printf '%-14s ' "$$(basename $$t)"; \
	  if $$t >/dev/null 2>&1; then echo "pass"; \
	  else echo "FAIL"; $$t 2>&1 | tail -20; fail=1; fi; \
	done; \
	if [ $$fail -eq 0 ]; then echo "all tests pass"; else \
	  echo "TEST FAILURES"; exit 1; fi

# Repeat the concurrency suite: seqlock/memory-ordering defects are
# racy by nature and a single green run proves little (RUNS=n).
RUNS ?= 20
test-stress: $(OBJDIR)/tests/test_ringbuf $(OBJDIR)/tests/test_session
	@fail=0; \
	for i in $$(seq 1 $(RUNS)); do \
	  $(OBJDIR)/tests/test_ringbuf >/dev/null 2>&1 || fail=$$((fail+1)); \
	  $(OBJDIR)/tests/test_session >/dev/null 2>&1 || fail=$$((fail+1)); \
	done; \
	echo "stress: $(RUNS) rounds, $$fail failure(s)"; \
	[ $$fail -eq 0 ] || exit 1

clean:
	rm -rf $(OBJDIR) $(TARGET) $(TARGET).exe src/*.o

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/share/man/man1
	install -m755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/
	install -m644 docs/snuffles.1 $(DESTDIR)$(PREFIX)/share/man/man1/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET) \
	      $(DESTDIR)$(PREFIX)/share/man/man1/snuffles.1

analyze:
	scan-build $(MAKE) clean all

-include $(ALL_DEPS)
