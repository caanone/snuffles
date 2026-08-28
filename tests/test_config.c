#include "config.h"
#include "test_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
static int set_env(const char *k, const char *v) { return _putenv_s(k, v); }
#else
static int set_env(const char *k, const char *v) { return setenv(k, v, 1); }
#endif

/* relative to the test's cwd (build dir under ctest, repo root under wine) */
#define CFG_PATH "test_snufflesrc.tmp"

static int write_file(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs(text, f);
    fclose(f);
    return 0;
}

int main(void) {
    static const char *text =
        "# snuffles test config\n"
        "\n"
        "  interface = eth0  \n"
        "snaplen=128\n"
        "ring_size = 512\n"
        "buffer_mb = 16\n"
        "promisc = 0\n"
        "syslog = 10.0.0.1:514\n"
        "syslog_iface = eth1\n"
        "unknown_key = whatever\n"       /* warn + skip */
        "snaplen = 999999\n"             /* out of range: keep 128 */
        "ring_size = banana\n"           /* not a number: keep 512 */
        "buffer_mb = 0\n"                /* out of range: keep 16 */
        "this line has no equals sign\n" /* warn + skip */
        "preset web = tcp and port 443\n"
        "  preset   DNS-Fast  =  udp and port 53  \n"
        "preset bad!name = tcp\n"        /* invalid name char */
        "preset thisnameiswaytoolongtofitinthefield = tcp\n"
        "preset empty =   \n"            /* empty expression */
        "preset = tcp\n"                 /* missing name */
        "preset third = icmp\n";

    CHECK(write_file(CFG_PATH, text) == 0);

    /* explicit path */
    capture_cfg_t cfg;
    capture_cfg_defaults(&cfg);
    filter_preset_t presets[8];
    memset(presets, 0, sizeof(presets));

    int n = config_load(CFG_PATH, &cfg, presets, 8);
    CHECK(n == 3);
    CHECK(strcmp(cfg.iface, "eth0") == 0);
    CHECK(cfg.snaplen == 128);
    CHECK(cfg.ring_size == 512);
    CHECK(cfg.buffer_mb == 16);
    CHECK(cfg.promisc == 0);
    CHECK(strcmp(cfg.syslog_target, "10.0.0.1:514") == 0);
    CHECK(strcmp(cfg.syslog_iface, "eth1") == 0);
    CHECK(strcmp(presets[0].name, "web") == 0);
    CHECK(strcmp(presets[0].expr, "tcp and port 443") == 0);
    CHECK(strcmp(presets[1].name, "DNS-Fast") == 0);
    CHECK(strcmp(presets[1].expr, "udp and port 53") == 0);
    CHECK(strcmp(presets[2].name, "third") == 0);
    CHECK(strcmp(presets[2].expr, "icmp") == 0);

    /* path NULL resolves through $SNUFFLES_CONFIG */
    capture_cfg_t cfg2;
    capture_cfg_defaults(&cfg2);
    filter_preset_t presets2[8];
    memset(presets2, 0, sizeof(presets2));
    CHECK(set_env("SNUFFLES_CONFIG", CFG_PATH) == 0);
    n = config_load(NULL, &cfg2, presets2, 8);
    CHECK(n == 3);
    CHECK(strcmp(cfg2.iface, "eth0") == 0);
    CHECK(cfg2.snaplen == 128);
    CHECK(strcmp(presets2[0].name, "web") == 0);

    /* max_presets caps the count; extra presets warn + drop */
    capture_cfg_t cfg3;
    capture_cfg_defaults(&cfg3);
    filter_preset_t one[1];
    memset(one, 0, sizeof(one));
    n = config_load(CFG_PATH, &cfg3, one, 1);
    CHECK(n == 1);
    CHECK(strcmp(one[0].name, "web") == 0);

    /* missing file: silent, returns 0, cfg untouched */
    capture_cfg_t cfg4;
    capture_cfg_defaults(&cfg4);
    CHECK(set_env("SNUFFLES_CONFIG", "no_such_file_snuffles.tmp") == 0);
    n = config_load(NULL, &cfg4, presets, 8);
    CHECK(n == 0);
    CHECK(cfg4.snaplen == 65535);
    CHECK(cfg4.ring_size == 10000);
    CHECK(cfg4.buffer_mb == 64);
    CHECK(cfg4.promisc == 1);
    CHECK(cfg4.iface[0] == '\0');

    remove(CFG_PATH);
    TEST_MAIN_END();
}
