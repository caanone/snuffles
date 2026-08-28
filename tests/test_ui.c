/* TUI main-loop pacing: frames are capped at ~30/s under load, drawn at
 * once on a key, throttled to the heartbeat when idle, and the sessions
 * view refreshes its table snapshot at most every 250 ms.
 *
 * White-box: ui.c is included so the test can read the pacing counters;
 * the capture and export entry points the UI calls are stubbed. The loop
 * runs on the real ui_run() with a pipe as stdin and /dev/null as stdout.
 * POSIX only (pipes, pthread). */
#include "../src/ui.c"
#include "test_common.h"
#include <fcntl.h>
#include <pthread.h>

/* ── stubs: the UI only reads status through these ──────────── */

int capture_is_running(const capture_ctx_t *c) { (void)c; return 1; }
int capture_had_error(const capture_ctx_t *c)  { (void)c; return 0; }
const char *capture_error_msg(const capture_ctx_t *c) { (void)c; return ""; }
const char *capture_get_iface(const capture_ctx_t *c) { (void)c; return "test0"; }
const char *capture_get_bpf(const capture_ctx_t *c)   { (void)c; return ""; }
int capture_get_datalink(const capture_ctx_t *c)      { (void)c; return 1; }
void capture_get_stats(capture_ctx_t *c, capture_stats_raw_t *out) {
    (void)c; memset(out, 0, sizeof(*out));
}
int capture_set_bpf(capture_ctx_t *c, const char *expr, char *err, size_t n) {
    (void)c; (void)expr; (void)err; (void)n; return 0;
}
int export_pcap(const char *path, ringbuf_t *rb, const display_filter_t *f,
                uint32_t snaplen, int linktype) {
    (void)path; (void)rb; (void)f; (void)snaplen; (void)linktype; return 0;
}
int export_json(const char *path, ringbuf_t *rb, const display_filter_t *f,
                const char *iface, const char *bpf) {
    (void)path; (void)rb; (void)f; (void)iface; (void)bpf; return 0;
}

/* ── harness ─────────────────────────────────────────────────── */

static int g_key_w = -1;    /* write end of the pipe that is the UI's stdin */

static void send_keys(const char *s) {
    (void)!write(g_key_w, s, strlen(s));
}

typedef struct {
    ringbuf_t       *rb;
    session_table_t *st;
    int              delay_ms;   /* idle before the flood (0 = none) */
    int              flood_ms;   /* commit as fast as possible this long */
    int              nsessions;  /* > 0: also feed the session table */
    const char      *then;       /* keys sent when done ("q" ends the run) */
} load_t;

static void *load_thread(void *arg) {
    load_t *l = (load_t *)arg;
    if (l->delay_ms) usleep((useconds_t)l->delay_ms * 1000);
    uint64_t end = ui_now_us() + (uint64_t)l->flood_ms * 1000u;
    uint32_t n = 0;
    while (l->flood_ms && ui_now_us() < end) {
        pkt_summary_t s;
        memset(&s, 0, sizeof(s));
        snprintf(s.src_ip, sizeof(s.src_ip), "10.0.0.1");
        snprintf(s.dst_ip, sizeof(s.dst_ip), "10.0.0.2");
        snprintf(s.protocol, sizeof(s.protocol), "UDP");
        s.l3_proto = PROTO_IPV4;
        s.l4_proto = s.highest_proto = PROTO_UDP;
        s.src_port = (uint16_t)(1024 + (l->nsessions ? n % (uint32_t)l->nsessions : 0));
        s.dst_port = 53;
        s.length   = 60;
        s.ts.tv_sec = (long)(n / 1000);
        pkt_record_t *r = ringbuf_producer_next(l->rb);
        r->summary = s;
        r->raw_len = 0;
        ringbuf_producer_commit(l->rb);
        if (l->nsessions)
            session_table_update(l->st, &s, NULL, 0);
        n++;
    }
    send_keys(l->then);
    return NULL;
}

/* Runs ui_run() with the load thread; returns wall time in ms. */
static uint64_t run_ui(ui_ctx_t *ui, load_t *l) {
    fflush(stdout);
    int saved = dup(STDOUT_FILENO);
    int null  = open("/dev/null", O_WRONLY);
    dup2(null, STDOUT_FILENO);
    ui->frames_rendered = 0;
    ui->snapshots_taken = 0;
    pthread_t th;
    uint64_t t0 = ui_now_us();
    pthread_create(&th, NULL, load_thread, l);
    ui_run(ui);
    uint64_t el = (ui_now_us() - t0) / 1000u;
    pthread_join(th, NULL);
    ui->stop = 0;
    dup2(saved, STDOUT_FILENO);
    close(saved);
    close(null);
    return el;
}

int main(void) {
    int p[2];
    CHECK(pipe(p) == 0);
    fcntl(p[0], F_SETFL, O_NONBLOCK);
    dup2(p[0], STDIN_FILENO);       /* read_key() polls this */
    g_key_w = p[1];

    ringbuf_t *rb = ringbuf_create(4096, 256);
    session_table_t *st = session_table_create(4096);
    capture_cfg_t cfg;
    capture_cfg_defaults(&cfg);
    ui_ctx_t *ui = ui_create(rb, NULL, &cfg, st, NULL, 0);
    CHECK(rb && st && ui);

    /* 1. Flood, packets view: ~30 frames/s, never per packet; stats keep
     *    up with the ring (the sleep is bounded by the ring-wrap rate). */
    {
        load_t l = { rb, st, 0, 500, 0, "q" };
        uint64_t ms = run_ui(ui, &l);
        uint64_t cap = ms / 33 + 2;              /* first frame + slop */
        printf("flood/packets: %llu frames in %llu ms (cap %llu), stats saw %llu of %llu\n",
               (unsigned long long)ui->frames_rendered, (unsigned long long)ms,
               (unsigned long long)cap, (unsigned long long)ui->stats.total_packets,
               (unsigned long long)ringbuf_total(rb));
        CHECK(ui->frames_rendered <= cap);
        CHECK(ui->frames_rendered >= 3);
        CHECK(ui->stats.total_packets > 0);
        CHECK(ui->snapshots_taken == 0);          /* not in the sessions view */
    }

    /* 2. Flood, sessions view: snapshots at most every 250 ms (plus the
     *    one forced by the view switch), frames still capped. */
    {
        send_keys("s");
        load_t l = { rb, st, 0, 500, 2000, "q" };
        uint64_t ms = run_ui(ui, &l);
        uint64_t fcap = ms / 33 + 3;             /* + the immediate key frame */
        uint64_t scap = ms / 250 + 2;
        printf("flood/sessions: %llu frames, %llu snapshots in %llu ms (caps %llu/%llu), %u sessions\n",
               (unsigned long long)ui->frames_rendered,
               (unsigned long long)ui->snapshots_taken, (unsigned long long)ms,
               (unsigned long long)fcap, (unsigned long long)scap,
               ui->sess_snap_count);
        CHECK(ui->view == VIEW_SESSIONS);
        CHECK(ui->frames_rendered <= fcap);
        CHECK(ui->snapshots_taken >= 1 && ui->snapshots_taken <= scap);
        CHECK(ui->sess_snap_count == session_table_count(st));
        CHECK(ui->sess_snap_count == 2000);
    }

    /* 3. Clear forces a fresh (empty) snapshot at once. */
    {
        send_keys("cq");
        load_t l = { rb, st, 0, 0, 0, "" };
        run_ui(ui, &l);
        CHECK(ui->snapshots_taken >= 1);
        CHECK(ui->sess_snap_count == 0);
        CHECK(ui->sess_snap == NULL);
        CHECK(session_table_count(st) == 0);
    }

    /* 4. Idle: only the heartbeat redraws (first frame + one per 250 ms). */
    {
        load_t l = { rb, st, 600, 0, 0, "q" };
        uint64_t ms = run_ui(ui, &l);
        uint64_t cap = ms / 250 + 2;
        printf("idle: %llu frames in %llu ms (cap %llu)\n",
               (unsigned long long)ui->frames_rendered, (unsigned long long)ms,
               (unsigned long long)cap);
        CHECK(ui->frames_rendered <= cap);
        CHECK(ui->frames_rendered >= 2);          /* heartbeat did fire */
    }

    /* 5. A key is drawn immediately, not at the next tick: 'p' 60 ms after
     *    the first frame must produce exactly one more frame before 'q'. */
    {
        load_t l = { rb, st, 60, 0, 0, "pq" };
        run_ui(ui, &l);
        printf("key: %llu frames\n", (unsigned long long)ui->frames_rendered);
        CHECK(ui->frames_rendered == 2);
        CHECK(ui->paused == 1);
    }

    ui_destroy(ui);
    session_table_destroy(st);
    ringbuf_destroy(rb);
    TEST_MAIN_END();
}
