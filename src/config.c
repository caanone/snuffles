#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Strip leading/trailing whitespace in place; returns the first non-space
 * character (the buffer tail is modified, the head is not shifted). */
static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
    return s;
}

/* Non-fatal counterpart of main.c's parse_num: 1 and *out set only when
 * s is a clean integer within [lo, hi]. */
static int cfg_num(const char *s, long lo, long hi, int *out) {
    char *end;
    long v = strtol(s, &end, 10);
    if (end == s || *end != '\0' || v < lo || v > hi) return 0;
    *out = (int)v;
    return 1;
}

/* alnum/underscore/hyphen, 1-31 chars (fits filter_preset_t.name). */
static int preset_name_ok(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n >= sizeof(((filter_preset_t *)0)->name)) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!isalnum(c) && c != '_' && c != '-') return 0;
    }
    return 1;
}

static int resolve_path(const char *path, char *buf, size_t buflen) {
    if (path) {
        snprintf(buf, buflen, "%s", path);
        return 1;
    }
    const char *env = getenv("SNUFFLES_CONFIG");
    if (env && env[0]) {
        snprintf(buf, buflen, "%s", env);
        return 1;
    }
#ifdef _WIN32
    const char *home = getenv("USERPROFILE");
    if (!home || !home[0]) return 0;
    snprintf(buf, buflen, "%s\\.snufflesrc", home);
#else
    const char *home = getenv("HOME");
    if (!home || !home[0]) return 0;
    snprintf(buf, buflen, "%s/.snufflesrc", home);
#endif
    return 1;
}

static void warn_line(const char *path, int lineno, const char *msg,
                      const char *detail) {
    fprintf(stderr, "snuffles: %s:%d: %s '%s' (skipped)\n",
            path, lineno, msg, detail);
}

/* preset <name> = <expr>; body points past the "preset" keyword. */
static int parse_preset(const char *path, int lineno, char *body,
                        filter_preset_t *presets, int max_presets,
                        int npresets) {
    char *eq = strchr(body, '=');
    if (!eq) {
        warn_line(path, lineno, "preset without '='", body);
        return npresets;
    }
    *eq = '\0';
    char *name = trim(body);
    char *expr = trim(eq + 1);
    if (!preset_name_ok(name)) {
        warn_line(path, lineno, "invalid preset name", name);
        return npresets;
    }
    if (expr[0] == '\0') {
        warn_line(path, lineno, "empty preset expression for", name);
        return npresets;
    }
    if (strlen(expr) >= sizeof(presets[0].expr)) {
        warn_line(path, lineno, "preset expression too long for", name);
        return npresets;
    }
    if (npresets >= max_presets) {
        warn_line(path, lineno, "too many presets, dropping", name);
        return npresets;
    }
    snprintf(presets[npresets].name, sizeof(presets[npresets].name), "%s", name);
    snprintf(presets[npresets].expr, sizeof(presets[npresets].expr), "%s", expr);
    return npresets + 1;
}

static void parse_keyval(const char *path, int lineno, char *line,
                         capture_cfg_t *cfg) {
    char *eq = strchr(line, '=');
    if (!eq) {
        warn_line(path, lineno, "unparseable line", line);
        return;
    }
    *eq = '\0';
    char *key = trim(line);
    char *val = trim(eq + 1);

    if (strcmp(key, "interface") == 0) {
        snprintf(cfg->iface, sizeof(cfg->iface), "%s", val);
    } else if (strcmp(key, "snaplen") == 0) {
        if (!cfg_num(val, 64, 65535, &cfg->snaplen))
            warn_line(path, lineno, "snaplen out of range (64-65535)", val);
    } else if (strcmp(key, "ring_size") == 0) {
        if (!cfg_num(val, 16, 1000000, &cfg->ring_size))
            warn_line(path, lineno, "ring_size out of range (16-1000000)", val);
    } else if (strcmp(key, "buffer_mb") == 0) {
        if (!cfg_num(val, 1, 2047, &cfg->buffer_mb))
            warn_line(path, lineno, "buffer_mb out of range (1-2047)", val);
    } else if (strcmp(key, "promisc") == 0) {
        if (!cfg_num(val, 0, 1, &cfg->promisc))
            warn_line(path, lineno, "promisc must be 0 or 1", val);
    } else if (strcmp(key, "syslog") == 0) {
        snprintf(cfg->syslog_target, sizeof(cfg->syslog_target), "%s", val);
    } else if (strcmp(key, "syslog_iface") == 0) {
        snprintf(cfg->syslog_iface, sizeof(cfg->syslog_iface), "%s", val);
    } else if (strcmp(key, "cpu") == 0) {
        if (!cfg_num(val, 0, 8191, &cfg->cpu))
            warn_line(path, lineno, "cpu out of range (0-8191)", val);
    } else if (strcmp(key, "rt") == 0) {
        if (!cfg_num(val, 0, 1, &cfg->rt))
            warn_line(path, lineno, "rt must be 0 or 1", val);
    } else {
        warn_line(path, lineno, "unknown key", key);
    }
}

int config_load(const char *path, capture_cfg_t *cfg,
                filter_preset_t *presets, int max_presets) {
    char resolved[512];
    if (!resolve_path(path, resolved, sizeof(resolved)))
        return 0;   /* no config location available */

    FILE *f = fopen(resolved, "r");
    if (!f)
        return 0;   /* missing/unreadable config is not an error */

    char line[1024];
    int lineno = 0;
    int npresets = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *s = trim(line);
        if (s[0] == '\0' || s[0] == '#')
            continue;

        if (strncmp(s, "preset", 6) == 0 && isspace((unsigned char)s[6])) {
            npresets = parse_preset(resolved, lineno, s + 7,
                                    presets, max_presets, npresets);
        } else {
            parse_keyval(resolved, lineno, s, cfg);
        }
    }

    fclose(f);
    return npresets;
}
