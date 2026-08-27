#ifndef CONFIG_H
#define CONFIG_H

#include "snuffles.h"

/* Saved display-filter preset, applied in the TUI as "@name". */
typedef struct {
    char name[32];
    char expr[256];
} filter_preset_t;

/* Load a config file into cfg and presets. path NULL resolves to
 * $SNUFFLES_CONFIG if set, else $HOME/.snufflesrc (POSIX) or
 * %USERPROFILE%\.snufflesrc (Windows). A missing file is not an error.
 * Bad lines (unknown key, out-of-range value, unparseable syntax) warn
 * once on stderr and are skipped — never fatal. Returns the number of
 * presets stored (0..max_presets). */
int config_load(const char *path, capture_cfg_t *cfg,
                filter_preset_t *presets, int max_presets);

#endif /* CONFIG_H */
