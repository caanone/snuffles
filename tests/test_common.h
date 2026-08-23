#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stdio.h>

static int test_failures = 0;

#define CHECK(cond) do {                                             \
        if (!(cond)) {                                               \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
            test_failures++;                                         \
        }                                                            \
    } while (0)

#define TEST_MAIN_END()                                              \
    do {                                                             \
        if (test_failures) {                                         \
            printf("%d failure(s)\n", test_failures);                \
            return 1;                                                \
        }                                                            \
        printf("all tests pass\n");                                  \
        return 0;                                                    \
    } while (0)

#endif
