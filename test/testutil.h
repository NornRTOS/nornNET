#ifndef TESTUTIL_INCLUDED
#define TESTUTIL_INCLUDED
/* Minimal check helpers of the host tests; a test ends with test_finish(name). */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

static unsigned test_failures = 0;

#define CHECK(cond) \
    do { if(!(cond)) { ++test_failures; printf("CHECK FAILED %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while(0)

#define CHECK_EQ(a, b) \
    do { unsigned long _a = (unsigned long)(a), _b = (unsigned long)(b); \
         if(_a != _b) { ++test_failures; \
             printf("CHECK FAILED %s:%d: %s=%lu expected %s=%lu\n", __FILE__, __LINE__, #a, _a, #b, _b); } } while(0)

static inline void test_finish(const char *name)
{
    printf("RESULT %s %s\n", name, test_failures == 0 ? "PASS" : "FAIL");
    fflush(stdout);
    exit(test_failures == 0 ? 0 : 1);
}

#endif  /* TESTUTIL_INCLUDED */
