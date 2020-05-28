#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../token.c"
#include "assert.h"

typedef struct {
  const char *const base10;
  const uint64_t num;
} test_vector_t;

static test_vector_t test_vectors[] = {
  {"0", 0},
  {"1", 1},
  {"321", 321},
  {"123456789012345678901", 12345678901234567890U},
  {NULL}
};

void
test_uint64_to_base10(void)
{
  test_vector_t *v = test_vectors;
  size_t ret;

  uint8_t buf[20];

  while (v->base10 != NULL) {
    ret = uint64_to_base10(buf, v->num, (sizeof (buf)));
    assert(ret >= 0 && ret < (sizeof (buf)) + 1);
    assert(memcmp(v->base10, buf + ret, (sizeof (buf)) - ret) == 0);

    v++;
  }
}

int
main(void)
{
  test_uint64_to_base10();

  printf("tests passed: %d failed: %d\n", tests_passed, tests_failed);

  return !(tests_failed == 0);
}
