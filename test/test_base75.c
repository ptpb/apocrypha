#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../base75.c"
#include "assert.h"

typedef struct {
  const char *const base256;
  const char *const base75;
} test_vector_t;

static test_vector_t test_vectors[] = {
  {"a", "B$"},
  {"foobar1", "enDl0bct6"},
  {"foobar1spam", "enDl0bct6zJr~j"},
  {"foobar1spamegg", "enDl0bct6reXp9IN.I"},
  {"foobar1spamegga", "enDl0bct6reXp9IN.IB$"},
  {
    "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55",
    "L6!sZk:41f3Q7ZjBHKL8?D99PGH9H7IVY~i0AsvMY",
  },
  {NULL}
};

void
test_base75(void)
{
  test_vector_t *v = test_vectors;

  while (v->base256 != NULL) {
    uint8_t out75[base75_min_symbols(strlen(v->base256)) + 1];
    memset(out75, '\0', (sizeof (out75)));
    ssize_t out75_len = uint8_to_base75(v->base256, strlen(v->base256), out75);

    assert((sizeof (out75)) - 1 >= out75_len);
    assert(out75_len == strlen(v->base75));
    assert(memcmp(out75, v->base75, out75_len) == 0);

    uint8_t out256[base75_min_length(strlen(v->base75)) + 1];
    memset(out256, '\0', (sizeof (out256)));
    ssize_t out256_len = base75_to_uint8(v->base75, strlen(v->base75), out256);
    assert((sizeof (out256)) - 1 >= out256_len);
    assert(strlen(out256) == strlen(v->base256));
    assert(memcmp(out256, v->base256, strlen(v->base256)) == 0);
    v++;
  }
}

void
test_invalid_base75()
{
  size_t out256_len;
  uint8_t out256[base75_min_length(8)];
  out256_len = base75_to_uint8("&'[](){}", 8, out256);

  assert(out256_len == -1);
}

int
main(void)
{
  test_base75();
  test_invalid_base75();

  printf("tests passed: %d failed: %d\n", tests_passed, tests_failed);

  return !(tests_failed == 0);
}
