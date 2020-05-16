#include <errno.h>
#include <stdio.h>
#include <string.h>

#pragma once

#define enprintf(ret, ...)         \
  do {                             \
    if (!(ret < 0))                \
      break;                       \
    fprintf(stderr, __VA_ARGS__);  \
    exit(ret);                     \
  } while (0)

#define esprintf(ret, ...)                           \
  do {                                               \
    if (!(ret < 0))                                  \
      break;                                         \
    fprintf(stderr, __VA_ARGS__);                    \
    fprintf(stderr, ": %s\n", strerror(errno));      \
    exit(ret);                                       \
  } while (0)
