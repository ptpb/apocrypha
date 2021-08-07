#include <sys/statfs.h>
#include <stdint.h>

#include "error.h"
#include "hex.h"

typedef struct field {
  char *s;
  uint64_t value;
} field_t;

size_t
stats_render(void *buf)
{
  int ret;
  struct statfs stat;
  uint8_t *bufi = buf;

  ret = statfs(".", &stat);
  esprintf(ret, "statfs");

  field_t fields[] = {
    {"total bytes: ", stat.f_bsize * stat.f_blocks},
    {"avail bytes: ", stat.f_bsize * stat.f_bavail},
    {"total inodes: ", stat.f_files},
    {"free inodes: ", stat.f_ffree},
  };
  for (unsigned int i = 0; i < (sizeof (fields)) / (sizeof (field_t)); i++) {
    bufi = (uint8_t*)stpcpy((char*)bufi, fields[i].s);
    bufi += uint64_to_dec(bufi, fields[i].value);
    *bufi++ = '\n';
  }

  return bufi - (uint8_t*)buf;
}
