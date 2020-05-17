#include <endian.h>
#include <stdint.h>
#include <stddef.h>

static char hex_chars[] = {
  [0x0] = '0',
  [0x1] = '1',
  [0x2] = '2',
  [0x3] = '3',
  [0x4] = '4',
  [0x5] = '5',
  [0x6] = '6',
  [0x7] = '7',
  [0x8] = '8',
  [0x9] = '9',
  [0xa] = 'a',
  [0xb] = 'b',
  [0xc] = 'c',
  [0xd] = 'd',
  [0xe] = 'e',
  [0xf] = 'f',
};

void
uint8_to_hex(void *dst, const void *src, size_t n)
{
  ptrdiff_t i;

  for (i = 0; i < n; i++) {
    *(uint8_t*)dst++ = hex_chars[((uint8_t*)src)[i] >> 4 & 0xf];
    *(uint8_t*)dst++ = hex_chars[((uint8_t*)src)[i] >> 0 & 0xf];
  }
}

void
uint16_to_hex(void *dst, const void *src, size_t n)
{
  ptrdiff_t i;
  uint16_t v;

  for (i = 0; i < n; i++) {
    v = htole16(((uint16_t*)src)[i]);
    *(uint8_t*)dst++ = hex_chars[v >> 12 & 0xf];
    *(uint8_t*)dst++ = hex_chars[v >> 8 & 0xf];
    *(uint8_t*)dst++ = hex_chars[v >> 4 & 0xf];
    *(uint8_t*)dst++ = hex_chars[v >> 0 & 0xf];
  }
}
