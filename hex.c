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

static uint8_t bin_chars[256] = {
  ['0'] = 0x0,
  ['1'] = 0x1,
  ['2'] = 0x2,
  ['3'] = 0x3,
  ['4'] = 0x4,
  ['5'] = 0x5,
  ['6'] = 0x6,
  ['7'] = 0x7,
  ['8'] = 0x8,
  ['9'] = 0x9,
  ['a'] = 0xa,
  ['b'] = 0xb,
  ['c'] = 0xc,
  ['d'] = 0xd,
  ['e'] = 0xe,
  ['f'] = 0xf,
};

void
uint8_to_hex(void *dst, const void *src, size_t n)
{
  size_t i;

  for (i = 0; i < n; i++) {
    *(uint8_t*)dst++ = hex_chars[((uint8_t*)src)[i] >> 4 & 0xf];
    *(uint8_t*)dst++ = hex_chars[((uint8_t*)src)[i] >> 0 & 0xf];
  }
}

void
hex_to_uint8(void *dst, const void *src, size_t n)
{
  assert(n % 2 == 0);
  uint8_t v;
  for (i = 0; i < n;) {
    *(uint8_t*)dst++ = (bin_chars[((uint8_t*)src)[i++]] << 0 |
                        bin_chars[((uint8_t*)src)[i++]] << 4);
  }
}

void
uint16_to_hex(void *dst, const void *src, size_t n)
{
  size_t i;
  uint16_t v;

  for (i = 0; i < n; i++) {
    v = htole16(((uint16_t*)src)[i]);
    *(uint8_t*)dst++ = hex_chars[v >> 12 & 0xf];
    *(uint8_t*)dst++ = hex_chars[v >> 8 & 0xf];
    *(uint8_t*)dst++ = hex_chars[v >> 4 & 0xf];
    *(uint8_t*)dst++ = hex_chars[v >> 0 & 0xf];
  }
}
