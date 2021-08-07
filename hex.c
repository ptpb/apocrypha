#include <endian.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>

static char base16_symbols[16] = "0123456789abcdef";

void
uint8_to_hex(void *dst, const void *src, size_t n)
{
  size_t i;

  for (i = 0; i < n; i++) {
    *(uint8_t*)dst++ = base16_symbols[((uint8_t*)src)[i] >> 4 & 0xf];
    *(uint8_t*)dst++ = base16_symbols[((uint8_t*)src)[i] >> 0 & 0xf];
  }
}

void
uint16_to_hex(void *dst, uint16_t n)
{
  *(uint8_t*)dst++ = base16_symbols[n >> 12 & 0xf];
  *(uint8_t*)dst++ = base16_symbols[n >> 8 & 0xf];
  *(uint8_t*)dst++ = base16_symbols[n >> 4 & 0xf];
  *(uint8_t*)dst++ = base16_symbols[n >> 0 & 0xf];
}

int
uint64_to_dec(void *dst, uint64_t n)
{
  uint8_t *buf = dst;
  int i, j;
  int len;

  while (n > 0) {
    i = n % 10;
    *buf++ = base16_symbols[i];
    n /= 10;
  }
  len = buf - (uint8_t *)dst;
  buf = dst;
  for (i = 0, j = len - 1; i < j; i++, j--) {
    uint8_t temp = buf[i];
    buf[i] = buf[j];
    buf[j] = temp;
  }
  return len;
}

static uint8_t base16_chars[256] = {
  [0 ... 255] = 255,
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

int
base16_to_uint64(const void *const buf, uint64_t *num, const size_t len)
{
  uint64_t n = 0;
  size_t index = 0;
  uint8_t d;

  if (len > 16)
    // definitely too large for uint64_t
    return -1;

  while (index < len) {
    switch (d = base16_chars[((uint8_t *)buf)[len - index - 1]]) {
    case 255:
      return -1;
    default:
      n += (d << index * 4);
      break;
    }
    index++;
  }

  *num = n;

  return 0;
}
