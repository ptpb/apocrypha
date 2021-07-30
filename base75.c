#include <assert.h>
#include <endian.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "base75.h"

uint8_t base75_symbols[75] =
  // ascii ordinal sort order
  "!$+,-[]0123456789:=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~";

#define INVALID_SYMBOL 255

uint8_t symbols_base75[256] = {
  [0 ... 255] = INVALID_SYMBOL,
  ['!'] = 0,  ['$'] = 1,  ['+'] = 2,  [','] = 3,  ['-'] = 4,
  ['['] = 5,  [']'] = 6,  ['0'] = 7,  ['1'] = 8,  ['2'] = 9,
  ['3'] = 10, ['4'] = 11, ['5'] = 12, ['6'] = 13, ['7'] = 14,
  ['8'] = 15, ['9'] = 16, [':'] = 17, ['='] = 18, ['?'] = 19,
  ['@'] = 20, ['A'] = 21, ['B'] = 22, ['C'] = 23, ['D'] = 24,
  ['E'] = 25, ['F'] = 26, ['G'] = 27, ['H'] = 28, ['I'] = 29,
  ['J'] = 30, ['K'] = 31, ['L'] = 32, ['M'] = 33, ['N'] = 34,
  ['O'] = 35, ['P'] = 36, ['Q'] = 37, ['R'] = 38, ['S'] = 39,
  ['T'] = 40, ['U'] = 41, ['V'] = 42, ['W'] = 43, ['X'] = 44,
  ['Y'] = 45, ['Z'] = 46, ['_'] = 47, ['a'] = 48, ['b'] = 49,
  ['c'] = 50, ['d'] = 51, ['e'] = 52, ['f'] = 53, ['g'] = 54,
  ['h'] = 55, ['i'] = 56, ['j'] = 57, ['k'] = 58, ['l'] = 59,
  ['m'] = 60, ['n'] = 61, ['o'] = 62, ['p'] = 63, ['q'] = 64,
  ['r'] = 65, ['s'] = 66, ['t'] = 67, ['u'] = 68, ['v'] = 69,
  ['w'] = 70, ['x'] = 71, ['y'] = 72, ['z'] = 73, ['~'] = 74,
};

size_t
uint8_to_base75(const void *buf, size_t len, void *out)
{
  uint8_t *outi = out;
  uint64_t num;
  size_t block_len;

  while (len > 0) {
    block_len = len < BASE75_ENCODE_BS ? len : BASE75_ENCODE_BS;
    num = 0;
    memcpy(&num, buf, block_len);
    len -= block_len;
    buf += block_len;
    num = le64toh(num);
    assert(num < 72057594037927936);

    while (num > 0) {
      *outi++ = base75_symbols[num % 75];
      num /= 75;
    }
  }

  return outi - (uint8_t *)out;
}

ssize_t
base75_to_uint8(const void *buf, size_t len, void *out)
{
  const uint8_t *bufi = buf;
  uint8_t *outi = out;

  while (len > 0) {
    uint64_t num = 0;
    size_t block_len = len < BASE75_DECODE_BS ? len : BASE75_DECODE_BS;
    size_t block_index = block_len;

    while ((block_index--) > 0) {
      num *= 75;
      uint8_t v = symbols_base75[*(bufi + block_index)];
      if (v == INVALID_SYMBOL)
        return -1;
      num += v;
    }

    assert(num < 72057594037927936);
    num = htole64(num);
    memcpy(outi, &num, BASE75_ENCODE_BS);

    bufi += block_len;
    len -= block_len;
    outi += BASE75_ENCODE_BS;
  }

  return outi - (uint8_t *)out;
}
