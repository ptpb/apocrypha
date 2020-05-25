#include <stdint.h>
#include <stddef.h>
#include <assert.h>

/*
rfc7320 defines "token" as:

   token          = 1*tchar
   tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
                    / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
                    / DIGIT / ALPHA
                    ; any VCHAR, except delimiters

For "case-insensitive" fields, we only care about the 52 characters in the ALPHA
set. This conversion is "locale"-independent, so using bloated stdlib functions
like tolower is not a correct implementation.
*/

static uint8_t alpha_normal[256] = {
  // s = "  ['{}'] = '{}',"
  // for u, l in zip(string.ascii_uppercase, string.ascii_lowercase):
  //   print(s.format(u, l))
  ['A'] = 'a',
  ['B'] = 'b',
  ['C'] = 'c',
  ['D'] = 'd',
  ['E'] = 'e',
  ['F'] = 'f',
  ['G'] = 'g',
  ['H'] = 'h',
  ['I'] = 'i',
  ['J'] = 'j',
  ['K'] = 'k',
  ['L'] = 'l',
  ['M'] = 'm',
  ['N'] = 'n',
  ['O'] = 'o',
  ['P'] = 'p',
  ['Q'] = 'q',
  ['R'] = 'r',
  ['S'] = 's',
  ['T'] = 't',
  ['U'] = 'u',
  ['V'] = 'v',
  ['W'] = 'w',
  ['X'] = 'x',
  ['Y'] = 'y',
  ['Z'] = 'z',
};

void
normalize_ascii_case(void *const buf, const size_t len)
{
  uint8_t *bufi;
  uint8_t normal;
  bufi = buf;

  while (bufi < (uint8_t *)buf + len) {
    switch ((normal = alpha_normal[*bufi])) {
    case '\0':
      break;
    default:
      *bufi = normal;
      break;
    }
    bufi++;
  }
}

/*
Forward and reverse search for

     OWS            = *( SP / HTAB )
*/

void *
mem_nows(void *const buf, const size_t len)
{
  uint8_t *bufi;

  bufi = buf;

  while (bufi < (uint8_t *)buf + len) {
    switch (*bufi++) {
    case ' ':
    case '\t':
      break;
    default:
      return bufi - 1;
      break;
    }
  }

  assert(bufi == (uint8_t *)buf + len);
  return bufi;
}

void *
mem_rnows(void *const buf, const size_t len)
{
  uint8_t *bufi;

  bufi = (uint8_t *)buf + len;

  while (bufi > (uint8_t *)buf) {
    switch (*(--bufi)) {
    case ' ':
    case '\t':
      break;
    default:
      return bufi + 1;
      break;
    }
  }

  assert(bufi == (uint8_t *)buf);
  return bufi;
}

static uint8_t decimal_chars[256] = {
  // s = "  ['{}'] = {},"
  // for i in string.digits:
  //   print(s.format(i, i))
  [0 ... 255] = 255,
  ['0'] = 0,
  ['1'] = 1,
  ['2'] = 2,
  ['3'] = 3,
  ['4'] = 4,
  ['5'] = 5,
  ['6'] = 6,
  ['7'] = 7,
  ['8'] = 8,
  ['9'] = 9,
};

#define MAX_POW 20

static uint64_t _pow10[MAX_POW] = {
  1E00, 1E01, 1E02, 1E03, 1E04, 1E05, 1E06, 1E07, 1E08, 1E09,
  1E10, 1E11, 1E12, 1E13, 1E14, 1E15, 1E16, 1E17, 1E18, 1E19,
};

int
mem_decimal_uint64(void *const buf, const size_t len, uint64_t *value)
{
  // this function has incorrect behavior for values between
  // 2^64 and 10^20
  uint64_t v = 0;
  size_t index = 0;
  uint8_t d;

  if (len > MAX_POW)
    // definitely too large for uint64_t
    return -1;

  while (index < len) {
    switch (d = decimal_chars[((uint8_t *)buf)[len - index - 1]]) {
    case 255:
      return -1;
    default:
      v += d * _pow10[index];
      break;
    }
    index++;
  }

  *value = v;

  return 0;
}
