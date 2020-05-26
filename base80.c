#include <openssl/bn.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>


uint8_t base80_symbols[80] =
  "!$&()*+,-./0123456789:=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz|~";

#define INVALID_SYMBOL 255

uint8_t symbols_base80[256] = {
  [0 ... 255] = INVALID_SYMBOL,
  ['!'] = 0,  ['$'] = 1,  ['&'] = 2,  ['('] = 3,  [')'] = 4,  ['*'] = 5,  ['+'] = 6,  [','] = 7,
  ['-'] = 8,  ['.'] = 9,  ['/'] = 10, ['0'] = 11, ['1'] = 12, ['2'] = 13, ['3'] = 14, ['4'] = 15,
  ['5'] = 16, ['6'] = 17, ['7'] = 18, ['8'] = 19, ['9'] = 20, [':'] = 21, ['='] = 22, ['?'] = 23,
  ['@'] = 24, ['A'] = 25, ['B'] = 26, ['C'] = 27, ['D'] = 28, ['E'] = 29, ['F'] = 30, ['G'] = 31,
  ['H'] = 32, ['I'] = 33, ['J'] = 34, ['K'] = 35, ['L'] = 36, ['M'] = 37, ['N'] = 38, ['O'] = 39,
  ['P'] = 40, ['Q'] = 41, ['R'] = 42, ['S'] = 43, ['T'] = 44, ['U'] = 45, ['V'] = 46, ['W'] = 47,
  ['X'] = 48, ['Y'] = 49, ['Z'] = 50, ['_'] = 51, ['a'] = 52, ['b'] = 53, ['c'] = 54, ['d'] = 55,
  ['e'] = 56, ['f'] = 57, ['g'] = 58, ['h'] = 59, ['i'] = 60, ['j'] = 61, ['k'] = 62, ['l'] = 63,
  ['m'] = 64, ['n'] = 65, ['o'] = 66, ['p'] = 67, ['q'] = 68, ['r'] = 69, ['s'] = 70, ['t'] = 71,
  ['u'] = 72, ['v'] = 73, ['w'] = 74, ['x'] = 75, ['y'] = 76, ['z'] = 77, ['|'] = 78, ['~'] = 79,
};

int main2(void);

int
main(void)
{
  int ret;
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *num = BN_new();
  const BIGNUM *zero = BN_new();
  BIGNUM *remainder = BN_new();
  BIGNUM *div80 = BN_new();
  BIGNUM *quot = BN_new();
  BIGNUM *temp;

  BN_set_word(div80, 80);

  //char c[] = "The BN library performs arithmet";
  char c[] = "performs arithmet";
  char buf[32] = {0};

  memcpy(buf + 32 - (sizeof (c)) - 1, c, (sizeof (c)) - 1);


  BN_bin2bn(buf, (sizeof (buf)), num);

  char *dec = BN_bn2dec(num);
  printf("%s\n", dec);
  free(dec);

  int index = 0;
  char out[42] = {0};

  while (BN_cmp(num, zero) == 1) {
    //int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d, BN_CTX *ctx);
    assert(BN_div(quot, remainder, num, div80, ctx));
    BN_ULONG w = BN_get_word(remainder);

    char *dec = BN_bn2dec(quot);
    printf("%s %ld\n", dec, w);
    free(dec);

    assert(80 > w);
    out[index] = base80_symbols[w];
    index++;

    temp = quot;
    quot = num;
    num = temp;
  }

  printf("%s\n", out);

  BN_clear_free(num);
  BN_free((BIGNUM*)zero);
  BN_clear_free(div80);
  BN_clear_free(remainder);
  BN_CTX_free(ctx);

  main2();

  return 0;

}

int
main2(void)
{
  //char buf[] = "qtt|Mlp&ruG@(BWyr:u+eWssG,$YxIsVHp)r1Gkr&";
  char buf[] = "U9ZegR,E*B2m@VoRcGH";
  uint8_t w;

  char out[33] = {0};

  BIGNUM *num = BN_new();
  BIGNUM *mul80 = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  BN_set_word(mul80, 80);

  int index = (sizeof (buf)) - 1;

  while (index > 0) {
    w = symbols_base80[buf[--index]];
    assert(w != INVALID_SYMBOL);
    BN_mul(num, num, mul80, ctx);
    BN_add_word(num, w);
    char *dec = BN_bn2dec(num);
    printf("%s %d\n", dec, w);
    free(dec);
  }

  printf("%d\n", BN_num_bytes(num));
  assert((sizeof (out)) - 1 >= BN_num_bytes(num));
  BN_bn2bin(num, out);
  printf("%s\n", out);

  return 0;
}
