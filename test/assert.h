#ifdef assert
#undef assert
#endif

static unsigned int tests_passed = 0;
static unsigned int tests_failed = 0;

#define assert(x)                                                   \
  do {                                                              \
    if ((x))                                                        \
      tests_passed++;                                               \
    else {                                                          \
      fprintf(stderr, "%s:%d: assert("#x")\n", __FILE__, __LINE__); \
      tests_failed++;                                               \
    }                                                               \
  } while (0)
