void
normalize_ascii_case(void *const buf, const size_t len);

void *
mem_nows(void *const buf, const size_t len);

void *
mem_rnows(void *const buf, const size_t len);

int
base10_to_uint64(const void *const buf, uint64_t *num, const size_t len);

size_t
uint64_to_base10(void *buf, uint64_t num, const size_t len);
