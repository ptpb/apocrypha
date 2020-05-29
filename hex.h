#pragma once

void
uint8_to_hex(void *dst, const void *src, size_t n);

void
uint16_to_hex(void *dst, const void *src, size_t n);

int
base16_to_uint64(const void *const buf, uint64_t *num, const size_t len);
