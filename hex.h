#pragma once

void
uint8_to_hex(void *dst, const void *src, size_t n);

int
uint64_to_dec(void *dst, uint64_t n);

void
uint16_to_hex(void *dst, uint16_t n);

int
base16_to_uint64(const void *const buf, uint64_t *num, const size_t len);
