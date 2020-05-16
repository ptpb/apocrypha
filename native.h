#pragma once

void *
binary_init(void);

size_t
binary_read(void *buf_head, size_t buf_size, void *ptr, int *want_write);
