#pragma once

void *
http_init(void);

size_t
http_read(void *buf_head, size_t buf_size, void *ptr, int *want_write);

size_t
http_write(void *buf_head, size_t buf_size, void *ptr, int *want_read);
