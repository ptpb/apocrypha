#pragma once

#include "protocol.h"

void *
http_init(void);

size_t
http_read(void *buf_head, size_t buf_size,
          void *ptr, protocol_state_t *protocol_state);

size_t
http_write(void *buf_head, size_t buf_size,
           void *ptr, protocol_state_t *protocol_state);

void
http_terminate(void *ptr);
