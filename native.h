#pragma once

#include "protocol.h"

void *
binary_init(void);

size_t
binary_read(void *buf_head, size_t buf_size,
            void *ptr, protocol_state_t *protocol_state);

size_t
binary_write(void *buf_head, size_t buf_size,
             void *ptr, protocol_state_t *protocol_state);

void
binary_terminate(void *ptr);
