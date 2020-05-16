#pragma once

typedef enum protocol_state {
  PROTOCOL_READING = 0,
  PROTOCOL_WRITING,
  PROTOCOL_SHUTDOWN,
} protocol_state_t;
