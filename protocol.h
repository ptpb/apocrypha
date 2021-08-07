#pragma once

typedef enum protocol_state {
  PROTOCOL_HANDSHAKE = 0,
  PROTOCOL_READING,
  PROTOCOL_WRITING,
  PROTOCOL_SHUTDOWN,
} protocol_state_t;
