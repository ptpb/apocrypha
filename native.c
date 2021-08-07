#include <assert.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include "error.h"
#include "native.h"
#include "protocol.h"
#include "storage.h"

typedef enum parser_state {
  READING_IDLE,
  READING_PREFIX_LENGTH,
  READING_CLOSING_FILE,
  READING_CHUNK_SIZE,
  READING_CHUNK,
} parser_state_t;

typedef enum emitter_state {
  WRITING_DIGEST,
} emitter_state_t;

typedef struct binary_context {
  parser_state_t parser_state;
  emitter_state_t emitter_state;
  uint32_t chunk_size;
  storage_writer_t storage;
  uint8_t prefix_length;
} binary_context_t;

void *
binary_init(void)
{
  binary_context_t *context;

  context = calloc(1, (sizeof (binary_context_t)));

  context->storage.write_fd = -1;
  context->parser_state = READING_IDLE;
  context->emitter_state = WRITING_DIGEST;

  return (void *)context;
}

#define _buf_length() (buf_size - ((uint8_t *)buf - (uint8_t *)buf_head))

#define min(a, b)               \
  ({ typeof (a) _a = (a);       \
    typeof (b) _b = (b);        \
    _a < _b ? _a : _b; })

size_t
binary_read(void *const buf_head, size_t buf_size,
            void *ptr, protocol_state_t *protocol_state)
{
  void *buf;
  ssize_t ret;
  size_t write_length;
  binary_context_t *context = (binary_context_t *)ptr;

  buf = buf_head;

  while (1) {
    switch (context->parser_state) {
    case READING_IDLE:
      storage_open_writer(&context->storage);
      context->parser_state = READING_PREFIX_LENGTH;
      break;
    case READING_PREFIX_LENGTH:
      if (_buf_length() < (sizeof (uint8_t)))
        goto handled_buf;

      context->prefix_length = *(uint8_t *)buf++;

      if (context->prefix_length < 3 || context->prefix_length > 42) {
        fprintf(stderr, "invalid prefix length: %d", context->prefix_length);
        *protocol_state = PROTOCOL_SHUTDOWN;
        goto handled_buf;
      }

      context->parser_state = READING_CHUNK_SIZE;
      break;
    case READING_CLOSING_FILE:
      storage_close_writer(&context->storage, context->prefix_length);
      context->parser_state = READING_IDLE;
      *protocol_state = PROTOCOL_WRITING;
      goto handled_buf;
      break;
    case READING_CHUNK_SIZE:
      if (_buf_length() < (sizeof (uint32_t)))
        goto handled_buf;

      context->chunk_size = ntohl(*(uint32_t *)buf);
      buf += (sizeof (uint32_t));

      if (context->chunk_size == 0) {
        fprintf(stderr, "handle_buf: end of file\n");
        context->parser_state = READING_CLOSING_FILE;
      } else {
        //fprintf(stderr, "handle_buf: chunk with size=%d\n", context->chunk_size);
        context->parser_state = READING_CHUNK;
      }
      break;
    case READING_CHUNK:
      if (!((write_length = min(_buf_length(), context->chunk_size)) > 0))
        goto handled_buf;

      ret = storage_write(&context->storage, buf, write_length);

      context->chunk_size -= ret;
      buf += ret;

      if (context->chunk_size == 0)
        context->parser_state = READING_CHUNK_SIZE;

      break;
    }
  }

 handled_buf:
  return (uint8_t *)buf - (uint8_t *)buf_head;
}

size_t
binary_write(void *const buf_head, size_t buf_size,
             void *ptr, protocol_state_t *protocol_state)
{
  binary_context_t *context = (binary_context_t *)ptr;
  void *buf = buf_head;

  fprintf(stderr, "binary writing\n");

  while (1) {
    switch (context->emitter_state) {
    case WRITING_DIGEST:
      if (_buf_length() < (sizeof (uint32_t)) + context->storage.name_length)
        goto handled_buf;

      *(uint32_t*)buf = htonl(SHA256_LENGTH);
      buf += (sizeof (uint32_t));
      memcpy(buf, context->storage.name, context->storage.name_length);
      buf += context->storage.name_length;

      context->emitter_state = WRITING_DIGEST;
      *protocol_state = PROTOCOL_READING;

      goto handled_buf;
      break;
    }
  }

 handled_buf:
  return (uint8_t *)buf - (uint8_t *)buf_head;
}

void
binary_terminate(void *ptr)
{
  binary_context_t *context = (binary_context_t *)ptr;

  if (context->storage.write_fd != -1) {
    unlink(context->storage.temp_filename);
    close(context->storage.write_fd);
  }

  free(context);
}
