#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/fcntl.h>

#include <openssl/evp.h>

#include "error.h"
#include "native.h"
#include "protocol.h"
#include "hex.h"

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
  uint8_t prefix_length;
  int write_fd;
  char temp_filename[7];
  EVP_MD_CTX digest;
  uint8_t digest_value[EVP_MAX_MD_SIZE];
  uint32_t digest_length;
} binary_context_t;

void *
binary_init(void)
{
  binary_context_t *context;

  context = calloc(1, (sizeof (binary_context_t)));

  context->write_fd = -1;
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
      memcpy(context->temp_filename, "XXXXXX", (sizeof (context->temp_filename)));
      ret = mkostemp(context->temp_filename, O_CLOEXEC);
      esprintf(ret, "mkostemp: %s", context->temp_filename);
      context->write_fd = ret;

      EVP_DigestInit_ex(&context->digest, EVP_sha256(), NULL);

      context->parser_state = READING_PREFIX_LENGTH;
      break;
    case READING_PREFIX_LENGTH:
      if (_buf_length() < (sizeof (uint8_t)))
        goto handled_buf;

      context->prefix_length = *(uint8_t *)buf++;

      if (context->prefix_length != 0 &&
          (context->prefix_length < 3 || context->prefix_length > 63)) {
        fprintf(stderr, "invalid prefix length: %d", context->prefix_length);
        *protocol_state = PROTOCOL_SHUTDOWN;
        goto handled_buf;
      }

      context->parser_state = READING_CHUNK_SIZE;
      break;
    case READING_CLOSING_FILE:
      {
        EVP_DigestFinal_ex(&context->digest, context->digest_value, &context->digest_length);

        char hex_digest[context->digest_length * 2 + 1];
        hex_digest[context->digest_length * 2] = '\0';
        uint8_to_hex(hex_digest, context->digest_value, context->digest_length);

        assert(context->write_fd > 0);
        ret = rename(context->temp_filename, hex_digest);
        esprintf(ret, "rename: %s -> %s", context->temp_filename, hex_digest);

        assert(context->digest_length * 2 > context->prefix_length);
        if (context->prefix_length != 0) {
          char prefix[context->prefix_length + 1];
          prefix[context->prefix_length] = '\0';
          memcpy(prefix, hex_digest, context->prefix_length);
          ret = unlink(prefix);
          assert(!(ret < 0) || errno == ENOENT);
          ret = symlink(hex_digest, prefix);
          esprintf(ret, "symlink: %s -> %s", prefix, hex_digest);
        }

        ret = close(context->write_fd);
        esprintf(ret, "close: %d", context->write_fd);
        context->write_fd = -1;
      }

      context->parser_state = READING_IDLE;
      *protocol_state = PROTOCOL_WRITING;
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

      ret = EVP_DigestUpdate(&context->digest, buf, write_length);
      assert(ret == 1 && "EVP_DigestUpdate");

      ret = write(context->write_fd, buf, write_length);
      esprintf(ret, "write: %d", context->write_fd);

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
      if (_buf_length() < (sizeof (uint32_t)) + context->digest_length)
        goto handled_buf;

      *(uint32_t*)buf = htonl(context->digest_length);
      buf += (sizeof (uint32_t));
      memcpy(buf, context->digest_value, context->digest_length);
      buf += context->digest_length;

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

  if (context->write_fd != -1) {
    unlink(context->temp_filename);
    close(context->write_fd);
  }

  free(context);
}
