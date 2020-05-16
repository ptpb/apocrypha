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

typedef enum binary_state {
  READING_IDLE,
  READING_CLOSING_FILE,
  READING_CHUNK_SIZE,
  READING_CHUNK,
  WRITING_RESPONSE,
} binary_state_t;

typedef struct binary_context {
  binary_state_t state;
  uint32_t chunk_size;
  int write_fd;
  char temp_filename[7];
  EVP_MD_CTX digest;
} binary_context_t;

void *
binary_init(void)
{
  binary_context_t *context;

  context = calloc(1, (sizeof (binary_context_t)));

  context->write_fd = -1;
  context->state = READING_IDLE;

  return (void *)context;
}

#define _buf_length() (buf_size - ((uint8_t *)buf - (uint8_t *)buf_head))

#define min(a, b)               \
  ({ typeof (a) _a = (a);       \
    typeof (b) _b = (b);        \
    _a < _b ? _a : _b; })

size_t
binary_read(void *buf_head, size_t buf_size,
            void *ptr, protocol_state_t *protocol_state)
{
  void *buf;
  ssize_t ret;
  size_t write_length;
  binary_context_t *context = (binary_context_t *)ptr;

  buf = buf_head;

  while (1) {
    switch (context->state) {
    case READING_IDLE:
      strncpy(context->temp_filename, "XXXXXX", (sizeof (context->temp_filename)));
      ret = mkostemp(context->temp_filename, O_CLOEXEC);
      esprintf(ret, "mkostemp: %s", context->temp_filename);
      context->write_fd = ret;

      EVP_DigestInit_ex(&context->digest, EVP_sha256(), NULL);

      context->state = READING_CHUNK_SIZE;
      break;
    case READING_CLOSING_FILE:
      {
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_length;
        EVP_DigestFinal_ex(&context->digest, md_value, &md_length);

        char hex_digest[md_length * 2 + 1];
        hex_digest[md_length * 2 + 1] = '\0';

        for (int i = 0; i < md_length; i++) {
          snprintf(&hex_digest[i * 2], 3, "%02x", md_value[i]);
        }
        fprintf(stderr, "digest: %s -> %s\n", context->temp_filename, hex_digest);

        assert(context->write_fd > 0);
        ret = rename(context->temp_filename, hex_digest);
        esprintf(ret, "rename: %s -> %s", context->temp_filename, hex_digest);

        ret = close(context->write_fd);
        esprintf(ret, "close: %d", context->write_fd);
        context->write_fd = -1;
      }

      context->state = READING_IDLE;
      break;
    case READING_CHUNK_SIZE:
      if (_buf_length() < (sizeof (uint32_t)))
        goto handled_buf;

      context->chunk_size = ntohl(*(uint32_t *)buf);
      buf += (sizeof (uint32_t));

      if (context->chunk_size == 0) {
        fprintf(stderr, "handle_buf: end of file\n");
        context->state = READING_CLOSING_FILE;
      } else {
        //fprintf(stderr, "handle_buf: chunk with size=%d\n", context->chunk_size);
        context->state = READING_CHUNK;
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
        context->state = READING_CHUNK_SIZE;

      break;

    default:
      assert(0 && "unreachable");
      break;
    }
  }

 handled_buf:
  return (uint8_t *)buf - (uint8_t *)buf_head;
}
