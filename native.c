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
  uint8_t content_digest[EVP_MAX_MD_SIZE];
  uint32_t content_digest_length;
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

      EVP_DigestInit(&context->digest, EVP_sha256());

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
      assert(context->write_fd > 0);

      ret = close(context->write_fd);
      esprintf(ret, "close: %d", context->write_fd);
      context->write_fd = -1;

      {
        /*
        A storage digest is the hash of the hexlified content digest--the former
        is used as the on-disk filename, rather than the content digest. With a
        1-way hash function like sha256, this makes the content digest
        unrecoverable from persistent storage.

        Provided content digests are not persisted in any way, the effect is it
        is not possible to read plaintext the plaintext of files encrypted with
        the content digest from storage out of band, unless you already know the
        content digest of that plaintext.
        */
        EVP_DigestFinal(&context->digest,
                        context->content_digest, &context->content_digest_length);

        // computing the storage digest from the hexlified digest means we need
        // to compute extra round of uint8_to_hex, but it also allows for
        // odd-length prefixes and obviates the need for a hex_to_uint8
        // function.
        uint8_t content_hex_digest[context->content_digest_length * 2];
        uint8_to_hex(content_hex_digest, context->content_digest, context->content_digest_length);

        inline void
        storage_digest(void *hex_buf, size_t hex_buf_size, size_t prefix_length)
        {
          EVP_MD_CTX ctx;
          uint8_t digest[EVP_MAX_MD_SIZE];
          uint32_t digest_length;

          EVP_DigestInit(&ctx, EVP_sha256());
          content_hex_digest[prefix_length] = '\0';
          EVP_DigestUpdate(&ctx, content_hex_digest, prefix_length);
          EVP_DigestFinal(&ctx, digest, &digest_length);

          assert(hex_buf_size == digest_length * 2 + 1);
          uint8_to_hex(hex_buf, digest, digest_length);
          ((uint8_t*)hex_buf)[hex_buf_size - 1] = '\0';
        }

        uint32_t hex_buf_size = context->content_digest_length * 2 + 1;

        // Binary filenames are awkward, so translate to a base16 string
        // representation, the "hex digest"
        char storage_hex_digest[hex_buf_size];
        storage_digest(storage_hex_digest, hex_buf_size, context->content_digest_length * 2);
        ret = rename(context->temp_filename, storage_hex_digest);
        esprintf(ret, "rename: %s -> %s", context->temp_filename, storage_hex_digest);

        // prefix_length == 0 is interpreted as "do not make a prefix"
        if (context->prefix_length != 0) {
          assert(context->content_digest_length * 2 > context->prefix_length);
          char prefix_hex_digest[hex_buf_size];
          storage_digest(prefix_hex_digest, hex_buf_size, context->prefix_length);

          // storage prefixes can collide; the API contract is the most recent
          // collision wins
          ret = unlink(prefix_hex_digest);
          assert(!(ret < 0) || errno == ENOENT);

          ret = symlink(storage_hex_digest, prefix_hex_digest);
          esprintf(ret, "symlink: %s -> %s", prefix_hex_digest, storage_hex_digest);
        }

        // this stack allocation would probably get immediately overwritten over
        // anyway. meh..
        memset(content_hex_digest, '\0', context->content_digest_length * 2);
      }

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

      EVP_DigestUpdate(&context->digest, buf, write_length);

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
      if (_buf_length() < (sizeof (uint32_t)) + context->content_digest_length)
        goto handled_buf;

      *(uint32_t*)buf = htonl(context->content_digest_length);
      buf += (sizeof (uint32_t));
      memcpy(buf, context->content_digest, context->content_digest_length);
      buf += context->content_digest_length;

      // minimize the time the content digest exists in memory (e.g, without
      // this, if the client keeps the connection open indefinitely, we will
      // have the content digest in memory indefinitely).
      memset(context->content_digest, '\0', context->content_digest_length);

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
