#include <assert.h>
#include <string.h>
#include <unistd.h>

#include <sys/fcntl.h>
#include <openssl/evp.h>

#include "error.h"
#include "hex.h"
#include "storage.h"

void
storage_open_writer(storage_context_t *storage)
{
  int ret;

  assert(storage->write_fd == -1);

  memcpy(storage->temp_filename, "XXXXXX", (sizeof (storage->temp_filename)));
  ret = mkostemp(storage->temp_filename, O_CLOEXEC);
  esprintf(ret, "mkostemp: %s", storage->temp_filename);
  storage->write_fd = ret;

  EVP_DigestInit_ex(&storage->digest, EVP_sha256(), NULL);
}

ssize_t
storage_write(storage_context_t *storage, void *buf, size_t len)
{
  ssize_t ret;

  ret = EVP_DigestUpdate(&storage->digest, buf, len);
  assert(ret == 1 && "EVP_DigestUpdate");

  ret = write(storage->write_fd, buf, len);
  esprintf(ret, "write: %d", storage->write_fd);

  return ret;
}

void
storage_close_writer(storage_context_t *storage, uint8_t prefix_length)
{
  int ret;

  EVP_DigestFinal_ex(&storage->digest, storage->digest_value, &storage->digest_length);

  storage->hex_digest[storage->digest_length * 2] = '\0';
  uint8_to_hex(storage->hex_digest, storage->digest_value, storage->digest_length);

  assert(storage->write_fd > 0);
  ret = rename(storage->temp_filename, storage->hex_digest);
  esprintf(ret, "rename: %s -> %s", storage->temp_filename, storage->hex_digest);

  assert(storage->digest_length * 2 > prefix_length);

  if (prefix_length != 0) {
    char prefix[prefix_length + 1];
    prefix[prefix_length] = '\0';
    memcpy(prefix, storage->hex_digest, prefix_length);

    ret = unlink(prefix);
    assert(!(ret < 0) || errno == ENOENT);

    ret = symlink(storage->hex_digest, prefix);
    esprintf(ret, "symlink: %s -> %s", prefix, storage->hex_digest);
  }

  ret = close(storage->write_fd);
  esprintf(ret, "close: %d", storage->write_fd);
  storage->write_fd = -1;
}
