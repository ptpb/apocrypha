#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/stat.h>

#include "error.h"
#include "hex.h"
#include "storage.h"
#include "base75.h"

void
storage_open_writer(storage_writer_t *storage)
{
  int ret;

  assert(storage->write_fd == -1);

  memcpy(storage->temp_filename, "XXXXXX", (sizeof (storage->temp_filename)));
  ret = mkostemp(storage->temp_filename, O_CLOEXEC);
  esprintf(ret, "mkostemp: %s", storage->temp_filename);
  storage->write_fd = ret;

  ret = gnutls_hash_init(&storage->digest, GNUTLS_DIG_SHA256);
  enprintf(ret, "gnutls_hash_init: %s\n", gnutls_strerror(ret));
}

ssize_t
storage_write(storage_writer_t *storage, void *buf, size_t len)
{
  ssize_t ret;

  ret = gnutls_hash(storage->digest, buf, len);
  enprintf(ret, "gnutls_hash: %s\n", gnutls_strerror(ret));

  ret = write(storage->write_fd, buf, len);
  esprintf(ret, "write: %d", storage->write_fd);

  return ret;
}

static inline void
storage_hex_digest(const void *name, uint32_t name_length, char *hex_digest)
{
  gnutls_hash_hd_t digest;
  uint8_t digest_value[SHA256_LENGTH];
  int ret;

  ret = gnutls_hash_init(&digest, GNUTLS_DIG_SHA256);
  enprintf(ret, "gnutls_hash_init: %s\n", gnutls_strerror(ret));
  ret = gnutls_hash(digest, name, name_length);
  enprintf(ret, "gnutls_hash: %s\n", gnutls_strerror(ret));
  gnutls_hash_deinit(digest, digest_value);

  uint8_to_hex(hex_digest, digest_value, SHA256_LENGTH);
  hex_digest[SHA256_LENGTH * 2] = '\0';
}

void
storage_close_writer(storage_writer_t *storage, uint8_t prefix_length)
{
  int ret;

  gnutls_hash_deinit(storage->digest, storage->digest_value);

  assert(base75_min_symbols((sizeof (storage->digest_value))) <= (sizeof (storage->name)));
  size_t base75_size = uint8_to_base75(storage->digest_value, SHA256_LENGTH, storage->name);
  storage->name[base75_size] = '\0';
  // a byte up to 8 bytes prior to base75_size could be zero
  char *tok = memchr(storage->name + base75_size - 8, '\0', 9);
  assert(tok != NULL);

  assert(prefix_length != 0);
  storage->name_length = prefix_length < tok - storage->name ? prefix_length : tok - storage->name;

  // fixme: explain this
  char hex_digest[SHA256_LENGTH * 2 + 1];
  storage_hex_digest(storage->name, storage->name_length, hex_digest);

  assert(storage->write_fd > 0);
  ret = rename(storage->temp_filename, hex_digest);
  fprintf(stderr, "write hash: %s\n", hex_digest);

  esprintf(ret, "rename: %s -> %s", storage->temp_filename, hex_digest);

  ret = close(storage->write_fd);
  esprintf(ret, "close: %d", storage->write_fd);
  storage->write_fd = -1;
}

int
storage_open_reader(storage_reader_t *reader, const char *name, uint32_t name_length, uint64_t first, uint64_t last)
{
  int ret;
  off_t off;

  char hex_digest[32 * 2 + 1];
  storage_hex_digest(name, name_length, hex_digest);

  fprintf(stderr, "read hash: %s\n", hex_digest);

  ret = open(hex_digest, O_RDONLY);
  if (ret < 0)
    return ret;

  assert(reader->read_fd == -1);
  reader->read_fd = ret;

  struct stat sb;
  ret = fstat(reader->read_fd, &sb);
  if (ret < 0)
    goto error;

  reader->size = sb.st_size;

  last++;
  if (first > (uint64_t)sb.st_size || first > last)
    goto error;
  if (last > (uint64_t)sb.st_size)
    last = (uint64_t)sb.st_size;

  off = lseek(reader->read_fd, first, SEEK_SET);
  if (off < 0)
    goto error;

  assert((uint64_t)off == first);

  reader->length = last - first;
  fprintf(stderr, "%zu, %zu, %zu\n", first, last, reader->length);

  return 0;
error:
  close(reader->read_fd);
  return -1;
}
