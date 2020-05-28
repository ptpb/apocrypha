#include <assert.h>
#include <string.h>
#include <unistd.h>

#include <sys/fcntl.h>
#include <sys/stat.h>
#include <openssl/evp.h>

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

  EVP_DigestInit(&storage->digest, EVP_sha256());
}

ssize_t
storage_write(storage_writer_t *storage, void *buf, size_t len)
{
  ssize_t ret;

  ret = EVP_DigestUpdate(&storage->digest, buf, len);
  assert(ret == 1 && "EVP_DigestUpdate");

  ret = write(storage->write_fd, buf, len);
  esprintf(ret, "write: %d", storage->write_fd);

  return ret;
}

static inline void
storage_hex_digest(const void *name, uint32_t name_length, char *hex_digest)
{
  EVP_MD_CTX digest;
  uint8_t digest_value[EVP_MAX_MD_SIZE];
  uint32_t digest_length;

  EVP_DigestInit(&digest, EVP_sha256());
  EVP_DigestUpdate(&digest, name, name_length);
  EVP_DigestFinal(&digest, digest_value, &digest_length);

  uint8_to_hex(hex_digest, digest_value, digest_length);
  hex_digest[digest_length * 2] = '\0';
}

void
storage_close_writer(storage_writer_t *storage, uint8_t prefix_length)
{
  int ret;

  EVP_DigestFinal(&storage->digest, storage->digest_value, &storage->digest_length);

  assert(base75_min_symbols((sizeof (storage->digest_value))) <= (sizeof (storage->name)));
  size_t base75_size = uint8_to_base75(storage->digest_value, storage->digest_length, storage->name);
  storage->name[base75_size] = '\0';
  // a byte up to 8 bytes prior to base75_size could be zero
  char *tok = memchr(storage->name + base75_size - 8, '\0', 9);
  assert(tok != NULL);

  assert(prefix_length != 0);
  storage->name_length = prefix_length < tok - storage->name ? prefix_length : tok - storage->name;

  // fixme: explain this
  char hex_digest[storage->digest_length * 2 + 1];
  storage_hex_digest(storage->name, storage->name_length, hex_digest);

  assert(storage->write_fd > 0);
  ret = rename(storage->temp_filename, hex_digest);
  esprintf(ret, "rename: %s -> %s", storage->temp_filename, hex_digest);
  fprintf(stderr, "%s\n", hex_digest);

  ret = close(storage->write_fd);
  esprintf(ret, "close: %d", storage->write_fd);
  storage->write_fd = -1;
}

int
storage_open_reader(storage_reader_t *reader, const char *name, uint32_t name_length)
{
  int ret;

  char hex_digest[32 * 2 + 1];
  storage_hex_digest(name, name_length, hex_digest);

  ret = open(hex_digest, O_RDONLY);
  if (ret < 0)
    return ret;

  assert(reader->read_fd == -1);
  reader->read_fd = ret;

  struct stat sb;
  ret = fstat(reader->read_fd, &sb);
  if (ret < 0)
    return ret;

  reader->size = sb.st_size;

  return 0;
}
