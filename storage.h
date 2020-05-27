#include <openssl/evp.h>

#pragma once

typedef struct storage_writer {
  int write_fd;
  char temp_filename[7];
  EVP_MD_CTX digest;
  uint8_t digest_value[EVP_MAX_MD_SIZE];
  uint32_t digest_length;
  char name[EVP_MAX_MD_SIZE * 2 + 1];
  uint32_t name_length;
} storage_writer_t;

void
storage_open_writer(storage_writer_t *storage);

ssize_t
storage_write(storage_writer_t *storage, void *buf, size_t len);

void
storage_close_writer(storage_writer_t *storage, uint8_t prefix_length);

typedef struct storage_reader {
  int read_fd;
} storage_reader_t;

int
storage_open_reader(storage_reader_t *storage, const char *name, uint32_t name_length);
