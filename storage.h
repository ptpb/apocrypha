#include <gnutls/crypto.h>

#pragma once

#define SHA256_LENGTH 32

typedef struct storage_writer {
  int write_fd;
  char temp_filename[7];
  gnutls_hash_hd_t digest;
  uint8_t digest_value[SHA256_LENGTH];
  char name[SHA256_LENGTH * 2 + 1];
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
  size_t size;
  size_t length;
  size_t read_bytes;
} storage_reader_t;

int
storage_open_reader(storage_reader_t *storage, const char *name, uint32_t name_length, uint64_t first, uint64_t last);
