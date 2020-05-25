#include <openssl/evp.h>

#pragma once

typedef struct storage_context {
  int write_fd;
  char temp_filename[7];
  EVP_MD_CTX digest;
  uint8_t digest_value[EVP_MAX_MD_SIZE];
  uint32_t digest_length;
  char hex_digest[EVP_MAX_MD_SIZE * 2 + 1];
} storage_context_t;

void
storage_open_writer(storage_context_t *storage);

ssize_t
storage_write(storage_context_t *storage, void *buf, size_t len);

void
storage_close_writer(storage_context_t *storage, uint8_t prefix_length);
