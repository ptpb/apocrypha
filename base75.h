#define base75_min_symbols(size) \
  ({ typeof (size) _size = (size); \
    (((_size) * 9) / 7) + 7 - (_size % 7); })

#define base75_min_length(size) \
  ({ typeof (size) _size = (size); \
    (((_size) * 7) / 9) + 9 - (_size % 9); })

#define BASE75_ENCODE_BS 7
#define BASE75_DECODE_BS 9

size_t
uint8_to_base75(const void *buf, size_t len, void *out);

ssize_t
base75_to_uint8(const void *buf, size_t len, void *out);
