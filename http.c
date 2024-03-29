#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "error.h"
#include "http.h"
#include "protocol.h"
#include "mime_types.h"
#include "hex.h"
#include "token.h"
#include "storage.h"
#include "stats.h"

typedef enum parser_terminator {
  INVALID_TERMINATOR = 0,
  SPACE,
  CRLF,
  COLON,
  TERMINATOR_LAST,
} parser_terminator_t;

typedef enum parser_state {
  PARSER_INVALID = 0,
  PARSING_REQUEST_METHOD,
  PARSING_REQUEST_URI,
  PARSING_REQUEST_VERSION,
  PARSING_HEADER_NAME_OR_BODY,
  PARSING_HEADER_VALUE,
  PARSING_BODY,
  PARSER_STATE_LAST,
} parser_state_t;

typedef enum parser_storage_state {
  PARSER_STORAGE_OPENING = 0,
  PARSER_STORAGE_WRITING,
  PARSER_STORAGE_CLOSING,
} parser_storage_state_t;

typedef struct parser_transition {
  parser_state_t next_state;
} parser_transition_t;

static parser_transition_t
transitions[PARSER_STATE_LAST][TERMINATOR_LAST] = {
  [PARSING_REQUEST_METHOD] = {
    [SPACE] = {PARSING_REQUEST_URI},
  },
  [PARSING_REQUEST_URI] = {
    [SPACE] = {PARSING_REQUEST_VERSION},
  },
  [PARSING_REQUEST_VERSION] = {
    [CRLF] = {PARSING_HEADER_NAME_OR_BODY},
  },
  [PARSING_HEADER_NAME_OR_BODY] = {
    [CRLF] = {PARSING_BODY},
    [COLON] = {PARSING_HEADER_VALUE},
  },
  [PARSING_HEADER_VALUE] = {
    [CRLF] = {PARSING_HEADER_NAME_OR_BODY},
  },
};

typedef enum method {
  METHOD_INVALID = 0,
  METHOD_GET,
  METHOD_POST,
  METHOD_OPTIONS,
  METHOD_HEAD,
  METHOD_LAST
} method_t;

typedef enum status_code {
  STATUS_UNSET = 0,
  STATUS_OK,
  STATUS_NO_CONTENT,
  STATUS_PARTIAL_CONTENT,
  STATUS_BAD_REQUEST,
  STATUS_NOT_FOUND,
  STATUS_CODE_LAST
} status_code_t;

typedef enum header {
  HEADER_INVALID = 0,
  HEADER_CONTENT_LENGTH,
  HEADER_CONTENT_TYPE,
  HEADER_CONTENT_RANGE,
  HEADER_TRANSFER_ENCODING,
  HEADER_ACAO,
  HEADER_ACAH,
  HEADER_ACAM,
  HEADER_ACCEPT_RANGES,
  HEADER_RANGE,
  HEADER_LAST,
} header_t;

typedef enum length_mode {
  LENGTH_MODE_NONE = 0,
  LENGTH_MODE_FIXED,
  LENGTH_MODE_CHUNKED,
} length_mode_t;

typedef enum cors_mode {
  CORS_NONE = 0,
  CORS_PREFLIGHT_COMPLETE,
} cors_mode_t;

typedef enum emitter_state {
  EMITTER_INVALID = 0,
  EMITTER_RESOLVE_URI,
  EMITTING_STATUS_LINE,
  EMITTING_HEADERS,
  EMITTING_LAST_HEADER,
  EMITTING_BODY,
  EMITTING_CHUNKED_EOF,
  EMITTER_STATE_LAST,
} emitter_state_t;

#define BAD 0
#define OK 1

static emitter_state_t emitter_transitions[EMITTER_STATE_LAST] = {
  [EMITTER_RESOLVE_URI] = EMITTING_STATUS_LINE,
  [EMITTING_STATUS_LINE] = EMITTING_HEADERS,
  [EMITTING_HEADERS] = EMITTING_LAST_HEADER,
  [EMITTING_LAST_HEADER] = EMITTING_BODY,
  [EMITTING_BODY] = EMITTING_CHUNKED_EOF,
  [EMITTING_CHUNKED_EOF] = EMITTER_RESOLVE_URI,
};

#define STATUS_CODE_SIZE 3

static char
protocol_code[STATUS_CODE_LAST][STATUS_CODE_SIZE] = {
  [STATUS_OK] = "200",
  [STATUS_NO_CONTENT] = "204",
  [STATUS_PARTIAL_CONTENT] = "206",
  [STATUS_BAD_REQUEST] = "400",
  [STATUS_NOT_FOUND] = "404",
};

static char http_version[] = "HTTP/1.1";
#define HTTP_VERSION_SIZE ((sizeof (http_version)) - 1)

typedef struct header_string {
  void *buf;
  unsigned int length;
} header_string_t;

static header_string_t header_strings[HEADER_LAST] = {
  [HEADER_TRANSFER_ENCODING] = {"transfer-encoding: chunked", 26},
  [HEADER_ACAO] = {"access-control-allow-origin: *", 30},
  [HEADER_ACAH] = {"access-control-allow-headers: *", 31},
  [HEADER_ACAM] = {"access-control-allow-methods: *", 31},
  [HEADER_ACCEPT_RANGES] = {"accept-ranges: bytes", 20},
  [HEADER_CONTENT_TYPE] = {"content-type: ", 14},
  [HEADER_CONTENT_LENGTH] = {"content-length: ", 16},
  [HEADER_CONTENT_RANGE] = {"content-range: bytes ", 21},
};

static header_t method_headers[METHOD_LAST][6] = {
  [METHOD_GET] = {HEADER_TRANSFER_ENCODING, HEADER_CONTENT_TYPE, HEADER_CONTENT_LENGTH, HEADER_ACCEPT_RANGES, HEADER_CONTENT_RANGE, HEADER_INVALID},
  [METHOD_HEAD] = {HEADER_TRANSFER_ENCODING, HEADER_ACCEPT_RANGES, HEADER_INVALID},
  [METHOD_POST] = {HEADER_TRANSFER_ENCODING, HEADER_ACAO, HEADER_ACAH, HEADER_ACAM, HEADER_INVALID},
  [METHOD_OPTIONS] = {HEADER_ACAO, HEADER_ACAH, HEADER_ACAM, HEADER_INVALID},
};

#define STATUS_LINE_LENGTH (HTTP_VERSION_SIZE + 1 + STATUS_CODE_SIZE + 3)

#define MAX_URI_LENGTH 127
#define QUALIFIED_URI_LENGTH 64

typedef enum content_mode {
  CONTENT_MODE_INVALID = 0,
  CONTENT_MODE_STATS,
  CONTENT_MODE_STORAGE
} content_mode_t;

typedef struct http_context {
  struct {
    emitter_state_t state;
    uint8_t header_index;
    storage_reader_t storage;
    length_mode_t length_mode;
    content_mode_t content_mode;
  } emitter;
  struct {
    parser_state_t state;
    storage_writer_t storage;
    parser_storage_state_t storage_state;
    length_mode_t length_mode;
  } parser;
  method_t method;
  header_t current_header;
  cors_mode_t cors_mode;
  union {
    struct {
      uint64_t length;
      uint64_t read;
    } fixed;
    struct {
      uint64_t length;
      uint64_t read;
    } chunked;
  };
  struct {
    uint64_t first;
    uint64_t last;
  } range;
  char uri[MAX_URI_LENGTH + 1];
  uint8_t uri_length;
  //
  const char *mime_type;
  status_code_t status_code;
  //
} http_context_t;

static void
http_context_init(http_context_t *context)
{
  context->emitter.state = EMITTER_RESOLVE_URI;
  context->parser.state = PARSING_REQUEST_METHOD;
  context->parser.storage_state = PARSER_STORAGE_OPENING;
  context->current_header = HEADER_INVALID;

  context->parser.length_mode = LENGTH_MODE_NONE;
  context->emitter.length_mode = LENGTH_MODE_CHUNKED;

  // clobbering read_fd here assumes emitter never has a recoverable
  // failure. This is currently true.
  context->parser.storage.write_fd = -1;
  context->emitter.storage.read_fd = -1;
  context->emitter.header_index = 0;
}

void *
http_init(void)
{
  http_context_t *context = calloc(1, (sizeof (http_context_t)));
  http_context_init(context);
  return context;
}

#define parser_stop(_status_code, _protocol_state)          \
  do {                                                      \
    http_context_init(context);                             \
    context->status_code =                                  \
      context->status_code == STATUS_UNSET                  \
      ? _status_code : context->status_code;                \
    *protocol_state = _protocol_state;                      \
    goto handled_buf;                                       \
  } while (0)

typedef struct header_entry {
  uint8_t *string;
  uint8_t length;
  header_t header;
} header_entry_t;

static header_entry_t string_headers[] = {
  {(uint8_t *)"content-length", 14, HEADER_CONTENT_LENGTH},
  {(uint8_t *)"transfer-encoding", 17, HEADER_TRANSFER_ENCODING},
  {(uint8_t *)"range", 5, HEADER_RANGE},
};

header_t
parse_header_name(void *buf, size_t len)
{
  size_t i;
  header_entry_t *entry;
  normalize_ascii_case(buf, len);

  for (i = 0; i < (sizeof (string_headers)) / (sizeof (header_entry_t)); i++) {
    entry = string_headers + i;
    if (entry->length == len && memcmp(entry->string, buf, len) == 0)
      return entry->header;
  }
  return HEADER_INVALID;
}

#define min(a, b)               \
  ({ typeof (a) _a = (a);       \
    typeof (b) _b = (b);        \
    _a < _b ? _a : _b; })

static size_t
handle_body_storage(storage_writer_t *storage,
                    parser_storage_state_t *state,
                    void *const buf, size_t len)
{
  uint8_t *bufi = buf;
  ssize_t ret;

  while (buf == NULL || len > 0) {
    switch (*state) {
    case PARSER_STORAGE_OPENING:
      storage_open_writer(storage);
      *state = PARSER_STORAGE_WRITING;
      break;
    case PARSER_STORAGE_WRITING:
      if (buf == NULL)
        *state = PARSER_STORAGE_CLOSING;
      else {
        ret = storage_write(storage, bufi, len);
        assert(ret >= 0);
        bufi += ret;
        len -= ret;
      }
      break;
    case PARSER_STORAGE_CLOSING:
      // fixme: hardcoded prefix length 6
      storage_close_writer(storage, 6);
      *state = PARSER_STORAGE_OPENING;
      goto done;
      break;
    }
  }

done:
  return bufi - (uint8_t *)buf;
}

size_t
http_read(void *const buf_head, size_t buf_size,
          void *ptr, protocol_state_t *protocol_state)
{
  http_context_t *context = (http_context_t *)ptr;
  void *buf = buf_head;
  void *ret = NULL;
  uint8_t *buf_tail = (uint8_t *)buf_head + buf_size;

  fprintf(stderr, "http_read %zu\n", buf_size);

  parser_terminator_t match;
  int length;

  void *
  next_terminator(parser_terminator_t stop)
  {
    uint8_t *bufi = buf;

    while (bufi < buf_tail) {
      switch (*bufi) {
      case ' ':
        match = SPACE;
        length = 1;
        goto match;
        break;
      case '\r':
        if (!(bufi + 1 < buf_tail))
          return NULL;
        if (*(bufi + 1) == '\n') {
          match = CRLF;
          length = 2;
          goto match;
        }
        break;
      case ':':
        match = COLON;
        length = 1;
        goto match;
        break;
      default:
        break;
      }
      bufi++;
      continue;

    match:
      if (stop != INVALID_TERMINATOR && stop != match) {
        bufi++;
        continue;
      } else
        return bufi;
    }
    return NULL;
  }

  parser_state_t next_state = PARSER_INVALID;

  context->range.first = 0;
  context->range.last = UINT64_MAX - 1;

  while (context->parser.state != PARSER_INVALID) {

    // PARSING_BODY handles its own state transitions
    if (context->parser.state != PARSING_BODY) {
      ret = next_terminator(context->parser.state == PARSING_HEADER_VALUE ? CRLF : INVALID_TERMINATOR);
      if (ret == NULL)
        goto handled_buf;

      next_state = transitions[context->parser.state][match].next_state;

      if (next_state == PARSER_INVALID) {
        fprintf(stderr, "no terminator match\n");
        parser_stop(STATUS_BAD_REQUEST, PROTOCOL_SHUTDOWN);
      }
    }

    assert(ret != NULL || context->parser.state == PARSING_BODY);

    switch (context->parser.state) {
    case PARSING_REQUEST_METHOD:
      {
        size_t method_length = ret - buf;
        *(uint8_t *)ret = '\0';
        fprintf(stderr, "method: `%s`\n", (char *)buf);
        if (3 == method_length && memcmp(buf, "GET", 3) == 0)
          context->method = METHOD_GET;
        else if (4 == method_length && memcmp(buf, "HEAD", 3) == 0)
          context->method = METHOD_HEAD;
        else if (4 == method_length && memcmp(buf, "POST", 4) == 0)
          context->method = METHOD_POST;
        else if (7 == method_length && memcmp(buf, "OPTIONS", 7) == 0) {
          context->method = METHOD_OPTIONS;
          // also assume this is a preflight request
          context->cors_mode = CORS_PREFLIGHT_COMPLETE;
        }
        else {
          *(char *)ret = '\0';
          fprintf(stderr, "unsupported method: `%s`\n", (char *)buf);
          context->status_code = STATUS_BAD_REQUEST;
        }
      }
      break;
    case PARSING_REQUEST_URI:
      context->uri_length = ret - buf;
      if (context->uri_length > MAX_URI_LENGTH) {
        fprintf(stderr, "bad uri length\n");
        parser_stop(STATUS_BAD_REQUEST, PROTOCOL_SHUTDOWN);
      }
      memcpy(context->uri, buf, ret - buf);
      *(context->uri + context->uri_length) = '\0';
      fprintf(stderr, "uri: %s\n", context->uri);
      break;
    case PARSING_REQUEST_VERSION:
      if (memcmp(http_version, buf, ret - buf) != 0) {
        fprintf(stderr, "wrong http version\n");
        parser_stop(STATUS_BAD_REQUEST, PROTOCOL_SHUTDOWN);
      }
      break;
    case PARSING_HEADER_NAME_OR_BODY:
      switch (next_state) {
      case PARSING_BODY:
        if (buf != ret) {
          fprintf(stderr, "garbage between last terminator and body crlf\n");
          parser_stop(STATUS_BAD_REQUEST, PROTOCOL_SHUTDOWN);
        }
        break;
      case PARSING_HEADER_VALUE:
        // we have a header name
        //*(char *)ret = '\0';
        //fprintf(stderr,"header: `%s` = ", (char*)buf);
        context->current_header = parse_header_name(buf, ret - buf);
        break;
      default:
        assert(0 && "unreachable");
        break;
      }
      break;
    case PARSING_HEADER_VALUE:
      //*(char *)ret = '\0';
      //fprintf(stderr, "`%s`\n", (char*)buf);

      if (context->current_header == HEADER_INVALID)
        // "INVALID" headers aren't really invalid; we just aren't concerned
        // with parsing them
        break;
      {
        uint8_t *value, *end, *tok;
        int valid;
        value = mem_nows(buf, ret - buf);
        end = mem_rnows(buf, ret - buf);

        switch (context->current_header) {
        case HEADER_TRANSFER_ENCODING:
          if (context->parser.length_mode != LENGTH_MODE_NONE)
            parser_stop(STATUS_BAD_REQUEST, PROTOCOL_SHUTDOWN);

          if (end - value != 7 || memcmp(value, "chunked", 7) != 0)
            parser_stop(STATUS_BAD_REQUEST, PROTOCOL_SHUTDOWN);

          context->chunked.read = 0;
          context->chunked.length = 0;
          context->parser.length_mode = LENGTH_MODE_CHUNKED;
          break;
        case HEADER_CONTENT_LENGTH:
          if (context->parser.length_mode != LENGTH_MODE_NONE)
            parser_stop(STATUS_BAD_REQUEST, PROTOCOL_SHUTDOWN);

          context->fixed.read = 0;
          valid = base10_to_uint64(value, &context->fixed.length, end - value);
          if (valid < 0)
            // rfc7320: [if] single Content-Length header field [has] an invalid
            // value, then the message framing is invalid and the recipient MUST
            // treat it as an unrecoverable error
            parser_stop(STATUS_BAD_REQUEST, PROTOCOL_SHUTDOWN);

          context->parser.length_mode = LENGTH_MODE_FIXED;
          break;
        case HEADER_RANGE:
          if (end - value < 6 || memcmp(value, "bytes=", 6) != 0)
            parser_stop(STATUS_BAD_REQUEST, PROTOCOL_SHUTDOWN);
          value += 6;
          tok = memrchr(value, '-', end - value);
          // parse "first-byte-pos"
          valid = base10_to_uint64(value, &context->range.first, tok - value);
          if (valid < 0)
            parser_stop(STATUS_BAD_REQUEST, PROTOCOL_SHUTDOWN);
          // parse "last-byte-pos"
          if (tok + 1 != end) {
            value = tok + 1;
            valid = base10_to_uint64(value, &context->range.last, end - value);
            if (valid < 0)
              parser_stop(STATUS_BAD_REQUEST, PROTOCOL_SHUTDOWN);
          }
          fprintf(stderr, "range: %zd %zd\n", context->range.first, context->range.last);
          break;
        case HEADER_INVALID:
          assert(0 && "unreachable");
          break;
        default:
          break;
        }
      }
      break;
    case PARSING_BODY:
      switch (context->parser.length_mode) {
      case LENGTH_MODE_NONE:
        if (context->method == METHOD_GET)
          parser_stop(STATUS_UNSET, PROTOCOL_WRITING);
        else if (context->method == METHOD_OPTIONS)
          parser_stop(STATUS_NO_CONTENT, PROTOCOL_WRITING);
        else if (context->method == METHOD_HEAD)
          parser_stop(STATUS_OK, PROTOCOL_WRITING);
        else
          parser_stop(STATUS_BAD_REQUEST, PROTOCOL_WRITING);
        break;
      case LENGTH_MODE_FIXED:
        if (context->method == METHOD_POST) {
          size_t len = min(context->fixed.length - context->fixed.read,
                           (size_t)(buf_tail - (uint8_t *)buf));

          len = handle_body_storage(&context->parser.storage,
                                    &context->parser.storage_state,
                                    buf, len);

          buf += len;
          context->fixed.read += len;
          assert(!(context->fixed.read > context->fixed.length));

          if (context->fixed.read == context->fixed.length) {
            handle_body_storage(&context->parser.storage,
                                &context->parser.storage_state,
                                NULL, 0);
            parser_stop(STATUS_OK, PROTOCOL_WRITING);
          } else
            goto handled_buf;
        } else
          parser_stop(STATUS_BAD_REQUEST, PROTOCOL_SHUTDOWN);
        break;
      case LENGTH_MODE_CHUNKED:

        if (context->method == METHOD_POST) {
        next_chunk:
          if (context->chunked.length == 0) {
            ret = next_terminator(CRLF);
            if (ret == NULL)
              goto handled_buf;

            if (base16_to_uint64(buf, &context->chunked.length, ret - buf) < 0)
              parser_stop(STATUS_BAD_REQUEST, PROTOCOL_SHUTDOWN);

            //fprintf(stderr, "new chunk: size: %ld %p %ld\n", context->chunked.length, buf, ret - buf);

            buf += (ret - buf) + length;

            if (context->chunked.length == 0) {
              handle_body_storage(&context->parser.storage,
                                  &context->parser.storage_state,
                                  NULL, 0);
              parser_stop(STATUS_OK, PROTOCOL_WRITING);
            }
          }

          size_t len = min(context->chunked.length - context->chunked.read,
                           (size_t)(buf_tail - (uint8_t *)buf));

          len = handle_body_storage(&context->parser.storage,
                                    &context->parser.storage_state,
                                    buf, len);

          buf += len;
          context->chunked.read += len;

          if (context->chunked.read == context->chunked.length) {
            if (buf_tail - (uint8_t *)buf < 2)
              goto handled_buf;
            ret = next_terminator(CRLF);
            if (ret == NULL || ret != buf)
              // unterminated or invalidly terminated chunk; the client is in error
              parser_stop(STATUS_BAD_REQUEST, PROTOCOL_SHUTDOWN);

            buf += length;

            context->chunked.length = 0;
            context->chunked.read = 0;
            goto next_chunk;
          } else
            goto handled_buf;
        } else
          parser_stop(STATUS_BAD_REQUEST, PROTOCOL_SHUTDOWN);
        break;
      }
      assert(0 && "unreachable: implicit body state transition");
      break;
    default:
      assert(0 && "unreachable: invalid context state");
      break;
    }

    context->parser.state = next_state;
    buf = ret + length;
  }

 handled_buf:
  return (uint8_t *)buf - (uint8_t *)buf_head;
}

#define _buf_length() ((size_t)(buf_size - ((uint8_t *)buf - (uint8_t *)buf_head)))

static const char *
find_mime_type(const char *ext)
{
  mime_entry_t *entry;

  entry = mime_types;
  while (entry < mime_types + ((sizeof (mime_types)) / (sizeof (mime_entry_t)))) {
    if (strcmp(entry->ext, ext) == 0)
      return entry->type;
    entry++;
  }
  return NULL;
}

size_t
http_write(void *const buf_head, size_t buf_size,
           void *ptr, protocol_state_t *protocol_state)
{
  http_context_t *context = (http_context_t *)ptr;
  uint8_t *buf = buf_head;
  int ret;

  while (1) {
    assert(!(context->emitter.state != EMITTER_RESOLVE_URI &&
             context->status_code == STATUS_UNSET));

    switch (context->emitter.state) {
    case EMITTER_RESOLVE_URI:
      // fixme: emitter_resolve_uri is a GET concept; maybe this is entire state
      // is actually a "parser" concern
      if (context->method != METHOD_GET)
        break;

      context->emitter.storage.read_fd = -1;

      if (context->status_code != STATUS_UNSET)
        // if the parser set an error, move to the next state without resolving a uri
        break;

      if (*context->uri != '/' ||
          *(context->uri + 1) == '/' || *(context->uri + 1) == '.') {
        context->status_code = STATUS_BAD_REQUEST;
        break;
      }

      if (*(context->uri + 1) == 's' && context->uri_length == 2) {
        context->status_code = STATUS_OK;
        context->emitter.content_mode = CONTENT_MODE_STATS;
      } else {
        char *ext;
        // find an extension
        ext = memrchr(context->uri + 1, '.', context->uri_length - 1);
        if (ext == NULL)
          context->mime_type = NULL;
        else {
          context->mime_type = find_mime_type(ext + 1);
          *ext = '\0';
          context->uri_length = ext - context->uri;
        }

        ret = storage_open_reader(&context->emitter.storage, context->uri + 1, context->uri_length - 1, context->range.first, context->range.last);
        if (ret < 0)
          context->status_code = STATUS_NOT_FOUND;
        else {
          if (context->range.first != 0 || context->range.last != (UINT64_MAX - 1))
            context->status_code = STATUS_PARTIAL_CONTENT;
          else
            context->status_code = STATUS_OK;
          context->emitter.length_mode = LENGTH_MODE_FIXED;
          context->emitter.content_mode = CONTENT_MODE_STORAGE;
        }
      }
      break;
    case EMITTING_STATUS_LINE:
      if (_buf_length() < STATUS_LINE_LENGTH)
        goto handled_buf;

      memcpy(buf, http_version, HTTP_VERSION_SIZE);
      buf += HTTP_VERSION_SIZE;
      *buf++ = ' ';
      memcpy(buf, protocol_code[context->status_code], STATUS_CODE_SIZE);
      buf += STATUS_CODE_SIZE;
      *buf++ = ' ';
      *buf++ = '\r';
      *buf++ = '\n';
      break;
    case EMITTING_HEADERS:
      next_header:
      {
        header_t *headers = method_headers[context->method];
        assert(headers != NULL);
        header_t header = headers[context->emitter.header_index++];

        if (header == HEADER_INVALID)
          break;

        header_string_t header_string = header_strings[header];
        switch (header) {
        case HEADER_ACAO:
        case HEADER_ACAH:
        case HEADER_ACAM:
          if (context->method != METHOD_OPTIONS &&
              context->cors_mode != CORS_PREFLIGHT_COMPLETE)
            goto next_header;
          __attribute__ ((fallthrough));
        case HEADER_ACCEPT_RANGES:
          if (_buf_length() < header_string.length + 2)
            goto handled_buf;
          memcpy(buf, header_string.buf, header_string.length);
          buf += header_string.length;
          *buf++ = '\r';
          *buf++ = '\n';
          break;
        case HEADER_TRANSFER_ENCODING:
          if (context->emitter.length_mode != LENGTH_MODE_CHUNKED)
            goto next_header;
          if (_buf_length() < header_string.length + 2)
            goto handled_buf;

          memcpy(buf, header_string.buf, header_string.length);
          buf += header_string.length;
          *buf++ = '\r';
          *buf++ = '\n';
          break;
        case HEADER_CONTENT_RANGE:
          if (context->status_code != STATUS_PARTIAL_CONTENT)
            goto next_header;
          if (_buf_length() < header_string.length + 2 + 2 + 20 + 20 + 20)
            goto handled_buf;

          memcpy(buf, header_string.buf, header_string.length);
          buf += header_string.length;

          fprintf(stderr, "need content-range\n");

          {
            size_t offset;

            offset = uint64_to_base10(buf, context->range.first, 20);
            memmove(buf, buf + offset, 20 - offset);
            buf += 20 - offset;

            *buf++ = '-';

            offset = uint64_to_base10(buf, context->range.last, 20);
            memmove(buf, buf + offset, 20 - offset);
            buf += 20 - offset;

            *buf++ = '/';

            offset = uint64_to_base10(buf, context->emitter.storage.size, 20);
            memmove(buf, buf + offset, 20 - offset);
            buf += 20 - offset;
          }

          *buf++ = '\r';
          *buf++ = '\n';
          break;
        case HEADER_CONTENT_LENGTH:
          if (context->emitter.length_mode != LENGTH_MODE_FIXED)
            goto next_header;
          if (_buf_length() < header_string.length + 2 + 20)
            goto handled_buf;

          memcpy(buf, header_string.buf, header_string.length);
          buf += header_string.length;

          {
            size_t offset = uint64_to_base10(buf, context->emitter.storage.length, 20);
            memmove(buf, buf + offset, 20 - offset);
            buf += 20 - offset;
          }

          *buf++ = '\r';
          *buf++ = '\n';
          break;
        case HEADER_CONTENT_TYPE:
          if (context->mime_type == NULL)
            break;

          size_t mime_length = strlen(context->mime_type);
          if (_buf_length() < header_string.length + 2 + mime_length)
            goto handled_buf;

          memcpy(buf, header_string.buf, header_string.length);
          buf += header_string.length;
          memcpy(buf, context->mime_type, mime_length);
          buf += mime_length;
          *buf++ = '\r';
          *buf++ = '\n';
          break;
        default:
          // next emitter state
          break;
        }

        goto next_header;
      }
      break;
    case EMITTING_LAST_HEADER:
      if (_buf_length() < 2)
        goto handled_buf;
      // last header
      *buf++ = '\r';
      *buf++ = '\n';
      break;
    case EMITTING_BODY:
      #define CHUNK_PAD_SIZE (context->emitter.length_mode == LENGTH_MODE_CHUNKED ? (4 + 2 + 2) : 0)
      #define CHUNK_OFFSET (context->emitter.length_mode == LENGTH_MODE_CHUNKED ? (4 + 2) : 0)

      #define terminate_chunk(_size)                               \
        do {                                                       \
          if (context->emitter.length_mode != LENGTH_MODE_CHUNKED) \
            buf += _size;                                          \
          else {                                                   \
            assert(_size < 0xffff);                                \
            uint16_to_hex(buf, _size);                             \
            buf += 4;                                              \
            *buf++ = '\r';                                         \
            *buf++ = '\n';                                         \
            buf += _size;                                          \
            *buf++ = '\r';                                         \
            *buf++ = '\n';                                         \
          }                                                        \
        } while (0);

      if (context->status_code != STATUS_OK && context->status_code != STATUS_PARTIAL_CONTENT)
        break;

      switch (context->method) {
      case METHOD_GET:
        // need at least 1 byte to read
        if (_buf_length() < CHUNK_PAD_SIZE + 1)
          goto handled_buf;

        uint16_t chunk_length;
        switch (context->emitter.content_mode) {
        case CONTENT_MODE_STORAGE:
          assert(context->emitter.storage.read_fd != -1);
          ssize_t count = read(context->emitter.storage.read_fd, buf + CHUNK_OFFSET,
                               _buf_length() - CHUNK_PAD_SIZE);
          esprintf(count, "read");
          ssize_t remaining = context->emitter.storage.length - context->emitter.storage.read_bytes;
          if (remaining < count)
            chunk_length = remaining;
          else
            chunk_length = count;
          context->emitter.storage.read_bytes += chunk_length;

          if (chunk_length == 0) {
            ret = close(context->emitter.storage.read_fd);
            esprintf(ret, "close");
            context->emitter.storage.read_fd = -1;
          } else {
            terminate_chunk(chunk_length);
            goto handled_buf;
          }
          break;
        case CONTENT_MODE_STATS:
          chunk_length = stats_render(buf + CHUNK_OFFSET);
          break;
        default:
          assert(0 && "unreachable");
          break;
        }

        terminate_chunk(chunk_length);
        break;
      case METHOD_POST:
        {
          if (_buf_length() < CHUNK_PAD_SIZE + context->parser.storage.name_length + 1)
            goto handled_buf;

          memcpy(buf + CHUNK_OFFSET,
                 context->parser.storage.name,
                 context->parser.storage.name_length);
          terminate_chunk(context->parser.storage.name_length);
        }
        break;
      default:
        break;
      }
      break;
    case EMITTING_CHUNKED_EOF:
      if (context->emitter.length_mode != LENGTH_MODE_CHUNKED)
        break;

      if (_buf_length() < 5)
        goto handled_buf;

      *buf++ = '0';
      *buf++ = '\r';
      *buf++ = '\n';
      *buf++ = '\r';
      *buf++ = '\n';
      break;
    default:
      assert(0 && "unreachable");
      break;
    }

    context->emitter.state = emitter_transitions[context->emitter.state];
    if (context->emitter.state == EMITTER_RESOLVE_URI) {
      // we are done, switch to PROTOCOL_READING
      *protocol_state = PROTOCOL_READING;
      assert(context->parser.state == PARSING_REQUEST_METHOD);
      context->status_code = STATUS_UNSET;
      break;
    }
  }

 handled_buf:
  return (uint8_t *)buf - (uint8_t *)buf_head;
}

void
http_terminate(void *ptr)
{
  http_context_t *context = (http_context_t *)ptr;

  if (context->emitter.storage.read_fd != -1)
    close(context->emitter.storage.read_fd);

  if (context->parser.storage.write_fd != -1)
    close(context->parser.storage.write_fd);

  free(context);
}
