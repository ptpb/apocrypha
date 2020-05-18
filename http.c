#include <assert.h>
#include <dirent.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/fcntl.h>

#include "error.h"
#include "http.h"
#include "protocol.h"
#include "mime_types.h"
#include "hex.h"

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
  METHOD_HEAD,
} method_t;

typedef enum status_code {
  STATUS_UNSET = 0,
  STATUS_OK,
  STATUS_BAD_REQUEST,
  STATUS_NOT_FOUND,
  STATUS_CODE_LAST
} status_code_t;

typedef enum emitter_state {
  EMITTER_INVALID = 0,
  EMITTER_RESOLVE_URI,
  EMITTING_STATUS_LINE,
  EMITTING_TE_HEADER,
  EMITTING_CT_HEADER,
  EMITTING_LAST_HEADER,
  EMITTING_BODY,
  EMITTING_CHUNKED_EOF,
  EMITTER_STATE_LAST,
} emitter_state_t;

#define BAD 0
#define OK 1

static emitter_state_t emitter_transitions[EMITTER_STATE_LAST][2] = {
  [EMITTER_RESOLVE_URI] = {
    [BAD] = EMITTING_STATUS_LINE,
    [OK] = EMITTING_STATUS_LINE,
  },
  [EMITTING_STATUS_LINE] = {
    [BAD] = EMITTING_TE_HEADER,
    [OK] = EMITTING_TE_HEADER,
  },
  [EMITTING_TE_HEADER] = {
    [BAD] = EMITTING_LAST_HEADER,
    [OK] = EMITTING_CT_HEADER,
  },
  [EMITTING_CT_HEADER] = {
    [OK] = EMITTING_LAST_HEADER,
  },
  [EMITTING_LAST_HEADER] = {
    [BAD] = EMITTING_CHUNKED_EOF,
    [OK] = EMITTING_BODY,
  },
  [EMITTING_BODY] = {
    [OK] = EMITTING_CHUNKED_EOF,
  },
  [EMITTING_CHUNKED_EOF] = {
    [OK] = EMITTER_RESOLVE_URI,
    [BAD] = EMITTER_RESOLVE_URI,
  },
};

#define STATUS_CODE_SIZE 3

static char
protocol_code[STATUS_CODE_LAST][STATUS_CODE_SIZE] = {
  [STATUS_OK] = "200",
  [STATUS_BAD_REQUEST] = "400",
  [STATUS_NOT_FOUND] = "404",
};

static char http_version[] = "HTTP/1.1";
#define HTTP_VERSION_SIZE ((sizeof (http_version)) - 1)
static char http_te_header[] = "transfer-encoding: chunked";
#define HTTP_TE_HEADER_SIZE ((sizeof (http_te_header)) - 1)
static char http_ct_header[] = "content-type: ";
#define HTTP_CT_HEADER_SIZE ((sizeof (http_ct_header)) - 1)

#define STATUS_LINE_LENGTH (HTTP_VERSION_SIZE + 1 + STATUS_CODE_SIZE + 3)

#define MAX_URI_LENGTH 127
#define QUALIFIED_URI_LENGTH 64

typedef struct http_context {
  emitter_state_t emitter_state;
  parser_state_t parser_state;
  method_t method;
  char uri[MAX_URI_LENGTH + 1];
  uint8_t uri_length;
  //
  const char *mime_type;
  status_code_t status_code;
  int read_fd;
} http_context_t;

void *
http_init(void)
{
  http_context_t *context;

  context = calloc(1, (sizeof (http_context_t)));
  context->emitter_state = EMITTER_RESOLVE_URI;
  context->parser_state = PARSING_REQUEST_METHOD;
  context->read_fd = -1;

  return (void *)context;
}

#define parser_stop(_status_code, _protocol_state)          \
  do {                                                      \
    context->status_code =                                  \
      context->status_code == STATUS_UNSET                  \
      ? _status_code : context->status_code;                \
    context->parser_state = PARSING_REQUEST_METHOD;         \
    assert(context->emitter_state == EMITTER_RESOLVE_URI);  \
    *protocol_state = _protocol_state;                      \
    goto handled_buf;                                       \
  } while (0)

size_t
http_read(void *const buf_head, size_t buf_size,
          void *ptr, protocol_state_t *protocol_state)
{
  http_context_t *context = (http_context_t *)ptr;
  void *buf = buf_head;
  void *ret;
  uint8_t *buf_tail = (uint8_t *)buf_head + buf_size;

  fprintf(stderr, "http_read %ld\n", buf_size);

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

  parser_state_t next_state;

  while (context->parser_state != PARSER_INVALID) {

    if (context->parser_state == PARSING_BODY) {
      if (buf_tail - (uint8_t *)buf != 0) {
        fprintf(stderr, "did not handle %ld bytes in body(?)", buf_tail - (uint8_t *)buf);
        parser_stop(STATUS_BAD_REQUEST, PROTOCOL_SHUTDOWN);
      } else
        parser_stop(STATUS_UNSET, PROTOCOL_WRITING);
    }

    fprintf(stderr, "parser: current_state: %d ", context->parser_state);

    ret = next_terminator(context->parser_state == PARSING_HEADER_VALUE ? CRLF : INVALID_TERMINATOR);
    if (ret == NULL)
      goto handled_buf;

    next_state = transitions[context->parser_state][match].next_state;
    fprintf(stderr, "next_state: %d\n", next_state);

    if (next_state == PARSER_INVALID) {
      fprintf(stderr, "no terminator match\n");
      parser_stop(STATUS_BAD_REQUEST, PROTOCOL_SHUTDOWN);
    }

    switch (context->parser_state) {
    case PARSING_REQUEST_METHOD:
      {
        size_t method_length = ret - buf;
        if (3 == method_length && memcmp(buf, "GET", 3) == 0)
          context->method = METHOD_GET;
        /*
        else if (4 == method_length && memcmp(buf, "POST", 4) == 0)
          context->method = METHOD_POST;
        */
        else {
          *(char *)ret = '\0';
          fprintf(stderr, "unsupported method: %s\n", (char *)buf);
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
        *(char *)ret = '\0';
        fprintf(stderr, "header-name: %s\n", (char *)buf);
        break;
      default:
        assert(0 && "unreachable");
        break;
      }
      break;
    case PARSING_HEADER_VALUE:
      *(char *)ret = '\0';
      fprintf(stderr, "header-value: %s\n", (char *)buf);
      break;
    default:
      assert(0 && "unreachable");
      break;
    }

    context->parser_state = next_state;
    buf = ret + length;
  }

 handled_buf:
  return (uint8_t *)buf - (uint8_t *)buf_head;
}

#define _buf_length() (buf_size - ((uint8_t *)buf - (uint8_t *)buf_head))

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

  fprintf(stderr, "http_write\n");

  while (1) {
    fprintf(stderr, "emitter: current_state: %d\n", context->emitter_state);

    assert(!(context->emitter_state != EMITTER_RESOLVE_URI &&
             context->status_code == STATUS_UNSET));

    switch (context->emitter_state) {
    case EMITTER_RESOLVE_URI:
      context->read_fd = -1;

      if (context->status_code != STATUS_UNSET)
        // if the parser set an error, move to the next state without resolving a uri
        break;

      if (*context->uri != '/' ||
          *(context->uri + 1) == '/' || *(context->uri + 1) == '.') {
        context->status_code = STATUS_BAD_REQUEST;
        break;
      }

      {
        char *ext;
        // find an extension
        ext = memrchr(context->uri + 1, '.', context->uri_length);
        if (ext == NULL)
          context->mime_type = NULL;
        else {
          context->mime_type = find_mime_type(ext + 1);
          //fprintf(stderr, "mime_type: %s -> %s\n", ext, context->mime_type);
          *ext = '\0';
          context->uri_length = ext - context->uri;
        }
      }

      ret = open(context->uri + 1, O_RDONLY);
      if (ret < 0)
        context->status_code = STATUS_NOT_FOUND;
      else {
        context->read_fd = ret;
        context->status_code = STATUS_OK;
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
    case EMITTING_TE_HEADER:
      if (_buf_length() < HTTP_TE_HEADER_SIZE + 2)
        goto handled_buf;

      memcpy(buf, http_te_header, HTTP_TE_HEADER_SIZE);
      buf += HTTP_TE_HEADER_SIZE;
      *buf++ = '\r';
      *buf++ = '\n';
      break;
    case EMITTING_CT_HEADER:
      if (context->mime_type == NULL)
        break;

      size_t mime_length = strlen(context->mime_type);
      if (_buf_length() < HTTP_CT_HEADER_SIZE + 2 + mime_length)
        goto handled_buf;

      memcpy(buf, http_ct_header, HTTP_CT_HEADER_SIZE);
      buf += HTTP_CT_HEADER_SIZE;
      memcpy(buf, context->mime_type, mime_length);
      buf += mime_length;
      *buf++ = '\r';
      *buf++ = '\n';
      break;
    case EMITTING_LAST_HEADER:
      if (_buf_length() < 2)
        goto handled_buf;
      // last header
      *buf++ = '\r';
      *buf++ = '\n';
      break;
    case EMITTING_BODY:
      #define CHUNK_PAD_SIZE (4 + 2 + 2)

      // need at least 1 byte to read
      if (_buf_length() < CHUNK_PAD_SIZE + 1)
        goto handled_buf;

      assert(context->read_fd != -1);
      ret = read(context->read_fd, buf + 6,
                 _buf_length() - CHUNK_PAD_SIZE);
      esprintf(ret, "read");
      if (ret == 0) {
        // end of file
        fprintf(stderr, "eof\n");
        ret = close(context->read_fd);
        context->read_fd = -1;
        esprintf(ret, "close");
      } else {
        assert(ret < 0xffff);
        uint16_to_hex(buf, &ret, 1);
        *(buf + 4) = '\0';
        buf += 4;
        *buf++ = '\r';
        *buf++ = '\n';
        buf += ret;
        *buf++ = '\r';
        *buf++ = '\n';

        fprintf(stderr, "http body: requested=%ld wrote=%d actual=%ld\n", buf_size, ret, (uint8_t *)buf - (uint8_t *)buf_head);
        goto handled_buf;
      }
      break;
    case EMITTING_CHUNKED_EOF:
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

    context->emitter_state = emitter_transitions[context->emitter_state][context->status_code == STATUS_OK];
    if (context->emitter_state == EMITTER_RESOLVE_URI) {
      // we are done, switch to PROTOCOL_READING
      *protocol_state = PROTOCOL_READING;
      assert(context->parser_state == PARSING_REQUEST_METHOD);
      context->status_code = STATUS_UNSET;
      break;
    }
  }

 handled_buf:
  fprintf(stderr, "handled_buf\n");
  return (uint8_t *)buf - (uint8_t *)buf_head;
}

void
http_terminate(void *ptr)
{
  http_context_t *context = (http_context_t *)ptr;

  if (context->read_fd != -1)
    close(context->read_fd);

  free(context);
}
