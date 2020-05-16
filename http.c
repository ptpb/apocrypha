#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/fcntl.h>

#include "error.h"
#include "http.h"

typedef enum terminator {
  INVALID_TERMINATOR = 0,
  SPACE,
  CRLF,
  COLON,
  TERMINATOR_LAST,
} terminator_t;

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

typedef enum emitter_state {
  EMITTER_INVALID = 0,
  EMITTER_IDLE,
  EMITTING_STATUS_LINE,
  EMITTING_TE_HEADER,
  EMITTING_BODY,
  EMITTER_STATE_LAST,
} emitter_state_t;

static emitter_state_t emitter_transitions[EMITTER_STATE_LAST] = {
  [EMITTER_IDLE] = EMITTING_STATUS_LINE,
  [EMITTING_STATUS_LINE] = EMITTING_TE_HEADER,
  [EMITTING_TE_HEADER] = EMITTING_BODY,
  [EMITTING_BODY] = EMITTER_INVALID,
};

typedef enum method {
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

#define STATUS_CODE_SIZE 3

static char
protocol_code[STATUS_CODE_LAST][STATUS_CODE_SIZE] = {
  [STATUS_OK] = "200",
  [STATUS_BAD_REQUEST] = "400",
  [STATUS_NOT_FOUND] = "404",
};

#define HTTP_VERSION_SIZE 8
static char http_version[HTTP_VERSION_SIZE] = "HTTP/1.1";
#define HTTP_TE_HEADER_SIZE 28
static char http_te_header[HTTP_TE_HEADER_SIZE] = "transfer-encoding: chunked\r\n";

#define STATUS_LINE_LENGTH (HTTP_VERSION_SIZE + 1 + STATUS_CODE_SIZE + 3)

#define URI_LENGTH 65

typedef struct http_context {
  emitter_state_t emitter_state;
  parser_state_t parser_state;
  method_t method;
  char uri[URI_LENGTH + 1];
  //
  status_code_t status_code;
  int write_fd;
  int read_fd;
} http_context_t;

void *
http_init(void)
{
  http_context_t *context;

  context = calloc(1, (sizeof (http_context_t)));
  context->emitter_state = EMITTER_INVALID;
  context->parser_state = PARSING_REQUEST_METHOD;

  return (void *)context;
}

size_t
http_read(void *buf_head, size_t buf_size, void *ptr, int *want_write)
{
  http_context_t *context = (http_context_t *)ptr;
  void *buf = buf_head;
  void *ret;
  uint8_t *buf_tail = (uint8_t *)buf_head + buf_size;

  fprintf(stderr, "http_read %ld\n", buf_size);

  terminator_t match;
  int length;

  void *
  next_terminator(terminator_t stop)
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

  while (1) {
    // FIXME: HACK
    if (context->parser_state == PARSING_BODY) {
      if (buf_tail - (uint8_t *)buf != 0)
        fprintf(stderr, "did not handle %ld bytes in body(?)", buf_tail - (uint8_t *)buf);
      context->emitter_state = EMITTER_IDLE;
      context->parser_state = PARSER_INVALID;
      *want_write = 1;
      break;
    }

    fprintf(stderr, "parser: current_state: %d ", context->parser_state);

    ret = next_terminator(context->parser_state == PARSING_HEADER_VALUE ? CRLF : INVALID_TERMINATOR);
    if (ret == NULL)
      goto handled_buf;

    parser_state_t next_state = transitions[context->parser_state][match].next_state;
    fprintf(stderr, "next_state: %d\n", next_state);

    if (next_state == PARSER_INVALID) {
      fprintf(stderr, "FIXME: no terminator match; should close\n");
    }

    switch (context->parser_state) {
    case PARSING_REQUEST_METHOD:
      *(char *)ret = '\0';
      fprintf(stderr, "method: %s\n", (char *)buf);
      break;
    case PARSING_REQUEST_URI:
      if (ret - buf != URI_LENGTH)
        fprintf(stderr, "wrong uri length; should 400\n");
      memcpy(context->uri, buf, ret - buf);
      fprintf(stderr, "uri: %s\n", context->uri);
      break;
    case PARSING_REQUEST_VERSION:
      if (memcmp(http_version, buf, ret - buf) != 0)
        fprintf(stderr, "wrong http version; should 400\n");
      break;
    case PARSING_HEADER_NAME_OR_BODY:
      switch (next_state) {
      case PARSING_BODY:
        if (buf != ret)
          fprintf(stderr, "garbage between last terminator and body crlf\n");
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

size_t
http_write(void *buf_head, size_t buf_size, void *ptr, int *want_read)
{
  http_context_t *context = (http_context_t *)ptr;
  uint8_t *buf = buf_head;
  int ret;

  fprintf(stderr, "http_write\n");

  while (1) {
    fprintf(stderr, "emitter: current_state: %d\n", context->emitter_state);

    switch (context->emitter_state) {
    case EMITTER_IDLE:
      context->read_fd = 0;

      if (context->status_code != STATUS_UNSET)
        break;

      if (*context->uri != '/' || *(context->uri + 1) == '/') {
        context->status_code = STATUS_BAD_REQUEST;
        break;
      }

      ret = open(context->uri + 1, O_RDONLY);
      if (ret < 0) {
        context->status_code = STATUS_NOT_FOUND;
        break;
      }

      context->read_fd = ret;

      context->status_code = STATUS_OK;

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
      // last header
      *buf++ = '\r';
      *buf++ = '\n';
      break;
    case EMITTING_BODY:
      #define CHUNK_PAD_SIZE (4 + 2 + 2)

      // need at least 1 byte to read
      if (_buf_length() < CHUNK_PAD_SIZE + 1)
        goto handled_buf;

      ret = read(context->read_fd, buf + 6,
                 _buf_length() - CHUNK_PAD_SIZE);
      esprintf(ret, "read");
      if (ret == 0) {
        *buf++ = '0';
        *buf++ = '\r';
        *buf++ = '\n';
        *buf++ = '\r';
        *buf++ = '\n';

        // end of file
        fprintf(stderr, "eof\n");
        ret = close(context->read_fd);
        esprintf(ret, "close");

        *want_read = 1;
        context->emitter_state = EMITTER_INVALID;
        context->parser_state = PARSING_REQUEST_METHOD;

        goto handled_buf;
      }
      else {
        assert(ret < 0xffff);
        snprintf((char *)buf, 5, "%04x", (uint16_t)ret);
        buf += 4;
        *buf++ = '\r';
        *buf++ = '\n';
        buf += ret;
        *buf++ = '\r';
        *buf++ = '\n';
        goto handled_buf;
      }
      break;
    default:
      assert(0 && "unreachable");
      break;
    }

    context->emitter_state = emitter_transitions[context->emitter_state];
  }

 handled_buf:
  return (uint8_t *)buf - (uint8_t *)buf_head;
}
