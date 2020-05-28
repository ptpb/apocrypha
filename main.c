#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/fcntl.h>

#include <tls.h>

#include "error.h"
#include "http.h"
#include "native.h"
#include "protocol.h"
#include "config.h"

#define BUF_SIZE 65536

typedef void *(protocol_init_t)(void);
typedef size_t (protocol_read_t)(void *buf_head, size_t buf_size,
                                 void *ptr, protocol_state_t *protocol_state);
typedef size_t (protocol_write_t)(void *buf_head, size_t buf_size,
                                  void *ptr, protocol_state_t *protocol_state);
typedef void (protocol_terminate_t)(void *ptr);

typedef struct protocol {
  int fd;
  protocol_init_t *init;
  protocol_read_t *read;
  protocol_write_t *write;
  protocol_terminate_t *terminate;
} protocol_t;

typedef struct client {
  int fd;
  struct tls *tls;
  uint8_t read_buf[BUF_SIZE];
  size_t read_buf_index;
  uint8_t write_buf[BUF_SIZE];
  size_t write_buf_index;

  //
  protocol_state_t protocol_state;
  protocol_t *protocol;
  void *context;
} client_t;

//

//

#define MAX_EVENTS 1024
#define MAX_CLIENTS 1024

static void
new_client(int epoll_fd, int client_fd, struct tls *tls, protocol_t *protocol) {
  client_t *client;
  int ret;

  client = calloc(1, (sizeof (client_t)));
  client->fd = client_fd;

  ret = tls_accept_socket(tls, &client->tls, client_fd);
  esprintf(ret, "tls_accept_socket");

  client->context = (*protocol->init)();
  client->protocol = protocol;
  client->protocol_state = PROTOCOL_READING;

  ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &(struct epoll_event){
    .events = EPOLLIN | EPOLLONESHOT,
    .data.ptr = client,
  });

  esprintf(ret, "epoll_ctl: EPOLL_CTL_ADD");

  fprintf(stderr, "new_client: %d\n", client->fd);
}

static void
handle_client_read(client_t *client) {
  int ret;
  size_t buf_length;
  size_t buf_handled;

  while (client->protocol_state == PROTOCOL_READING) {
    ret = tls_read(client->tls, client->read_buf + client->read_buf_index, (sizeof (client->read_buf)) - client->read_buf_index);
    if (ret == TLS_WANT_POLLIN)
      break;
    else if (ret < 0) {
      fprintf(stderr, "tls_read: %s\n", tls_error(client->tls));
      client->protocol_state = PROTOCOL_SHUTDOWN;
    } else if (ret == 0) {
      client->protocol_state = PROTOCOL_SHUTDOWN;
    } else {
      //fprintf(stderr, "tls_read: %d\n", ret);
      buf_length = client->read_buf_index + ret;
      buf_handled = (*client->protocol->read)(client->read_buf, buf_length, client->context, &client->protocol_state);

      memmove(client->read_buf, client->read_buf + buf_handled, buf_length - buf_handled);

      client->read_buf_index = buf_length - buf_handled;
    }
  }
}

static void
handle_client_write(client_t *client)
{
  int ret;
  size_t protocol_ret;

  if (client->protocol_state == PROTOCOL_WRITING) {
    protocol_ret = (*client->protocol->write)(client->write_buf + client->write_buf_index,
                                              (sizeof (client->write_buf)) - client->write_buf_index,
                                              client->context, &client->protocol_state);
    client->write_buf_index += protocol_ret;

    if (protocol_ret == 0 && client->write_buf_index == 0)
      return;
  }

  assert(client->write_buf_index != 0);

  size_t write_offset = 0;

  while (write_offset != client->write_buf_index) {
    ret = tls_write(client->tls, client->write_buf + write_offset, client->write_buf_index - write_offset);
    if (ret == TLS_WANT_POLLOUT) {
      break;
    } else if (ret < 0) {
      fprintf(stderr, "tls_write: %s\n", tls_error(client->tls));
      client->protocol_state = PROTOCOL_SHUTDOWN;
      break;
    } else {
      write_offset += ret;
    }
  }

  memmove(client->write_buf, client->write_buf + write_offset, client->write_buf_index - write_offset);
  client->write_buf_index -= write_offset;
}

void
load_tls_config(int dirfd, struct tls *ctx)
{
  struct tls_config *tls_config;
  int ret;

  static uint8_t buf[8092];

  //

  tls_config = tls_config_new();
  assert(tls_config != NULL && "tls_config_new");

  //

  ssize_t size;
  int fd;

  fd = openat(dirfd, TLS_CERT, O_RDONLY);
  esprintf(fd, "open: %s", TLS_CERT);

  size = read(fd, buf, (sizeof (buf)));
  esprintf(size, "read: %s", TLS_CERT);
  assert(size != (sizeof (buf)) && "tls_cert too large");

  ret = tls_config_set_cert_mem(tls_config, buf, size);
  etcprintf(ret, tls_config, "tls_config_set_cert_mem: %s", TLS_CERT);

  ret = close(fd);
  esprintf(ret, "close");

  //

  fd = openat(dirfd, TLS_KEY, O_RDONLY);
  esprintf(fd, "open: %s", TLS_CERT);

  size = read(fd, buf, (sizeof (buf)));
  esprintf(size, "read: %s", TLS_CERT);
  assert(size != (sizeof (buf)) && "tls_key too large");

  ret = tls_config_set_key_mem(tls_config, buf, size);
  etcprintf(ret, tls_config, "tls_config_set_key_mem: %s", TLS_KEY);

  ret = close(fd);
  esprintf(ret, "close");

  //

  ret = tls_configure(ctx, tls_config);
  enprintf(ret, "tls_configure");

  tls_config_free(tls_config);
}

typedef enum signal_state {
  SIGNAL_NONE,
  SIGNAL_WANT_TLS_CONFIG_RELOAD,
} signal_state_t;

static signal_state_t signal_state = SIGNAL_NONE;

static void
sighup_handler(int signum)
{
  assert(signum == SIGHUP);
  signal_state = SIGNAL_WANT_TLS_CONFIG_RELOAD;
}

int
main(void)
{
  int ret;
  struct tls *tls;

  //

  int dirfd;
  dirfd = open(".", O_DIRECTORY);
  esprintf(dirfd, "open: .");

  ret = chdir("objects");
  esprintf(ret, "chdir: %s", "objects");

  //

  ret = tls_init();
  enprintf(ret, "tls_init");

  tls = tls_server();
  assert(tls != NULL && "tls_server");

  load_tls_config(dirfd, tls);
  //

  int
  open_port(uint16_t port)
  {
    int fd;

    ret = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    esprintf(ret, "socket");
    fd = ret;

    ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, (sizeof (int)));
    esprintf(ret, "setsockopt: SO_REUSEADDR");

    struct sockaddr_in6 sockaddr = {
      .sin6_family = AF_INET6,
      .sin6_port = htons(port),
      .sin6_addr = IN6ADDR_ANY_INIT,
    };

    ret = bind(fd, (struct sockaddr *)&sockaddr, (sizeof (struct sockaddr_in6)));
    esprintf(ret, "bind: %hu", port);

    ret = listen(fd, 1024);
    esprintf(ret, "listen");

    return fd;
  }

  protocol_t binary = {
    .fd = open_port(NATIVE_PORT),
    .init = &binary_init,
    .read = &binary_read,
    .write = &binary_write,
    .terminate = &binary_terminate,
  };

  protocol_t http = {
    .fd = open_port(HTTP_PORT),
    .init = &http_init,
    .read = &http_read,
    .write = &http_write,
    .terminate = &http_terminate,
  };

  //

  int epoll_fd;
  ret = epoll_create1(EPOLL_CLOEXEC);
  esprintf(ret, "epoll_create1");
  epoll_fd = ret;

  ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, binary.fd, &(struct epoll_event){
    .events = EPOLLIN | EPOLLET,
    .data.ptr = &binary,
  });
  esprintf(ret, "epoll_ctl: EPOLL_CTL_ADD");

  ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, http.fd, &(struct epoll_event){
    .events = EPOLLIN | EPOLLET,
    .data.ptr = &http,
  });
  esprintf(ret, "epoll_ctl: EPOLL_CTL_ADD");

  //

  struct sigaction sa;
  sa.sa_handler = sighup_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  ret = sigaction(SIGHUP, &sa, NULL);
  esprintf(ret, "sigaction: SIGHUP");

  ret = sigaction(SIGPIPE, &(struct sigaction){.sa_handler = SIG_IGN, .sa_flags = 0}, NULL);
  esprintf(ret, "sigation: SIGPIPE");

  //

  int client_fd;
  struct epoll_event events[MAX_EVENTS];
  void *event_ptr;
  int event_index;

  while (1) {
    switch (signal_state) {
    case SIGNAL_WANT_TLS_CONFIG_RELOAD:
      fprintf(stderr, "want_tls_config_reload\n");
      tls_reset(tls);
      load_tls_config(dirfd, tls);
      signal_state = SIGNAL_NONE;
      break;
    case SIGNAL_NONE:
      break;
    }

    const int total_events = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
    if (total_events < 0 && errno == EINTR)
      continue;
    else
      esprintf(total_events, "epoll_wait");

    for (event_index = 0; event_index < total_events; event_index++) {
      event_ptr = events[event_index].data.ptr;
      if (event_ptr == &binary || event_ptr == &http) {
        protocol_t *protocol = (protocol_t *)event_ptr;
        while (1) {
          ret = accept4(protocol->fd, NULL, NULL, SOCK_NONBLOCK);
          if (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
          esprintf(ret, "accept4");
          fprintf(stderr, "accept4 %d\n", ret);
          client_fd = ret;

          new_client(epoll_fd, client_fd, tls, protocol);
        }
      } else {
        uint32_t event = events[event_index].events;
        client_t *client = (client_t *)events[event_index].data.ptr;
        assert(((event & EPOLLIN) && client->protocol_state == PROTOCOL_READING) ||
               ((event & EPOLLOUT) && client->protocol_state == PROTOCOL_WRITING));

        if (event & EPOLLIN)
          handle_client_read(client);
        if (event & EPOLLOUT)
          handle_client_write(client);

        inline int draining(void)
        {
          if ((ret = client->write_buf_index == 0 ? 0 : EPOLLOUT) != 0)
            fprintf(stderr, "protocol_state: draining\n");
          return ret;
        }

        switch (client->protocol_state) {
        case PROTOCOL_READING:
          ret = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &(struct epoll_event){
            .events = EPOLLIN | draining() | EPOLLONESHOT,
            .data.ptr = client,
          });
          esprintf(ret, "epoll_ctl: EPOLL_CTL_MOD");
          break;
        case PROTOCOL_WRITING:
          ret = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &(struct epoll_event){
            .events = EPOLLOUT | EPOLLONESHOT,
            .data.ptr = client,
          });
          esprintf(ret, "epoll_ctl: EPOLL_CTL_MOD");
          break;
        case PROTOCOL_SHUTDOWN:
          fprintf(stderr, "PROTOCOL_SHUTDOWN\n");
          ret = tls_close(client->tls);
          if (ret < 0)
            fprintf(stderr, "tls_close: %s\n", tls_error(client->tls));
          tls_free(client->tls);

          ret = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client->fd, NULL);
          esprintf(ret, "epoll_ctl: EPOLL_CTL_DEL");

          ret = close(client->fd);
          esprintf(ret, "close: %d", client->fd);

          // protocol->terminate is reponsible for free'ing its own context,
          // closing open file descriptors, etc..
          (*client->protocol->terminate)(client->context);

          free(client);
          break;
        }
      }
    }
  }

  //

  tls_free(tls);

  return 0;
}
