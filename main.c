#include <assert.h>
#include <errno.h>
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

#define BUF_SIZE 65536

typedef void *(protocol_init_t)(void);
typedef size_t (protocol_read_t)(void *buf_head, size_t buf_size, void *ptr, int *want_write);
typedef size_t (protocol_write_t)(void *buf_head, size_t buf_size, void *ptr, int *want_read);

typedef struct protocol {
  int fd;
  protocol_init_t *init;
  protocol_read_t *read;
  protocol_write_t *write;
} protocol_t;

typedef struct client {
  int fd;
  struct tls *tls;
  uint8_t read_buf[BUF_SIZE];
  ptrdiff_t read_buf_index;
  uint8_t write_buf[BUF_SIZE];
  ptrdiff_t write_buf_index;
  //
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

  ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &(struct epoll_event){
    .events = EPOLLIN | EPOLLET,
    .data.ptr = client,
  });

  esprintf(ret, "epoll_ctl: EPOLL_CTL_ADD");

  fprintf(stderr, "new_client: %d\n", client->fd);
}

static void
handle_client_read(int epoll_fd, client_t *client) {
  int ret;
  size_t buf_length;
  size_t buf_handled;
  int want_write = 0;

  while (want_write == 0) {
    ret = tls_read(client->tls, client->read_buf + client->read_buf_index, (sizeof (client->read_buf)) - client->read_buf_index);
    if (ret == TLS_WANT_POLLIN)
      break;
    else if (ret < 0) {
      fprintf(stderr, "tls_read: %s\n", tls_error(client->tls));
      break;
    } else if (ret == 0) {
      ret = tls_close(client->tls);
      if (ret < 0)
        fprintf(stderr, "tls_close: %s\n", tls_error(client->tls));
      tls_free(client->tls);

      ret = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client->fd, NULL);
      esprintf(ret, "epoll_ctl: EPOLL_CTL_DEL");

      ret = close(client->fd);
      esprintf(ret, "close: %d", client->fd);

      /*
      ret = close(client->write_fd);
      esprintf(ret, "close: %d", client->write_fd);
      */

      free(client->context);
      free(client);
      break;
    } else {
      //fprintf(stderr, "tls_read: %d\n", ret);
      buf_length = client->read_buf_index + ret;
      buf_handled = (*client->protocol->read)(client->read_buf, buf_length, client->context, &want_write);

      memmove(client->read_buf, client->read_buf + buf_handled, buf_length - buf_handled);

      client->read_buf_index = buf_length - buf_handled;
    }
  }

  if (want_write != 0) {
    ret = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &(struct epoll_event){
      .events = EPOLLOUT | EPOLLET,
      .data.ptr = client,
    });
    esprintf(ret, "epoll_ctl: EPOLL_CTL_MOD");
  }
}

static void
handle_client_write(int epoll_fd, client_t *client)
{
  int ret;
  size_t buf_length;
  size_t buf_written;
  size_t write_length;
  int want_read = 0;

  fprintf(stderr, "handle_client_write\n");

  while (want_read == 0) {
    buf_length = (sizeof (client->write_buf)) - client->write_buf_index;
    buf_written = (*client->protocol->write)(client->write_buf + client->write_buf_index, buf_length, client->context, &want_read);

    write_length = client->write_buf_index + buf_written;

    if (write_length != 0) {
      ret = tls_write(client->tls, client->write_buf, write_length);
      if (ret == TLS_WANT_POLLOUT)
        break;
      else if (ret < 0) {
        fprintf(stderr, "tls_write: %s\n", tls_error(client->tls));
        break;
      } else {
        memmove(client->write_buf, client->write_buf + ret, write_length - ret);
        client->write_buf_index = write_length - ret;
      }
    }
  }

  if (want_read != 0) {
    ret = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &(struct epoll_event){
      .events = EPOLLIN | EPOLLET,
      .data.ptr = client,
    });
    esprintf(ret, "epoll_ctl: EPOLL_CTL_MOD");
  }
}

int
main(int argc, char *argv[])
{
  int ret;
  struct tls_config *tls_config;
  struct tls *tls;

  ret = tls_init();
  enprintf(ret, "tls_init");

  tls_config = tls_config_new();
  assert(tls_config != NULL && "tls_config_new");

  ret = tls_config_set_ca_file(tls_config, "/etc/ssl/cert.pem");
  enprintf(ret, "tls_config_set_ca_file: %s", "/etc/ssl/cert.pem");

  ret = tls_config_set_cert_file(tls_config, "localhost.crt.pem");
  enprintf(ret, "tls_config_set_cert_file: %s", "localhost.crt.pem");
  ret = tls_config_set_key_file(tls_config, "localhost.key.pem");
  enprintf(ret, "tls_config_set_key_file: %s", "localhost.key.pem");

  tls = tls_server();
  assert(tls != NULL && "tls_server");

  ret = tls_configure(tls, tls_config);
  enprintf(ret, "tls_configure");

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
    .fd = open_port(8000),
    .init = &binary_init,
    .read = &binary_read,
  };

  protocol_t http = {
    .fd = open_port(8443),
    .init = &http_init,
    .read = &http_read,
    .write = &http_write,
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

  ret = chdir("objects");
  esprintf(ret, "chdir");

  //

  int client_fd;
  struct epoll_event events[MAX_EVENTS];
  int event_index;
  void *event_ptr;

  while (1) {
    ret = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
    esprintf(ret, "epoll_wait");

    for (event_index = 0; event_index < ret; event_index++) {
      event_ptr = events[event_index].data.ptr;
      if (event_ptr == &binary || event_ptr == &http) {
        protocol_t *protocol = (protocol_t *)event_ptr;
        while (1) {
          ret = accept4(protocol->fd, NULL, NULL, SOCK_NONBLOCK);
          if (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
          esprintf(ret, "accept4");
          client_fd = ret;

          new_client(epoll_fd, client_fd, tls, protocol);
        }
      } else {
        uint32_t event = events[event_index].events;
        client_t *client = (client_t *)events[event_index].data.ptr;
        if (event & EPOLLIN)
          handle_client_read(epoll_fd, client);
        if (event & EPOLLOUT)
          handle_client_write(epoll_fd, client);
      }
    }
  }

  //

  tls_free(tls);
  tls_config_free(tls_config);

  return 0;
}
