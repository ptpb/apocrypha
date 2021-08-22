#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include <gnutls/gnutls.h>

#include "error.h"
#include "http.h"
#include "native.h"
#include "protocol.h"
#include "config.h"

#define BUF_SIZE 0xffff

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
  gnutls_session_t session;
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
new_client(int epoll_fd, int client_fd, gnutls_priority_t priority, gnutls_certificate_credentials_t credentials, protocol_t *protocol) {
  client_t *client;
  int ret;

  client = calloc(1, (sizeof (client_t)));
  client->fd = client_fd;

  ret = gnutls_init(&client->session, GNUTLS_SERVER);
  enprintf(ret, "gnutls_init");
  ret = gnutls_priority_set(client->session, priority);
  enprintf(ret, "gnutls_priority_set");
  ret = gnutls_credentials_set(client->session, GNUTLS_CRD_CERTIFICATE, credentials);
  enprintf(ret, "gnutls_credentials_set");
  gnutls_certificate_server_set_request(client->session, GNUTLS_CERT_IGNORE);
  gnutls_transport_set_int(client->session, client_fd);

  client->context = (*protocol->init)();
  client->protocol = protocol;
  client->protocol_state = PROTOCOL_HANDSHAKE;

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

  while (client->protocol_state == PROTOCOL_HANDSHAKE) {
    ret = gnutls_handshake(client->session);
    if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN)
      break;
    else if (ret < 0) {
      fprintf(stderr, "gnutls_handshake: %s\n", gnutls_strerror(ret));
      client->protocol_state = PROTOCOL_SHUTDOWN;
    } else
      client->protocol_state = PROTOCOL_READING;
  }

  while (client->protocol_state == PROTOCOL_READING) {
    ret = gnutls_record_recv(client->session, client->read_buf + client->read_buf_index, (sizeof (client->read_buf)) - client->read_buf_index);
    if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN)
      break;
    else if (ret < 0) {
      fprintf(stderr, "gnutls_record_recv: %s\n", gnutls_strerror(ret));
      client->protocol_state = PROTOCOL_SHUTDOWN;
    } else if (ret == 0) {
      client->protocol_state = PROTOCOL_SHUTDOWN;
    } else {
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

  size_t write_offset = 0;
  while (client->protocol_state == PROTOCOL_WRITING) {
    if (client->protocol_state == PROTOCOL_WRITING) {
      protocol_ret = (*client->protocol->write)(client->write_buf + client->write_buf_index,
                                                (sizeof (client->write_buf)) - client->write_buf_index,
                                                client->context, &client->protocol_state);
      client->write_buf_index += protocol_ret;

      if (protocol_ret == 0 && client->write_buf_index == 0)
        return;
    }

    assert(client->write_buf_index != 0);

    write_offset = 0;
    int eagain = 0;

    while (write_offset != client->write_buf_index) {
      ret = gnutls_record_send(client->session, client->write_buf + write_offset, client->write_buf_index - write_offset);
      if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN) {
        eagain = 1;
        break;
      } else if (ret < 0) {
        fprintf(stderr, "gnutls_record_send: %s\n", gnutls_strerror(ret));
        client->protocol_state = PROTOCOL_SHUTDOWN;
        break;
      } else {
        write_offset += ret;
      }
    }

    memmove(client->write_buf, client->write_buf + write_offset, client->write_buf_index - write_offset);
    client->write_buf_index -= write_offset;
    if (eagain)
      break;
  }
}

void
load_tls_config(int dirfd, gnutls_certificate_credentials_t *credentials)
{
  int ret;

  ret = gnutls_certificate_allocate_credentials(credentials);
  enprintf(ret, "gnutls_certificate_allocate_credentials: %s\n", gnutls_strerror(ret));

  //

  ssize_t size;
  int fd;
  uint8_t buf[2][8092];
  const char *path[2] = {TLS_CERT, TLS_KEY};
  gnutls_datum_t datum[2];

  for (int i = 0; i < 2; i++) {
    fd = openat(dirfd, path[i], O_RDONLY);
    esprintf(fd, "open: %s", path[i]);

    size = read(fd, buf[i], (sizeof (buf)));
    esprintf(size, "read: %s", TLS_CERT);
    assert(size != (sizeof (buf[i])) && "tls_cert too large");

    ret = close(fd);
    esprintf(ret, "close");

    datum[i].data = buf[i];
    datum[i].size = size;
  }

  ret = gnutls_certificate_set_x509_key_mem(*credentials, &datum[0], &datum[1], GNUTLS_X509_FMT_PEM);
  enprintf(ret, "gnutls_certificate_set_x509_key_mem: %s\n", gnutls_strerror(ret));
  //
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
  gnutls_priority_t priority;
  gnutls_certificate_credentials_t credentials;

  //

  int dirfd;
  dirfd = open(".", O_DIRECTORY);
  esprintf(dirfd, "open: .");

  ret = chdir("objects");
  esprintf(ret, "chdir: %s", "objects");

  //

  ret = gnutls_global_init();
  enprintf(ret, "gnutls_global_init: %s\n", gnutls_strerror(ret));

  ret = gnutls_priority_init(&priority, NULL, NULL);
  enprintf(ret, "gnutls_priority_init: %s\n", gnutls_strerror(ret));
  load_tls_config(dirfd, &credentials);
  //

  int
  open_port(const char *name, uint16_t port)
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

    socklen_t socklen = (sizeof (struct sockaddr_in6));
    ret = getsockname(fd, (struct sockaddr *)&sockaddr, &socklen);
    esprintf(ret, "getsockname");
    fprintf(stderr, "protocol %s listening on port %d\n", name, ntohs(sockaddr.sin6_port));

    ret = listen(fd, 1024);
    esprintf(ret, "listen");

    return fd;
  }

  protocol_t binary = {
    .fd = open_port("native+tls", NATIVE_PORT),
    .init = &binary_init,
    .read = &binary_read,
    .write = &binary_write,
    .terminate = &binary_terminate,
  };

  protocol_t http = {
    .fd = open_port("http+tls", HTTP_PORT),
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
      gnutls_certificate_free_credentials(credentials);
      load_tls_config(dirfd, &credentials);
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
          client_fd = ret;

          new_client(epoll_fd, client_fd, priority, credentials, protocol);
        }
      } else {
        uint32_t event = events[event_index].events;
        client_t *client = (client_t *)events[event_index].data.ptr;
        assert(((event & EPOLLIN) && (client->protocol_state == PROTOCOL_READING
                                      || client->protocol_state == PROTOCOL_HANDSHAKE))
               || ((event & EPOLLOUT) && client->protocol_state == PROTOCOL_WRITING));

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
        case PROTOCOL_HANDSHAKE:
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
          fprintf(stderr, "PROTOCOL_SHUTDOWN %p\n", client);
          ret = gnutls_bye(client->session, GNUTLS_SHUT_WR);
          if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
            continue;
          if (ret < 0)
            fprintf(stderr, "gnutls_bye: %s\n", gnutls_strerror(ret));
          gnutls_deinit(client->session);

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

  gnutls_certificate_free_credentials(credentials);
  gnutls_priority_deinit(priority);
  gnutls_global_deinit();

  return 0;
}
