/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2020, Jacob Hoffman-Andrews, <github@hoffman-andrews.com>
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "curl_setup.h"

#ifdef USE_RUSTLS

#include "curl_printf.h"

#include <errno.h>
#include <rustls.h>

#include "urldata.h"
#include "vtls.h"

struct ssl_backend_data
{
  struct rustls_client_session *session;
};

static const struct rustls_client_config *client_config = NULL;

static int
Curl_rustls_init(void)
{
  fprintf(stderr, "rustls begins!\n");
  client_config = rustls_client_config_new();
  return 1;
}

static size_t
Curl_rustls_version(char *buffer, size_t size)
{
  return msnprintf(buffer, size, "rustls");
}

static bool
Curl_rustls_data_pending(const struct connectdata *conn, int sockindex)
{
  const struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *backend = connssl->backend;
  return rustls_client_session_wants_read(backend->session);
}

static CURLcode
Curl_rustls_connect(struct connectdata *conn, int sockindex)
{
  fprintf(stderr, "rustls_connect: unimplemented\n");
  return CURLE_COULDNT_CONNECT;
}

static ssize_t
rustls_recv(struct connectdata *conn, int sockindex, char *buf, size_t len,
            CURLcode *err)
{
  fprintf(stderr, "rustls_recv: unimplemented\n");
  return -1;
}

static ssize_t
rustls_send(struct connectdata *conn, int sockindex, const void *buf,
            size_t len, CURLcode *err)
{
  fprintf(stderr, "rustls_send: unimplemented\n");
  return -1;
}

/*
 * Write n bytes from buf to the provided fd, retrying short writes until
 * we finish or hit an error. Assumes fd is blocking and therefore doesn't
 * handle EAGAIN. Returns 0 for success or 1 for error.
 */
int
write_all(int fd, const char *buf, int n)
{
  int m = 0;
  while(n > 0) {
    m = write(fd, buf, n);
    if(m < 0) {
      perror("writing to stdout");
      return 1;
    }
    if(m == 0) {
      fprintf(stderr, "early EOF when writing to stdout\n");
      return 1;
    }
    n -= m;
  }
  return 0;
}

static CURLcode
Curl_rustls_connect_nonblocking(struct connectdata *conn, int sockindex,
                                bool *done)
{
  int n = 0;
  int what = 0;
  int rustls_result = 0;
  uint8_t buf[2048];
  struct ssl_connect_data *const connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *const backend = connssl->backend;
  struct rustls_client_session *const session = backend->session;
  curl_socket_t sockfd = conn->sock[sockindex];
  struct Curl_easy *data = conn->data;

  /* Connection has already been established, and state machine has
   been updated. */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    DEBUGASSERT(!rustls_client_session_is_handshaking(session));
    return CURLE_OK;
  }

  if(rustls_client_session_wants_read(session)) {
    fprintf(stderr,
            "ClientSession wants us to read_tls. First we need to pull some "
            "bytes from the socket\n");

    bzero(buf, sizeof(buf));
    n = read(sockfd, buf, sizeof(buf));
    if(n == 0) {
      fprintf(stderr, "EOF reading from socket\n");
      return CURLE_COULDNT_CONNECT;
    }
    else if(n == EAGAIN || n == EWOULDBLOCK) {
      return CURLE_OK;
    }
    else if(n < 0) {
      perror("reading from socket");
      return CURLE_COULDNT_CONNECT;
    }
    fprintf(stderr, "read %d bytes from socket\n", n);

    /*
     * Now pull those bytes from the buffer into ClientSession.
     * Note that we pass buf, n; not buf, sizeof(buf). We don't
     * want to pull in unitialized memory that we didn't just
     * read from the socket.
     */
    n = rustls_client_session_read_tls(session, (uint8_t *)buf, n);
    if(n == 0) {
      fprintf(stderr, "EOF from ClientSession::read_tls\n");
      return CURLE_COULDNT_CONNECT;
    }
    else if(n < 0) {
      fprintf(stderr, "Error in ClientSession::read_tls\n");
      return CURLE_COULDNT_CONNECT;
    }

    rustls_result = rustls_client_session_process_new_packets(session);
    if(rustls_result != CRUSTLS_OK) {
      fprintf(stderr, "Error in process_new_packets");
      return CURLE_COULDNT_CONNECT;
    }
  }

  if(rustls_client_session_wants_write(session)) {
    fprintf(stderr, "ClientSession wants us to write_tls.\n");
    bzero(buf, sizeof(buf));
    n = rustls_client_session_write_tls(session, (uint8_t *)buf, sizeof(buf));
    if(n == 0) {
      fprintf(stderr, "EOF from ClientSession::write_tls\n");
      return CURLE_COULDNT_CONNECT;
    }
    else if(n < 0) {
      fprintf(stderr, "Error in ClientSession::write_tls\n");
      return CURLE_COULDNT_CONNECT;
    }

    rustls_result = write_all(sockfd, buf, n);
    if(rustls_result != 0) {
      fprintf(stderr, "Error in ClientSession::write_tls\n");
      return CURLE_COULDNT_CONNECT;
    }
  }

  /* Connection has been established according to rustls. Set send/recv
   handlers, and update the state machine. */
  if(!rustls_client_session_is_handshaking(session)) {
    /* Done with the handshake. Set up callbacks to send/receive data. */
    connssl->state = ssl_connection_complete;
    conn->recv[sockindex] = rustls_recv;
    conn->send[sockindex] = rustls_send;
    *done = TRUE;
    return CURLE_OK;
  }

  return CURLE_OK;
}

static void *
Curl_rustls_get_internals(struct ssl_connect_data *connssl,
                          CURLINFO info UNUSED_PARAM)
{
  struct ssl_backend_data *backend = connssl->backend;
  /* TODO: This is returning something unlikely to be recognized by the caller.
   But we can't leave this function blank. What to do? */
  return &backend->session;
}

static void
Curl_rustls_close(struct connectdata *conn, int sockindex)
{
  /* TODO */
}

static void
Curl_rustls_session_free(void *ptr)
{
  rustls_client_session_free(ptr);
}

const struct Curl_ssl Curl_ssl_rustls = {
  { CURLSSLBACKEND_RUSTLS, "rustls" },
  0, /* supports */
  sizeof(struct ssl_backend_data),

  Curl_none_init, /* init */
  Curl_none_cleanup, /* cleanup */
  Curl_rustls_version, /* version */
  Curl_none_check_cxn, /* check_cxn */
  Curl_none_shutdown, /* shutdown */
  Curl_rustls_data_pending, /* data_pending */
  Curl_none_random, /* random */
  Curl_none_cert_status_request, /* cert_status_request */
  Curl_rustls_connect, /* connect */
  Curl_rustls_connect_nonblocking, /* connect_nonblocking */
  Curl_rustls_get_internals, /* get_internals */
  Curl_rustls_close, /* close_one */
  Curl_none_close_all, /* close_all */
  Curl_rustls_session_free, /* session_free */
  Curl_none_set_engine, /* set_engine */
  Curl_none_set_engine_default, /* set_engine_default */
  Curl_none_engines_list, /* engines_list */
  Curl_none_false_start, /* false_start */
  Curl_none_md5sum, /* md5sum */
  NULL /* sha256sum */
};

#endif /* USE_RUSTLS */
