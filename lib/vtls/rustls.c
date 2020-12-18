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
#include "sendf.h"
#include "vtls.h"

struct ssl_backend_data
{
  struct rustls_client_session *session;
  bool data_pending;
};

static const struct rustls_client_config *client_config = NULL;

static int
Curl_rustls_init(void)
{
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
  struct Curl_easy *data = conn->data;
  const struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *backend = connssl->backend;
  infof(data, "rustls_data_pending %d\n", backend->data_pending);
  return backend->data_pending;
}

static CURLcode
Curl_rustls_connect(struct connectdata *conn,
                    int sockindex UNUSED_PARAM)
{
  struct Curl_easy *data = conn->data;
  infof(data, "rustls_connect: unimplemented\n");
  return CURLE_COULDNT_CONNECT;
}

static ssize_t
rustls_recv(struct connectdata *conn, int sockindex, char *plainbuf,
            size_t plainlen, CURLcode *err)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *const connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *const backend = connssl->backend;
  struct rustls_client_session *const session = backend->session;
  curl_socket_t sockfd = conn->sock[sockindex];
  uint8_t tlsbuf[16384];
  ssize_t n = 0;
  ssize_t tls_bytes_read = 0;
  ssize_t tls_bytes_processed = 0;
  ssize_t plain_bytes_copied = 0;
  int rustls_result = 0;

  bzero(tlsbuf, sizeof(tlsbuf));
  tls_bytes_read = read(sockfd, tlsbuf, sizeof(tlsbuf));
  if(tls_bytes_read == 0) {
    failf(data, "rustls_recv: EOF reading from socket");
    *err = CURLE_READ_ERROR;
    return -1;
  }
  else if(tls_bytes_read < 0) {
    if(SOCKERRNO == EAGAIN || SOCKERRNO == EWOULDBLOCK) {
      infof(data, "rustls_recv: EAGAIN or EWOULDBLOCK\n");
      *err = CURLE_AGAIN;
      return 0;
    }
    failf(data, "rustls_recv: reading from socket: %s", strerror(SOCKERRNO));
    *err = CURLE_READ_ERROR;
    return -1;
  }
  infof(data, "rustls_recv: read %d bytes from socket\n", tls_bytes_read);

  /*
  * Now pull those bytes from the buffer into ClientSession.
  * Note that we pass tlsbuf, n; not tlsbuf, sizeof(tlsbuf). We don't
  * want to pull in unitialized memory that we didn't just
  * read from the socket.
  */
  while(tls_bytes_processed < tls_bytes_read) {
    n = rustls_client_session_read_tls(session,
      (uint8_t *)tlsbuf + tls_bytes_processed,
      tls_bytes_read - tls_bytes_processed);
    if(n == 0) {
      infof(data, "rustls_recv: EOF from rustls_client_session_read_tls\n");
      break;
    }
    else if(n < 0) {
      failf(data, "rustls_recv: error in rustls_client_session_read_tls");
      *err = CURLE_READ_ERROR;
      return -1;
    }

    rustls_result = rustls_client_session_process_new_packets(session);
    if(rustls_result != RUSTLS_RESULT_OK) {
      failf(data, "rustls_recv: error in process_new_packets");
      *err = CURLE_READ_ERROR;
      return -1;
    }

    tls_bytes_processed += n;
    backend->data_pending = TRUE;
  }

  while((size_t)plain_bytes_copied < plainlen) {
    n = rustls_client_session_read(session,
      (uint8_t *)plainbuf + plain_bytes_copied,
      plainlen - plain_bytes_copied);
    if(n == 0) {
      /* rustls returns 0 from client_session_read to mean "all currently
        available data has been read." If we bring in more ciphertext with
        read_tls, more plaintext will become available. So don't tell curl
        this is an EOF. Instead, say "come back later." */
      infof(data, "rustls_recv: EOF from rustls_client_session_read\n");
      backend->data_pending = FALSE;
      break;
    }
    else if(n < 0) {
      failf(data, "rustls_recv: error in rustls_client_session_read");
      *err = CURLE_READ_ERROR;
      return -1;
    }
    else {
      plain_bytes_copied += n;
    }
  }

  /* If we wrote out 0 plaintext bytes, it might just mean we haven't yet
     read a full TLS record. Return CURLE_AGAIN so curl doesn't treat this
     as EOF. */
  if(plain_bytes_copied == 0) {
    *err = CURLE_AGAIN;
    return -1;
  }

  return plain_bytes_copied;
}

/*
 * Write n bytes from buf to the provided fd, retrying short writes until
 * we finish or hit an error. Assumes fd is blocking and therefore doesn't
 * handle EAGAIN. Returns 0 for success or 1 for error.
 */
static int
write_all(int fd, const uint8_t *buf, size_t n)
{
  ssize_t m = 0;
  while(n > 0) {
    m = write(fd, buf, n);
    if(m < 0) {
      perror("writing to socket");
      return 1;
    }
    if(m == 0) {
      return 1;
    }
    if((size_t)m <= n) {
      n -= m;
    }
    else {
      /* too many bytes from write; would overflow. */
      return 1;
    }
  }
  return 0;
}

static ssize_t
rustls_send(struct connectdata *conn, int sockindex, const void *plainbuf,
            size_t plainlen, CURLcode *err)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *const connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *const backend = connssl->backend;
  struct rustls_client_session *const session = backend->session;
  curl_socket_t sockfd = conn->sock[sockindex];
  ssize_t n = 0;
  uint8_t tlsbuf[2048];
  int result = 0;

  infof(data, "rustls_send of %d bytes\n", plainlen);

  n = rustls_client_session_write(session, plainbuf, plainlen);
  if(n == 0) {
    failf(data, "rustls_send: EOF in write");
    *err = CURLE_WRITE_ERROR;
    return -1;
  }
  else if(n < 0) {
    failf(data, "rustls_send: error in write");
    *err = CURLE_WRITE_ERROR;
    return -1;
  }

  n = rustls_client_session_write_tls(session, tlsbuf, sizeof(tlsbuf));
  if(n == 0) {
    failf(data, "rustls_send: EOF in write_tls");
    *err = CURLE_WRITE_ERROR;
    return -1;
  }
  else if(n < 0) {
    failf(data, "rustls_send: error in write_tls");
    *err = CURLE_WRITE_ERROR;
    return -1;
  }


  infof(data, "rustls_send: writing %d\n", n);
  result = write_all(sockfd, tlsbuf, n);
  if(result != 0) {
    failf(data, "rustls_send: error in write_all");
    *err = CURLE_WRITE_ERROR;
    return -1;
  }

  infof(data, "rustls_send done: %d\n", n);
  return n;
}

static CURLcode
Curl_rustls_connect_nonblocking(struct connectdata *conn, int sockindex,
                                bool *done)
{
  struct Curl_easy *data = conn->data;
  ssize_t n = 0;
  int rustls_result = 0;
  uint8_t buf[6000]; /* TODO: Make this smaller */
  struct ssl_connect_data *const connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *const backend = connssl->backend;
  struct rustls_client_session *session = backend->session;
  curl_socket_t sockfd = conn->sock[sockindex];

  if(ssl_connection_none == connssl->state) {
    rustls_client_session_new(client_config, conn->host.name, &session);
    backend->session = session;
    connssl->state = ssl_connection_negotiating;
  }

  /* Connection has already been established, and state machine has
   been updated. */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    DEBUGASSERT(!rustls_client_session_is_handshaking(session));
    return CURLE_OK;
  }

  if(rustls_client_session_wants_write(session)) {
    infof(data, "ClientSession wants us to write_tls.\n");
    bzero(buf, sizeof(buf));
    n = rustls_client_session_write_tls(session, (uint8_t *)buf, sizeof(buf));
    if(n == 0) {
      infof(data, "EOF from ClientSession::write_tls\n");
      return CURLE_COULDNT_CONNECT;
    }
    else if(n < 0) {
      infof(data, "Error in ClientSession::write_tls\n");
      return CURLE_COULDNT_CONNECT;
    }

    rustls_result = write_all(sockfd, buf, n);
    if(rustls_result != 0) {
      infof(data, "Error in ClientSession::write_tls\n");
      return CURLE_COULDNT_CONNECT;
    }
  }

  if(rustls_client_session_wants_read(session)) {
    infof(data,
            "ClientSession wants us to read_tls. First we need to pull some "
            "bytes from the socket\n");

    bzero(buf, sizeof(buf));
    n = read(sockfd, buf, sizeof(buf));
    if(n == 0) {
      infof(data, "EOF reading from socket\n");
      return CURLE_COULDNT_CONNECT;
    }
    else if(n < 0) {
      if(SOCKERRNO == EAGAIN || SOCKERRNO == EWOULDBLOCK) {
        infof(data, "again!\n");
        return CURLE_OK;
      }
      perror("reading from socket");
      infof(data, "foo %d\n", n);
      return CURLE_COULDNT_CONNECT;
    }
    infof(data, "read %d bytes from socket\n", n);

    /*
     * Now pull those bytes from the buffer into ClientSession.
     * Note that we pass buf, n; not buf, sizeof(buf). We don't
     * want to pull in unitialized memory that we didn't just
     * read from the socket.
     */
    n = rustls_client_session_read_tls(session, (uint8_t *)buf, n);
    if(n == 0) {
      infof(data, "EOF from ClientSession::read_tls\n");
      return CURLE_COULDNT_CONNECT;
    }
    else if(n < 0) {
      infof(data, "Error in ClientSession::read_tls\n");
      return CURLE_COULDNT_CONNECT;
    }

    rustls_result = rustls_client_session_process_new_packets(session);
    if(rustls_result != RUSTLS_RESULT_OK) {
      infof(data, "Error in process_new_packets");
      return CURLE_COULDNT_CONNECT;
    }
  }

  /* TODO: For some reason, on the very first call is_handshaking is already
     returning false, even though in theory no I/O has been done. */
  /* Connection has been established according to rustls. Set send/recv
   handlers, and update the state machine. */
  if(!rustls_client_session_is_handshaking(session)) {
    infof(data, "Done handshaking\n");
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
Curl_rustls_close(struct connectdata *conn UNUSED_PARAM,
                  int sockindex UNUSED_PARAM)
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

  Curl_rustls_init, /* init */
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
