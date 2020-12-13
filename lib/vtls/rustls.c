#include "curl_setup.h"
#include "curl_printf.h"

#include <rustls.h>

#include "vtls.h"
#include "urldata.h"

struct ssl_backend_data {
    struct rustls_client_session *session;
};

static const struct rustls_client_config *client_config = NULL;

static int Curl_rustls_init(void) {
  client_config = rustls_client_config_new();
  return 1;
}

static size_t Curl_rustls_version(char *buffer, size_t size)
{
  return msnprintf(buffer, size, "rustls");
}

static bool Curl_rustls_data_pending(const struct connectdata *conn,
                                      int sockindex)
{
  const struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *backend = connssl->backend;
  return rustls_client_session_wants_read(backend->session);
}

static CURLcode Curl_rustls_connect(struct connectdata *conn, int sockindex)
{
  CURLcode ret = CURLE_COULDNT_CONNECT;
  bool done = FALSE;

  ret = bearssl_connect_common(conn, sockindex, FALSE, &done);
  if(ret)
    return ret;

  DEBUGASSERT(done);

  return CURLE_OK;
}

static CURLcode Curl_bearssl_connect_nonblocking(struct connectdata *conn,
                                                 int sockindex, bool *done)
{
  int n = 0;
  const uint8_t buf[2048];
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *backend = connssl->backend;
  curl_socket_t sockfd = conn->sock[sockindex];
  if (!rustls_client_session_is_handshaking(connssl->session)) {
      *done = TRUE;
      return CURLE_OK;
  } else if (rustls_client_session_wants_read(connssl->session) && ...) {
      fprintf(stderr,
              "ClientSession wants us to read_tls. First we need to pull some "
              "bytes from the socket\n");

      bzero(buf, sizeof(buf));
      n = read(sockfd, buf, sizeof(buf));
      if(n == 0) {
        fprintf(stderr, "EOF reading from socket\n");
        return CURLE_COULDNT_CONNECT;
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
      n = rustls_client_session_read_tls(client_session, (uint8_t *)buf, n);
      if(n == 0) {
        fprintf(stderr, "EOF from ClientSession::read_tls\n");
        // TODO: What to do here?
        break;
      }
      else if(n < 0) {
        fprintf(stderr, "Error in ClientSession::read_tls\n");
        goto cleanup;
      }

      result = rustls_client_session_process_new_packets(client_session);
      if(result != CRUSTLS_OK) {
        fprintf(stderr, "Error in process_new_packets");
        goto cleanup;
      }

      /* Read all available bytes from the client_session until EOF.
       * Note that EOF here indicates "no more bytes until
       * process_new_packets", not "stream is closed".
       */
      for(;;) {
        bzero(buf, sizeof(buf));
        n = rustls_client_session_read(
          client_session, (uint8_t *)buf, sizeof(buf));
        if(n == 0) {
          fprintf(stderr, "EOF from ClientSession::read (this is expected)\n");
          break;
        }
        else if(n < 0) {
          fprintf(stderr, "Error in ClientSession::read\n");
          goto cleanup;
        }

        result = write_all(STDOUT_FILENO, buf, n);
        if(result != 0) {
          goto cleanup;
        }
      }
  } else if (rustls_client_session_wants_write(connssl->session)) {
  }

  return bearssl_connect_common(conn, sockindex, TRUE, done);
}

static CURLcode bearssl_connect_common(struct connectdata *conn,
                                       int sockindex,
                                       bool nonblocking,
                                       bool *done)
{
  CURLcode ret;
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  curl_socket_t sockfd = conn->sock[sockindex];
  timediff_t timeout_ms;
  int what;

  /* check if the connection has already been established */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(ssl_connect_1 == connssl->connecting_state) {
    ret = bearssl_connect_step1(conn, sockindex);
    if(ret)
      return ret;
  }

  while(ssl_connect_2 == connssl->connecting_state ||
        ssl_connect_2_reading == connssl->connecting_state ||
        ssl_connect_2_writing == connssl->connecting_state) {
    /* check allowed time left */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    /* if ssl is expecting something, check if it's available. */
    if(ssl_connect_2_reading == connssl->connecting_state ||
       ssl_connect_2_writing == connssl->connecting_state) {

      curl_socket_t writefd = ssl_connect_2_writing ==
        connssl->connecting_state?sockfd:CURL_SOCKET_BAD;
      curl_socket_t readfd = ssl_connect_2_reading ==
        connssl->connecting_state?sockfd:CURL_SOCKET_BAD;

      what = Curl_socket_check(readfd, CURL_SOCKET_BAD, writefd,
                               nonblocking?0:timeout_ms);
      if(what < 0) {
        /* fatal error */
        failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        return CURLE_SSL_CONNECT_ERROR;
      }
      else if(0 == what) {
        if(nonblocking) {
          *done = FALSE;
          return CURLE_OK;
        }
        else {
          /* timeout */
          failf(data, "SSL connection timeout");
          return CURLE_OPERATION_TIMEDOUT;
        }
      }
      /* socket is readable or writable */
    }

    /* Run transaction, and return to the caller if it failed or if this
     * connection is done nonblocking and this loop would execute again. This
     * permits the owner of a multi handle to abort a connection attempt
     * before step2 has completed while ensuring that a client using select()
     * or epoll() will always have a valid fdset to wait on.
     */
    ret = bearssl_connect_step2(conn, sockindex);
    if(ret || (nonblocking &&
               (ssl_connect_2 == connssl->connecting_state ||
                ssl_connect_2_reading == connssl->connecting_state ||
                ssl_connect_2_writing == connssl->connecting_state)))
      return ret;
  }

  if(ssl_connect_3 == connssl->connecting_state) {
    ret = bearssl_connect_step3(conn, sockindex);
    if(ret)
      return ret;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    conn->recv[sockindex] = bearssl_recv;
    conn->send[sockindex] = bearssl_send;
    *done = TRUE;
  }
  else
    *done = FALSE;

  /* Reset our connect state machine */
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}


static void *Curl_bearssl_get_internals(struct ssl_connect_data *connssl,
                                        CURLINFO info UNUSED_PARAM)
{
  struct ssl_backend_data *backend = connssl->backend;
  return &backend->ctx;
}

static void Curl_bearssl_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *backend = connssl->backend;
  size_t i;

  if(backend->active) {
    br_ssl_engine_close(&backend->ctx.eng);
    (void)bearssl_run_until(conn, sockindex, BR_SSL_CLOSED);
  }
  for(i = 0; i < backend->anchors_len; ++i)
    free(backend->anchors[i].dn.data);
  free(backend->anchors);
}

static void Curl_bearssl_session_free(void *ptr)
{
  free(ptr);
}

static CURLcode Curl_bearssl_md5sum(unsigned char *input,
                                    size_t inputlen,
                                    unsigned char *md5sum,
                                    size_t md5len UNUSED_PARAM)
{
  br_md5_context ctx;

  br_md5_init(&ctx);
  br_md5_update(&ctx, input, inputlen);
  br_md5_out(&ctx, md5sum);
  return CURLE_OK;
}

static CURLcode Curl_bearssl_sha256sum(const unsigned char *input,
                                       size_t inputlen,
                                       unsigned char *sha256sum,
                                       size_t sha256len UNUSED_PARAM)
{
  br_sha256_context ctx;

  br_sha256_init(&ctx);
  br_sha256_update(&ctx, input, inputlen);
  br_sha256_out(&ctx, sha256sum);
  return CURLE_OK;
}

const struct Curl_ssl Curl_ssl_bearssl = {
  { CURLSSLBACKEND_RUSTLS, "rustls" },
  0, /* supports */
  sizeof(struct ssl_backend_data),

  Curl_none_init,
  Curl_none_cleanup,
  Curl_bearssl_version,
  Curl_none_check_cxn,
  Curl_none_shutdown,
  Curl_bearssl_data_pending,
  Curl_none_random,
  Curl_none_cert_status_request,
  Curl_bearssl_connect,
  Curl_bearssl_connect_nonblocking,
  Curl_bearssl_get_internals,
  Curl_bearssl_close,
  Curl_none_close_all,
  Curl_bearssl_session_free,
  Curl_none_set_engine,
  Curl_none_set_engine_default,
  Curl_none_engines_list,
  Curl_none_false_start,
  Curl_bearssl_md5sum,
  Curl_bearssl_sha256sum
};
