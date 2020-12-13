#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define CRUSTLS_OK 0

#define CRUSTLS_ERROR 1

typedef int CrustlsResult;

/**
 * Create a client_config. Caller owns the memory and must free it with
 * rustls_client_config_free.
 */
const void *rustls_client_config_new(void);

/**
 * "Free" a client_config previously returned from rustls_client_config_new.
 * Since client_config is actually an atomically reference-counted pointer,
 * extant client_sessions may still hold an internal reference to the
 * Rust object. However, C code must consider this pointer unusable after
 * "free"ing it.
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_client_config_free(const void *config);

/**
 * Create a new rustls::ClientSession, and return it in the output parameter `out`.
 * If this returns an error code, the memory pointed to by `session_out` remains unchanged.
 * If this returns a non-error, the memory pointed to by `session_out` is modified to point
 * at a valid ClientSession. The caller now owns the ClientSession and must call
 * `rustls_client_session_free` when done with it.
 */
CrustlsResult rustls_client_session_new(const void *config,
                                        const char *hostname,
                                        void **session_out);

bool rustls_client_session_wants_read(const void *session);

bool rustls_client_session_wants_write(const void *session);

CrustlsResult rustls_client_session_process_new_packets(void *session);

/**
 * Free a client_session previously returned from rustls_client_session_new.
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_client_session_free(void *session);

/**
 * Write plaintext bytes into the ClientSession. This acts like
 * write(2). It returns the number of bytes written, or -1 on error.
 */
ssize_t rustls_client_session_write(const void *session, const uint8_t *buf, size_t count);

/**
 * Read plaintext bytes from the ClientSession. This acts like
 * read(2), writing the plaintext bytes into `buf`. It returns
 * the number of bytes read, or -1 on error.
 */
ssize_t rustls_client_session_read(const void *session, uint8_t *buf, size_t count);

/**
 * Read TLS bytes taken from a socket into the ClientSession. This acts like
 * read(2). It returns the number of bytes read, or -1 on error.
 */
ssize_t rustls_client_session_read_tls(const void *session, const uint8_t *buf, size_t count);

/**
 * Write TLS bytes from the ClientSession into a buffer. Those bytes should then be written to
 * a socket. This acts like write(2). It returns the number of bytes read, or -1 on error.
 */
ssize_t rustls_client_session_write_tls(const void *session, uint8_t *buf, size_t count);
