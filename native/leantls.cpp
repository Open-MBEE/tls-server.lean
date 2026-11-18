// A TLS server for Lean over OpenSSL: a listening socket, a server context from a certificate and
// its key, accepted connections read and written, and a self-signed certificate made on the spot.
// Every function answers an `EIO String` value: the error is a message.
#include <lean/lean.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static lean_external_class *g_tls_ctx_class = nullptr;
static lean_external_class *g_tls_conn_class = nullptr;

struct Conn {
  SSL *ssl;
  int fd;
  bool eof;
};

// A connection accepted and in its handshake, on the stack of its accept.
struct Pending {
  int fd;
  Pending *next;
};

// `mu` guards fd, accepting, closed and pending; the descriptor is closed only when no accept is using it.
struct Lst {
  pthread_mutex_t mu;
  Pending *pending;
  int fd;
  int accepting;
  bool closed;
  uint16_t port;
};

static lean_external_class *g_tls_lst_class = nullptr;

// The error: `what`, then OpenSSL's pending error or errno when either says more. The functions do not
// use the C++ standard library, as Lean's linker does not link it.
static lean_object *fail(const char *what, const char *subject = nullptr) {
  char msg[512];
  int n = subject ? snprintf(msg, sizeof msg, "%s %s", what, subject) : snprintf(msg, sizeof msg, "%s", what);
  if (n < 0) n = 0;
  if ((size_t)n > sizeof msg - 1) n = sizeof msg - 1;
  unsigned long e = ERR_get_error();
  if (e != 0) {
    char buf[256];
    ERR_error_string_n(e, buf, sizeof buf);
    snprintf(msg + n, sizeof msg - n, ": %s", buf);
  } else if (errno != 0) {
    snprintf(msg + n, sizeof msg - n, ": %s", strerror(errno));
  }
  ERR_clear_error();
  return lean_io_result_mk_error(lean_mk_string(msg));
}

static void ctx_finalizer(void *p) { SSL_CTX_free(static_cast<SSL_CTX *>(p)); }
static void conn_finalizer(void *p) {
  Conn *c = static_cast<Conn *>(p);
  if (c->ssl) SSL_free(c->ssl);
  if (c->fd >= 0) close(c->fd);
  free(c);
}
static void lst_finalizer(void *p) {
  Lst *l = static_cast<Lst *>(p);
  if (l->fd >= 0) close(l->fd);
  pthread_mutex_destroy(&l->mu);
  free(l);
}
static void noop_foreach(void *, b_lean_obj_arg) {}

// Once, whichever task comes first: OpenSSL, the three external classes, and SIGPIPE ignored — a peer
// gone before a write then makes SSL_write fail (reported by `write`) instead of ending the process.
static pthread_once_t g_tls_once = PTHREAD_ONCE_INIT;
static void initialize_once() {
  SSL_library_init();
  SSL_load_error_strings();
  g_tls_ctx_class = lean_register_external_class(ctx_finalizer, noop_foreach);
  g_tls_conn_class = lean_register_external_class(conn_finalizer, noop_foreach);
  g_tls_lst_class = lean_register_external_class(lst_finalizer, noop_foreach);
  signal(SIGPIPE, SIG_IGN);
}
static void initialize() { pthread_once(&g_tls_once, initialize_once); }

// A PEM file written whole: created with `mode` (the key 0600, the certificate 0644), truncated, the
// writer run, and fclose's verdict counted, since a buffered write can fail only then.
template <typename W> static bool write_pem(const char *path, mode_t mode, W writer) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
  if (fd < 0) return false;
  if (fchmod(fd, mode) != 0) { close(fd); return false; }
  FILE *f = fdopen(fd, "w");
  if (!f) { close(fd); return false; }
  bool ok = writer(f) != 0;
  if (fclose(f) != 0) ok = false;
  return ok;
}

// lean_tls_self_signed cn san days certPath keyPath: an RSA-2048 key and a self-signed X.509 v3
// certificate for `cn` with the subjectAltName `san` (e.g. "IP:127.0.0.1,DNS:localhost"), valid
// `days` days from now, written as PEM to the two paths. RFC 5280: version (§4.1.2.1), serial
// (§4.1.2.2), issuer = subject (§4.1.2.4, §4.1.2.6), validity (§4.1.2.5), subjectAltName (§4.2.1.6),
// basicConstraints (§4.2.1.9), subjectKeyIdentifier (§4.2.1.2); PEM per RFC 7468.
extern "C" LEAN_EXPORT lean_object *lean_tls_self_signed(b_lean_obj_arg cn, b_lean_obj_arg san, uint32_t days,
                                                          b_lean_obj_arg certPath, b_lean_obj_arg keyPath,
                                                          lean_obj_arg /* w */) {
  initialize();
  errno = 0;
  EVP_PKEY *key = EVP_RSA_gen(2048);
  if (!key) return fail("key generation failed");
  X509 *crt = X509_new();
  if (!crt) { EVP_PKEY_free(key); return fail("certificate allocation failed"); }
  X509_set_version(crt, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(crt), (long)time(nullptr));
  X509_gmtime_adj(X509_getm_notBefore(crt), 0);
  X509_gmtime_adj(X509_getm_notAfter(crt), (long)days * 24 * 60 * 60);
  X509_set_pubkey(crt, key);
  X509_NAME *name = X509_get_subject_name(crt);
  if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)lean_string_cstr(cn), -1, -1, 0) != 1) {
    X509_free(crt); EVP_PKEY_free(key); return fail("common name rejected:", lean_string_cstr(cn));
  }
  X509_set_issuer_name(crt, name);
  X509V3_CTX v3;
  X509V3_set_ctx_nodb(&v3);
  X509V3_set_ctx(&v3, crt, crt, nullptr, nullptr, 0);
  const char *exts[][2] = {{"subjectAltName", lean_string_cstr(san)}, {"basicConstraints", "critical,CA:TRUE"},
                           {"subjectKeyIdentifier", "hash"}};
  for (auto &e : exts) {
    X509_EXTENSION *x = X509V3_EXT_conf(nullptr, &v3, e[0], e[1]);
    if (!x) { X509_free(crt); EVP_PKEY_free(key); return fail("extension failed:", e[0]); }
    X509_add_ext(crt, x, -1);
    X509_EXTENSION_free(x);
  }
  if (X509_sign(crt, key, EVP_sha256()) == 0) { X509_free(crt); EVP_PKEY_free(key); return fail("signing failed"); }
  bool keyOk = write_pem(lean_string_cstr(keyPath), 0600, [&](FILE *f) {
    return PEM_write_PrivateKey(f, key, nullptr, nullptr, 0, nullptr, nullptr);
  });
  if (!keyOk) { X509_free(crt); EVP_PKEY_free(key); return fail("writing failed:", lean_string_cstr(keyPath)); }
  bool crtOk = write_pem(lean_string_cstr(certPath), 0644, [&](FILE *f) { return PEM_write_X509(f, crt); });
  if (!crtOk) { X509_free(crt); EVP_PKEY_free(key); return fail("writing failed:", lean_string_cstr(certPath)); }
  X509_free(crt);
  EVP_PKEY_free(key);
  return lean_io_result_mk_ok(lean_box(0));
}

// lean_tls_listen host port: a TCP socket bound to `host:port` (port 0 for any free one), listening —
// a Listener, closed when it is dropped or by lean_tls_listener_close.
extern "C" LEAN_EXPORT lean_object *lean_tls_listen(b_lean_obj_arg host, uint32_t port, lean_obj_arg /* w */) {
  initialize();
  errno = 0;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return fail("socket failed");
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, lean_string_cstr(host), &addr.sin_addr) != 1) { close(fd); return fail("not an IPv4 address"); }
  if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) { int e = errno; close(fd); errno = e; return fail("bind failed"); }
  if (listen(fd, 16) != 0) { int e = errno; close(fd); errno = e; return fail("listen failed"); }
  socklen_t len = sizeof addr;
  if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) { int e = errno; close(fd); errno = e; return fail("getsockname failed"); }
  Lst *l = (Lst *)malloc(sizeof *l);
  pthread_mutex_init(&l->mu, nullptr);
  l->fd = fd;
  l->accepting = 0;
  l->pending = nullptr;
  l->closed = false;
  l->port = ntohs(addr.sin_port);
  return lean_io_result_mk_ok(lean_alloc_external(g_tls_lst_class, l));
}

// lean_tls_listener_port l: the port the listener is bound to.
extern "C" LEAN_EXPORT uint32_t lean_tls_listener_port(b_lean_obj_arg lst) {
  return static_cast<Lst *>(lean_get_external_data(lst))->port;
}

// lean_tls_listener_close l: the listening socket closed; a later accept fails, and one in progress is
// woken by shutdown, whether it waits for a connection or for its handshake.
extern "C" LEAN_EXPORT lean_object *lean_tls_listener_close(b_lean_obj_arg lst, lean_obj_arg /* w */) {
  Lst *l = static_cast<Lst *>(lean_get_external_data(lst));
  pthread_mutex_lock(&l->mu);
  if (!l->closed) {
    l->closed = true;
    if (l->accepting > 0) shutdown(l->fd, SHUT_RDWR);
    else { close(l->fd); l->fd = -1; }
    for (Pending *p = l->pending; p; p = p->next) shutdown(p->fd, SHUT_RDWR);
  }
  pthread_mutex_unlock(&l->mu);
  return lean_io_result_mk_ok(lean_box(0));
}

// lean_tls_server_context certPath keyPath: a TLS server context presenting that certificate.
extern "C" LEAN_EXPORT lean_object *lean_tls_server_context(b_lean_obj_arg certPath, b_lean_obj_arg keyPath,
                                                             lean_obj_arg /* w */) {
  initialize();
  errno = 0;
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx) return fail("SSL_CTX_new failed");
  // TLS 1.2 (RFC 5246) or 1.3 (RFC 8446) and nothing below; no CertificateRequest (RFC 8446 §4.3.2 /
  // RFC 5246 §7.4.4), so clients are not authenticated.
  if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) { SSL_CTX_free(ctx); return fail("TLS 1.2 minimum refused"); }
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
  if (SSL_CTX_use_certificate_chain_file(ctx, lean_string_cstr(certPath)) != 1) { SSL_CTX_free(ctx); return fail("certificate rejected"); }
  if (SSL_CTX_use_PrivateKey_file(ctx, lean_string_cstr(keyPath), SSL_FILETYPE_PEM) != 1) { SSL_CTX_free(ctx); return fail("key rejected"); }
  if (SSL_CTX_check_private_key(ctx) != 1) { SSL_CTX_free(ctx); return fail("key does not match the certificate"); }
  return lean_io_result_mk_ok(lean_alloc_external(g_tls_ctx_class, ctx));
}

// lean_tls_accept ctx l: the next connection on the listener, its TLS handshake (RFC 8446 §4 /
// RFC 5246 §7.4) done by SSL_accept.
extern "C" LEAN_EXPORT lean_object *lean_tls_accept(b_lean_obj_arg ctx, b_lean_obj_arg lst, lean_obj_arg /* w */) {
  errno = 0;
  Lst *l = static_cast<Lst *>(lean_get_external_data(lst));
  pthread_mutex_lock(&l->mu);
  if (l->closed) { pthread_mutex_unlock(&l->mu); return fail("listener closed"); }
  int fd = l->fd;
  l->accepting++;
  pthread_mutex_unlock(&l->mu);
  int c = accept(fd, nullptr, nullptr);
  int e = errno;
  pthread_mutex_lock(&l->mu);
  bool closed = l->closed;
  if (--l->accepting == 0 && closed && l->fd >= 0) { close(l->fd); l->fd = -1; }
  Pending self = {c, l->pending};
  if (c >= 0 && !closed) l->pending = &self;
  pthread_mutex_unlock(&l->mu);
  if (closed) { if (c >= 0) close(c); errno = 0; return fail("listener closed"); }
  if (c < 0) { errno = e; return fail("accept failed"); }
  SSL *ssl = SSL_new(static_cast<SSL_CTX *>(lean_get_external_data(ctx)));
  if (ssl) SSL_set_fd(ssl, c);
  ERR_clear_error();
  bool ok = ssl && SSL_accept(ssl) == 1;
  pthread_mutex_lock(&l->mu);
  for (Pending **p = &l->pending; *p; p = &(*p)->next)
    if (*p == &self) { *p = self.next; break; }
  closed = l->closed;
  pthread_mutex_unlock(&l->mu);
  if (!ok) {
    if (ssl) SSL_free(ssl);
    close(c);
    if (closed) { ERR_clear_error(); errno = 0; return fail("listener closed"); }
    return fail(ssl ? "handshake failed" : "SSL_new failed");
  }
  Conn *conn = (Conn *)malloc(sizeof *conn);
  conn->ssl = ssl;
  conn->fd = c;
  conn->eof = false;
  return lean_io_result_mk_ok(lean_alloc_external(g_tls_conn_class, conn));
}

// OpenSSL 3 reports a TCP close without close_notify as this SSL error, not as SSL_ERROR_SYSCALL.
static bool unexpected_eof() {
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
  unsigned long e = ERR_peek_error();
  return ERR_GET_LIB(e) == ERR_LIB_SSL && ERR_GET_REASON(e) == SSL_R_UNEXPECTED_EOF_WHILE_READING;
#else
  return false;
#endif
}

// lean_tls_read conn max: up to `max` bytes of application data (RFC 8446 §5.1 / RFC 5246 §6.2); empty
// once the peer has closed, and at every read after that: its close_notify (RFC 8446 §6.1 / RFC 5246 §7.2.1, SSL_ERROR_ZERO_RETURN)
// or its TCP connection gone (SSL_ERROR_SYSCALL with 0, or OpenSSL 3's unexpected-EOF error).
extern "C" LEAN_EXPORT lean_object *lean_tls_read(b_lean_obj_arg conn, uint32_t max, lean_obj_arg /* w */) {
  errno = 0;
  Conn *c = static_cast<Conn *>(lean_get_external_data(conn));
  if (!c->ssl) return fail("connection closed");
  lean_object *bytes = lean_alloc_sarray(1, 0, max);
  if (c->eof) return lean_io_result_mk_ok(bytes);
  ERR_clear_error();
  int n = SSL_read(c->ssl, lean_sarray_cptr(bytes), (int)max);
  if (n <= 0) {
    int err = SSL_get_error(c->ssl, n);
    if (err == SSL_ERROR_ZERO_RETURN || (err == SSL_ERROR_SYSCALL && n == 0) ||
        (err == SSL_ERROR_SSL && unexpected_eof())) {
      c->eof = true;
      ERR_clear_error();
      return lean_io_result_mk_ok(bytes);
    }
    lean_dec(bytes);
    return fail("read failed");
  }
  lean_sarray_set_size(bytes, n);
  return lean_io_result_mk_ok(bytes);
}

// lean_tls_write conn bytes: all of `bytes` to the connection.
extern "C" LEAN_EXPORT lean_object *lean_tls_write(b_lean_obj_arg conn, b_lean_obj_arg bytes, lean_obj_arg /* w */) {
  errno = 0;
  Conn *c = static_cast<Conn *>(lean_get_external_data(conn));
  if (!c->ssl) return fail("connection closed");
  size_t size = lean_sarray_size(bytes), done = 0;
  const uint8_t *data = lean_sarray_cptr(bytes);
  while (done < size) {
    ERR_clear_error();
    int n = SSL_write(c->ssl, data + done, (int)(size - done));
    if (n <= 0) return fail("write failed");
    done += n;
  }
  return lean_io_result_mk_ok(lean_box(0));
}

// lean_tls_close conn: the TLS session shut down — SSL_shutdown sends close_notify (RFC 8446 §6.1 /
// RFC 5246 §7.2.1), the peer's is not awaited — and the socket closed; later reads and writes fail
// with "connection closed".
extern "C" LEAN_EXPORT lean_object *lean_tls_close(b_lean_obj_arg conn, lean_obj_arg /* w */) {
  Conn *c = static_cast<Conn *>(lean_get_external_data(conn));
  if (c->ssl) {
    ERR_clear_error();
    SSL_shutdown(c->ssl);
    ERR_clear_error();
    SSL_free(c->ssl);
    c->ssl = nullptr;
  }
  if (c->fd >= 0) { close(c->fd); c->fd = -1; }
  return lean_io_result_mk_ok(lean_box(0));
}
