#include <string.h>
#include <openssl/ssl.h>

int bend_tls_alpn_code(void *ssl) {
  const unsigned char *protocol = 0;
  unsigned length = 0;
  SSL_get0_alpn_selected(ssl, &protocol, &length);
  if (length == 2 && protocol != 0
    && protocol[0] == 'h' && protocol[1] == '2') {
    return 1;
  }
  if (length == 8 && protocol != 0
    && memcmp(protocol, "http/1.1", 8) == 0) {
    return 2;
  }
  return 0;
}
