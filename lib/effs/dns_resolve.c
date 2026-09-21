// DNS
// ===

#include <arpa/inet.h>
#include <netdb.h>

// getaddrinfo blocks, so it rides io_work's helper thread: the loop
// stays free. Stable fail codes (the JS twin maps its UDP answer to
// the same table): 601 bad host, 602 host not found, 603 resolve
// failed (try again), 604 no IPv4 address, 605 resolve error.
static u32 dns_map(int gai) {
  switch (gai) {
    case EAI_NONAME: return 602;
    case EAI_AGAIN:  return 603;
#ifdef EAI_ADDRFAMILY
    case EAI_ADDRFAMILY: return 604;
#endif
#ifdef EAI_NODATA
    case EAI_NODATA: return 604;
#endif
    default: return 605;
  }
}

static const char* dns_msg(u32 code) {
  switch (code) {
    case 601: return "bad host";
    case 602: return "host not found";
    case 603: return "resolve failed, try again";
    case 604: return "no ipv4 address";
    default:  return "resolve error";
  }
}

// call has no Env: the host rides w->data (io_cstr'd in run), and the
// answer lands in w->text as a dotted quad.
static void dns_call(IoWork* w) {
  struct addrinfo  hints;
  struct addrinfo* res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  int gai = getaddrinfo(w->data, NULL, &hints, &res);
  if (gai != 0) {
    w->code = dns_map(gai);
  } else if (res == NULL) {
    w->code = 604;
  } else if (inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, w->text, 16) == NULL) {
    w->code = 605;
  } else {
    w->code = 0;
  }
  if (res != NULL) {
    freeaddrinfo(res);
  }
}

static Term dns_pack(Env e, IoWork* w) {
  Term r = w->code == 0
    ? io_done(e, io_str(e, w->text, strlen(w->text)))
    : io_fail(e, w->code, dns_msg(w->code));
  free(w->data);
  free(w->text);
  return r;
}

Term dns_lookup_run(Env e, Term* f, IoWork* w) {
  w->data = io_cstr(e, f[0], &w->size);
  w->text = io_mem(malloc(16));
  if (io_nul(w->data, w->size)) {
    w->code = 601;
    return dns_pack(e, w);
  }
  return io_work(w, dns_call, dns_pack);
}

static void __attribute__((constructor)) dns_lookup_use(void) {
  io_eff(CID_DNS_LOOKUP, dns_lookup_run, 0);
}
