#include "general.h"
#include "errors.h"
#include "secmem.h"
#include "log.h"
#include "dns.h"
#include "crypto.h"
#include "cert_struct.h"
#include "cert_chk.h"
#include "usock.h"
#include "futils.h"
#include "utils.h"
#include "key_rw.h"
#include "packets_struct.h"
#include "packets.h"
#include "keygen.h"
#include "sqlite3.h"
#include "db.h"
#include "query.h"
#include "err_conv.h"
#include "shared_list.h"
#include "active_buf.h"
#include "zlib.h"
#include "base64.h"

#include "cwcli.h"

extern CW_CLIENT *cli;

static CWERROR _get_user_info(CW_EXTERNAL_USER_INFO *res, const CW_UINT32 sid, const CW_UINT32 uid) {
  CW_UINT32 sid_uid[2] = {sid, uid};
  int pckt_len;
  CW_PACKET_TYPE pckt_t;
  CW_UINT8 buf[max(sizeof(CW_EXTERNAL_USER_INFO), sizeof(CW_ERROR_PACKET))];
  CW_EXTERNAL_USER_INFO *info = (CW_EXTERNAL_USER_INFO *) buf;
  CW_ERROR_PACKET *serv_err = (CW_ERROR_PACKET *) buf;
  CWERROR err = CW_ER_OK;

  pthread_mutex_lock(&cli->api_mtx);

  if ((err = packet_send_crypted(&cli->srv_pctx, &sid_uid, sizeof(sid_uid), PT_GET_USER_INFO)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = packet_recv_crypted(&cli->srv_pctx, buf, sizeof(buf), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_t == PT_ERROR) && (pckt_len == sizeof(CW_ERROR_PACKET)) && (serv_err->code == PE_NO_QUERIED_INFO)) {
    err = CW_ER_NO_QUERIED_INFO;
    goto err_exit;
  } else if ((pckt_t != PT_GET_USER_INFO_RESP) || (pckt_len != sizeof(CW_EXTERNAL_USER_INFO))) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }

  /* check certificate if exists */
  if (info->has_cert) {
    if ((err = cert_check(&info->cert, &cli->root_cert.ku, CT_USER)) != CW_ER_OK) {
      DEBUG_ERROR();
      goto err_exit;
    }
  }

  memcpy(res, info, sizeof(CW_EXTERNAL_USER_INFO));

  err_exit:

  pthread_mutex_unlock(&cli->api_mtx);

  return err;
}

static CWERROR _get_server_info(CW_SERVER_INFO *res, const CW_UINT32 sid) {
  int pckt_len;
  CW_PACKET_TYPE pckt_t;
  CW_UINT8 buf[max(sizeof(CW_SERVER_INFO), sizeof(CW_ERROR_PACKET))];
  CW_SERVER_INFO *info = (CW_SERVER_INFO *) buf;
  CW_ERROR_PACKET *serv_err = (CW_ERROR_PACKET *) buf;
  CWERROR err = CW_ER_OK;

  pthread_mutex_lock(&cli->api_mtx);

  if ((err = packet_send_crypted(&cli->srv_pctx, &sid, sizeof(sid), PT_GET_SERVER_INFO)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = packet_recv_crypted(&cli->srv_pctx, buf, sizeof(buf), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_t == PT_ERROR) && (pckt_len == sizeof(CW_ERROR_PACKET)) && (serv_err->code == PE_NO_QUERIED_INFO)) {
    err = CW_ER_NO_QUERIED_INFO;
    goto err_exit;
  } else if ((pckt_t != PT_GET_SERVER_INFO_RESP) || (pckt_len != sizeof(CW_SERVER_INFO))) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }

  if ((err = cert_check(&info->cert, &cli->root_cert.ku, CT_SERVER)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  memcpy(res, info, sizeof(CW_SERVER_INFO));

  err_exit:

  pthread_mutex_unlock(&cli->api_mtx);

  return err;
}

THREAD_PROC(_ping_thrd_proc)
    {
        CW_UINT32 tmp = QRND();

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    while (TRUE) {
      delay(cli->ping_timeout * 1000);
      pthread_mutex_lock(&cli->api_mtx);
      packet_send_crypted(&cli->srv_pctx, &tmp, sizeof(tmp), PT_PING);
      pthread_mutex_unlock(&cli->api_mtx);
    }

    return THREAD_RET;
    }

static CWERROR _connect_direct(SOCKET sock,
                               const char *serv_addr,
                               const CW_UINT16 serv_port) {
  SOCKADDR_IN addr;
  int sz = sizeof(addr);
  char ip_str[MAX_IP_LEN];
  unsigned long ip_ulong;

  if (!resolve_ip(ip_str, serv_addr)) {
    DEBUG_ERROR();
    return CW_ER_SOCKET;
  }

  memset(&addr, 0, sizeof(addr));

  addr.sin_family = AF_INET;
  addr.sin_port = htons(serv_port);
  ip_ulong = inet_addr(ip_str);

  memcpy(&addr.sin_addr, &ip_ulong, sizeof(ip_ulong));

  if (connect(sock, (struct sockaddr *) &addr, sz)) {
    DEBUG_ERROR();
    return CW_ER_SOCKET;
  }

  return CW_ER_OK;
}

static CWERROR _connect_http(SOCKET sock,
                             const char *serv_addr,
                             const CW_UINT16 serv_port,
                             const char *proxy_addr,
                             const CW_UINT16 proxy_port,
                             const char *proxy_user,
                             const char *proxy_passwd,
                             const long recv_timeout) {
  static const char emp[3] = {'\x0D', '\x0A', '\0'};

  SOCKADDR_IN addr;
  int sz = sizeof(addr), r, n;
  char buf[1024], auth[100], *auth_base = NULL;
  char ip_str[MAX_IP_LEN];
  unsigned long ip_ulong;

  if (!resolve_ip(ip_str, proxy_addr)) {
    DEBUG_ERROR();
    return CW_ER_SOCKET;
  }

  memset(&addr, 0, sizeof(addr));

  addr.sin_family = AF_INET;
  addr.sin_port = htons(proxy_port);
  ip_ulong = inet_addr(ip_str);
  memcpy(&addr.sin_addr, &ip_ulong, sizeof(ip_ulong));

  if (connect(sock, (struct sockaddr *) &addr, sz)) {
    DEBUG_ERROR();
    return CW_ER_SOCKET;
  }

  if (proxy_user == NULL) {
    sprintf(buf,
            "CONNECT %s:%u HTTP/1.0\x0D\x0AUser-agent: Mozilla/4.0\x0D\x0AProxy-Connection: Keep-Alive\x0D\x0A\x0D\x0A",
            serv_addr, serv_port);
  } else {
    sprintf(auth, "%s:%s", proxy_user, proxy_passwd);
    n = base64_encode_alloc(auth, strlen(auth), &auth_base);
    if (auth_base == NULL) {
      DEBUG_ERROR();
      return CW_ER_MEMORY;
    }
    sprintf(buf,
            "CONNECT %s:%u HTTP/1.0\x0D\x0AUser-agent: Mozilla/4.0\x0D\x0AProxy-Connection: Keep-Alive\x0D\x0AProxy-authorization: Basic %s\x0D\x0A\x0D\x0A",
            serv_addr, serv_port, auth_base);
    FREE(auth_base);
  }
  n = strlen(buf);

  sz = n;
  if (send_buf(sock, buf, &sz) == SOCK_ER_SEND) {
    DEBUG_ERROR();
    return CW_ER_SEND;
  }
  if (sz != n) {
    DEBUG_ERROR();
    return CW_ER_SEND;
  }

  memset(buf, 0, sizeof(buf));
  n = 1;
  do {
    sz = 1;
    r = recv_buf(sock, &buf[n], &sz, recv_timeout);
    if (r <= 0) {
      if (r == SOCK_ER_RECV_TIMEOUT) {
        return CW_ER_RECV_TIMEOUT;
      } else if ((r == SOCK_ER_RECV_DISCONN) || (r == SOCK_ER_RECV) || (sz != 1)) {
        DEBUG_ERROR();
        return CW_ER_RECV;
      }
    }
  }while ((buf[n - 1] != '\x0D') && (buf[n++] != '\x0A'));

  if (strstr(&buf[1], "HTTP/1.0 200") != NULL) {
    do {
      memset(buf, 0, sizeof(buf));
      n = 1;
      do {
        sz = 1;
        r = recv_buf(sock, &buf[n], &sz, recv_timeout);
        if (r <= 0) {
          if (r == SOCK_ER_RECV_TIMEOUT) {
            return CW_ER_RECV_TIMEOUT;
          } else if ((r == SOCK_ER_RECV_DISCONN) || (r == SOCK_ER_RECV) || (sz != 1)) {
            DEBUG_ERROR();
            return CW_ER_RECV;
          }
        }
      }while ((buf[n - 1] != '\x0D') && (buf[n++] != '\x0A'));
    }while (strcmp(&buf[1], emp) != 0);
  } else {
    DEBUG_ERROR();
    return CW_ER_PROXY;
  }

  return CW_ER_OK;
}

static CWERROR _connect_socks5(SOCKET sock,
                               const char *serv_addr,
                               const CW_UINT16 serv_port,
                               const char *proxy_addr,
                               const CW_UINT16 proxy_port,
                               const char *proxy_user,
                               const char *proxy_passwd,
                               const long recv_timeout) {
  SOCKADDR_IN addr;
  int sz = sizeof(addr), r, n;
  char buf[1024], *pb;
  char ip_str[MAX_IP_LEN];
  unsigned long ip_ulong;

  if (!resolve_ip(ip_str, proxy_addr)) {
    DEBUG_ERROR();
    return CW_ER_SOCKET;
  }

  memset(&addr, 0, sizeof(addr));

  addr.sin_family = AF_INET;
  addr.sin_port = htons(proxy_port);
  ip_ulong = inet_addr(ip_str);
  memcpy(&addr.sin_addr, &ip_ulong, sizeof(ip_ulong));

  if (connect(sock, (struct sockaddr *) &addr, sz)) {
    DEBUG_ERROR();
    return CW_ER_SOCKET;
  }

  /* connect to sock5 server */
  buf[0] = 5;  /* ver */
  buf[1] = 1;  /* 1 method */
  if (proxy_user == NULL) {
    buf[2] = 0;  /* no auth */
  } else {
    buf[2] = 2;  /* USERNAME/PASSWORD (RFC1929) */
  }
  sz = 3;
  if (send_buf(sock, buf, &sz) == SOCK_ER_SEND) {
    DEBUG_ERROR();
    return CW_ER_SEND;
  }
  if (sz != 3) {
    DEBUG_ERROR();
    return CW_ER_SEND;
  }
  sz = 2;
  r = recv_buf(sock, buf, &sz, recv_timeout);
  if (r <= 0) {
    if (r == SOCK_ER_RECV_TIMEOUT) {
      return CW_ER_RECV_TIMEOUT;
    } else if ((r == SOCK_ER_RECV_DISCONN) || (r == SOCK_ER_RECV) || (sz != 2)) {
      DEBUG_ERROR();
      return CW_ER_RECV;
    }
  }
  if (proxy_user == NULL) {
    if (buf[1] != 0) {
      DEBUG_ERROR();
      return CW_ER_PROXY;
    }
  } else {
    if (buf[1] != 2) {
      DEBUG_ERROR();
      return CW_ER_PROXY;
    }
    /* authentication */
    pb = buf;
    *pb = 1;
    ++pb;
    /* copy user name */
    n = strlen(proxy_user);
    *pb = (char) n;
    ++pb;
    memcpy(pb, proxy_user, n);
    pb += n;
    /* copy password */
    n = strlen(proxy_passwd);
    *pb = (char) n;
    ++pb;
    memcpy(pb, proxy_passwd, n);
    pb += n;
    n = (int) (pb - buf);
    /* send */
    sz = n;
    if (send_buf(sock, buf, &sz) == SOCK_ER_SEND) {
      DEBUG_ERROR();
      return CW_ER_SEND;
    }
    if (sz != n) {
      DEBUG_ERROR();
      return CW_ER_SEND;
    }
    /* recv */
    sz = 2;
    r = recv_buf(sock, buf, &sz, recv_timeout);
    if (r <= 0) {
      if (r == SOCK_ER_RECV_TIMEOUT) {
        return CW_ER_RECV_TIMEOUT;
      } else if ((r == SOCK_ER_RECV_DISCONN) || (r == SOCK_ER_RECV) || (sz != 2)) {
        DEBUG_ERROR();
        return CW_ER_RECV;
      }
    }
    if (buf[1] != 0) {
      DEBUG_ERROR();
      return CW_ER_PROXY;
    }
  }
  /* connect to server through proxy */
  buf[0] = 5;  /* ver */
  buf[1] = 1;  /* CONNECT */
  buf[2] = 0;  /* Reserved */

  if (!IS_DOMAIN(serv_addr)) {
    buf[3] = 1;  /* IPv4 */
    *((unsigned long *) (buf + 4)) = inet_addr(serv_addr);
    *((unsigned short *) (buf + 8)) = htons(serv_port);
    n = 10;
  } else {
    buf[3] = 3; /* domain name */
    pb = &buf[4];
    n = strlen(serv_addr);
    *pb = (char) n;
    ++pb;
    memcpy(pb, serv_addr, n);
    pb += n;
    *((unsigned short *) pb) = htons(serv_port);
    pb += sizeof(unsigned short);
    n = (int) (pb - buf);
  }

  sz = n;
  if (send_buf(sock, buf, &sz) == SOCK_ER_SEND) {
    DEBUG_ERROR();
    return CW_ER_SEND;
  }
  if (sz != n) {
    DEBUG_ERROR();
    return CW_ER_SEND;
  }
  sz = 10;
  r = recv_buf(sock, buf, &sz, recv_timeout);
  if (r <= 0) {
    if (r == SOCK_ER_RECV_TIMEOUT) {
      return CW_ER_RECV_TIMEOUT;
    } else if ((r == SOCK_ER_RECV_DISCONN) || (r == SOCK_ER_RECV) || (sz != 10)) {
      DEBUG_ERROR();
      return CW_ER_RECV;
    }
  }
  if (buf[1] != 0) {
    DEBUG_ERROR();
    return CW_ER_PROXY;
  }
  if (buf[3] != 1) {
    DEBUG_ERROR();
    return CW_ER_PROXY;
  }

  return CW_ER_OK;
}

DLLEXPORT
    CWERROR

DLLCALL client_keygen(const char *work_dir,
                      const char *ku_file,
                      const char *kr_file,
                      const char *efs_file,
                      const char *passwd,
                      const int kpair_sz) {
  char fpath[MAX_PATH + 1];
  RSA_PUBLIC_KEY ku;
  RSA_PRIVATE_KEY kr;
  CW_UINT8 efs_k[EFS_KEY_LEN];
  CWERROR err = CW_ER_OK;

  /* open log file */
  sprintf(fpath, "%s%s", work_dir, CLIENT_LOG_FILE_NAME);

  if ((err = log_open(fpath)) != CW_ER_OK) {
    return err;
  }

  if ((err = rnd_init()) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  mlock(&kr, sizeof(kr));
  mlock(efs_k, sizeof(efs_k));

  if ((err = gen_keys(&ku, &kr, efs_k, kpair_sz)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  if ((err = ku_write(&ku, ku_file)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = kr_write(&kr, kr_file, passwd)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = efsk_write(efs_k, efs_file, passwd)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  err_exit:

  memset(&kr, 0, sizeof(kr));
  memset(efs_k, 0, sizeof(efs_k));
  munlock(&kr, sizeof(kr));
  munlock(efs_k, sizeof(efs_k));

  rnd_final();
  log_close();

  return err;
}

DLLEXPORT
    CWERROR

DLLCALL client_chpass(const char *work_dir,
                      const char *kr_file,
                      const char *efs_file,
                      const char *passwd,
                      const char *new_passwd) {
  char log_file[MAX_PATH + 1];
  CWERROR err = CW_ER_OK;

  sprintf(log_file, "%s%s", work_dir, CLIENT_LOG_FILE_NAME);

  /* open log file */
  if ((err = log_open(log_file)) != CW_ER_OK) {
    return err;
  }

  if ((err = rnd_init()) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  if ((err = chpass(kr_file, efs_file, passwd, new_passwd)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  err_exit:

  rnd_final();
  log_close();

  return err;
}

DLLEXPORT
    CWERROR

DLLCALL client_init(const char *work_dir,
                    const char *root_cert,
                    const char *serv_cert,
                    const char *ku_file,
                    const char *kr_file,
                    const char *efs_file,
                    const char *passwd,
                    const CW_UINT32 ping_timeout,
                    const CW_UINT8 comp_level) {
  WSADATA wsa;
  char fpath[MAX_PATH + 1];
  CWERROR err = CW_ER_OK;

  MUTEX_INIT(cli->api_mtx);
  pthread_mutex_init(&cli->api_mtx, NULL);

  cli->ping_thrd = PTHREAD_INITIALIZER;

  cli->ping_timeout = ping_timeout;
  cli->comp_level = comp_level;

  sock_init(wsa);

  /* lock sensitive data */
  mlock(&cli->kr, sizeof(cli->kr));
  mlock(cli->efs_key, sizeof(cli->efs_key));

  /* open log file */
  sprintf(fpath, "%s%s", work_dir, CLIENT_LOG_FILE_NAME);
  if ((err = log_open(fpath)) != CW_ER_OK) {
    goto err_exit;
  }

  if ((err = rnd_init()) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  /* init database */
  sprintf(fpath, "%s%s", work_dir, CLIENT_DB_FILE_NAME);
  if ((err = db_init(fpath)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  /* read root certificate */
  if ((err = cert_read(&cli->root_cert, root_cert)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  /* read server certificate */
  if ((err = cert_read(&cli->serv_cert, serv_cert)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  /* check certificates */
  if ((err = cert_check(&cli->root_cert, &cli->root_cert.ku, CT_ROOT)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = cert_check(&cli->serv_cert, &cli->root_cert.ku, CT_SERVER)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  /* read client public key */
  if ((err = ku_read(&cli->ku, ku_file)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  /* read client private key */
  if ((err = kr_read(&cli->kr, kr_file, passwd)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  /* read EFS key */
  if ((err = efsk_read(cli->efs_key, efs_file, passwd)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  /* set current directory */
  if (strcpy_s(cli->work_dir, work_dir, sizeof(cli->work_dir)) == NULL) {
    DEBUG_ERROR();
    err = CW_ER_INTERNAL;
    goto err_exit;
  }

  err_exit:

  if (err != CW_ER_OK) {
    rnd_final();
    log_close();
    memset(&cli->kr, 0, sizeof(cli->kr));
    memset(cli->efs_key, 0, sizeof(cli->efs_key));
    munlock(&cli->kr, sizeof(cli->kr));
    munlock(cli->efs_key, sizeof(cli->efs_key));
    pthread_mutex_destroy(&cli->api_mtx);
  }

  return err;
}

DLLEXPORT
    CWERROR

DLLCALL client_final(void) {
  CWERROR err = CW_ER_OK;

  pthread_mutex_lock(&cli->api_mtx);

  memset(&cli->kr, 0, sizeof(cli->kr));
  memset(cli->efs_key, 0, sizeof(cli->efs_key));
  munlock(&cli->kr, sizeof(cli->kr));
  munlock(cli->efs_key, sizeof(cli->efs_key));

  if (cli->ping_thrd != PTHREAD_INITIALIZER) {
    pthread_cancel(cli->ping_thrd);
  }

  PACKET_FINAL(cli->srv_pctx);

  sock_final();
  rnd_final();
  log_close();

  pthread_mutex_destroy(&cli->api_mtx);

  return CW_ER_OK;
}

DLLEXPORT
    CWERROR

DLLCALL client_connect(const CW_CONNECT_MODE conn_mode,
                       const char *serv_addr,
                       const CW_UINT16 serv_port,
                       const char *proxy_addr,
                       const CW_UINT16 proxy_port,
                       const char *proxy_user,
                       const char *proxy_passwd,
                       const long recv_timeout) {
  SOCKET sock = INVALID_SOCKET;
  CWERROR err = CW_ER_OK;

  packets_startup(recv_timeout);
  PACKET_INIT(cli->srv_pctx);

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
    DEBUG_ERROR();
    return CW_ER_SOCKET;
  }

  switch (conn_mode) {
    case CM_DIRECT:
      if ((err = _connect_direct(sock, serv_addr, serv_port)) != CW_ER_OK) {
        DEBUG_ERROR();
        return err;
      }
      break;
    case CM_SOCKS5:
      if ((err = _connect_socks5(sock,
                                 serv_addr,
                                 serv_port,
                                 proxy_addr,
                                 proxy_port,
                                 proxy_user,
                                 proxy_passwd,
                                 recv_timeout)) != CW_ER_OK) {
        DEBUG_ERROR();
        return err;
      }
      break;
    case CM_HTTP:
      if ((err = _connect_http(sock,
                               serv_addr,
                               serv_port,
                               proxy_addr,
                               proxy_port,
                               proxy_user,
                               proxy_passwd,
                               recv_timeout)) != CW_ER_OK) {
        DEBUG_ERROR();
        return err;
      }
      break;
    default:
      DEBUG_ERROR();
      return CW_ER_INTERNAL;
      break;
  }

  PACKET_BIND(cli->srv_pctx, sock);

  return CW_ER_OK;
}

DLLEXPORT
    CWERROR

DLLCALL client_register(CW_UINT32 *sid, CW_UINT32 *uid, const char *name, const char *email) {
  BLOWFISH_CTX bf;
  SHA256_CTX sha256;
  CW_CLI_REG1_PACKET reg1;
  CW_CLI_REG1_RESP_PACKET reg1_resp;
  CW_CLI_REG2_PACKET reg2;
  CW_ERROR_PACKET serv_err;
  CW_PACKET_TYPE pckt_t;
  CW_UINT32 r_a;
  int pckt_len;
  unsigned int t;
  CW_UINT8 hash[SHA256_DIGEST_LEN], tbuf[MAX_RSA_BLOCK_LEN];
  RSA_RANDOM_STRUCT s_rnd;
  CWERROR err = CW_ER_OK;

  mlock(tbuf, sizeof(tbuf));

  /* REG1 */
  reg1.version = CURRENT_PROTOCOL_VERSION;
  if (strcpy_s(reg1.name, name, sizeof(reg1.name)) == NULL) {
    DEBUG_ERROR();
    return CW_ER_INTERNAL;
  }
  if (strcpy_s(reg1.email, email, sizeof(reg1.email)) == NULL) {
    DEBUG_ERROR();
    return CW_ER_INTERNAL;
  }
  memcpy(&reg1.ku_a, &cli->ku, sizeof(cli->ku));

  rnd_getbytes(&reg1.r_a, sizeof(reg1.r_a));

  r_a = reg1.r_a;

  SHA256_GET_HASH(sha256, &reg1.version, sizeof(CW_CLI_REG1_PACKET) -
                                         sizeof(reg1.e_skey) - sizeof(reg1.hash), reg1.hash);

  t = 1;
  R_RandomInit(&s_rnd);
  while (t != 0) {
    rnd_getbytes(tbuf, sizeof(tbuf));
    R_RandomUpdate(&s_rnd, tbuf, sizeof(tbuf));
    R_GetRandomBytesNeeded(&t, &s_rnd);
  }

  rnd_getbytes(tbuf, SESSION_KEY_LEN);

  BLOWFISH_ENCRYPT(bf, tbuf, &reg1.hash, sizeof(CW_CLI_REG1_PACKET) - sizeof(reg1.e_skey));

  RSAPublicEncrypt(reg1.e_skey.data, (unsigned int *) &reg1.e_skey.len, tbuf, SESSION_KEY_LEN, &cli->serv_cert.ku,
                   &s_rnd);
  R_RandomFinal(&s_rnd);

  if ((err = packet_send_raw(&cli->srv_pctx, &reg1, sizeof(reg1), PT_CLI_REG1)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  /* REG_RESP */
  if ((err = packet_recv_raw(&cli->srv_pctx, &reg1_resp, sizeof(reg1_resp), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }
  if ((pckt_t == PT_ERROR) && (pckt_len == sizeof(CW_ERROR_PACKET))) {
    DEBUG_ERROR();
    return pterr_to_cwerr(((CW_ERROR_PACKET * ) & reg1_resp)->code);
  } else if ((pckt_t != PT_CLI_REG1_RESP) || (pckt_len != sizeof(CW_CLI_REG1_RESP_PACKET))) {
    DEBUG_ERROR();
    return CW_ER_WRONG_PCKT;
  }

  RSAPrivateDecrypt(tbuf, (unsigned int *) &t, reg1_resp.e_skey.data, reg1_resp.e_skey.len, &cli->kr);
  if (t != SESSION_KEY_LEN) {
    DEBUG_ERROR();
    return CW_ER_WRONG_PCKT;
  }

  BLOWFISH_DECRYPT(bf, tbuf, &reg1_resp.sgn_s, sizeof(CW_CLI_REG1_RESP_PACKET) - sizeof(reg1_resp.e_skey));

  memset(tbuf, 0, sizeof(tbuf));

  SHA256_GET_HASH(sha256, &reg1_resp.sid_a, sizeof(CW_CLI_REG1_RESP_PACKET) -
                                            sizeof(reg1_resp.e_skey) - sizeof(reg1_resp.sgn_s), hash);

  RSAPublicDecrypt(tbuf, (unsigned int *) &t, reg1_resp.sgn_s.data, reg1_resp.sgn_s.len, &(cli->serv_cert.ku));
  if (t != SHA256_DIGEST_LEN) {
    DEBUG_ERROR();
    return CW_ER_WRONG_PCKT;
  }

  if (memcmp(tbuf, hash, sizeof(hash)) != 0) {
    DEBUG_ERROR();
    return CW_ER_WRONG_PCKT;
  }

  if (r_a != reg1_resp.r_a) {
    DEBUG_ERROR();
    return CW_ER_WRONG_PCKT;
  }

  *sid = reg1_resp.sid_a;
  *uid = reg1_resp.uid_a;

  /* REG2 */

  RSAPrivateEncrypt(reg2.r_s.data, (unsigned int *) &reg2.r_s.len, (char *) &reg1_resp.r_s, sizeof(reg1_resp.r_s),
                    &cli->kr);

  if ((err = packet_send_raw(&cli->srv_pctx, &reg2, sizeof(reg2), PT_CLI_REG2)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  /* check result */
  if ((err = packet_recv_raw(&cli->srv_pctx, &serv_err, sizeof(serv_err), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }
  if ((pckt_t != PT_ERROR) || (pckt_len != sizeof(CW_ERROR_PACKET))) {
    DEBUG_ERROR();
    return CW_ER_WRONG_PCKT;
  }
  if (serv_err.code != PE_OK) {
    DEBUG_ERROR();
    return pterr_to_cwerr(serv_err.code);
  }

  err_exit:

  memset(tbuf, 0, sizeof(tbuf));
  munlock(tbuf, sizeof(tbuf));

  return err;
}

DLLEXPORT
    CWERROR
DLLCALL client_login(CW_UINT64 * max_msg_sz,
                     CW_UINT64 * max_file_sz,
    const
CW_UINT32 sid,
const CW_UINT32 uid,
const CW_UINT16 l_port,
const CW_UINT16 kbps,
    ON_TIME_COLLISION
on_time_col)
{
BLOWFISH_CTX bf;
SHA256_CTX sha256;
CW_LOGIN1_PACKET login1;
CW_LOGIN1_RESP_PACKET login1_resp;
CW_LOGIN2_PACKET login2;
CW_PACKET_TYPE pckt_t;
CW_UINT32 r_a;
int pckt_len;
unsigned int t;
CW_UINT8 tbuf[MAX_RSA_BLOCK_LEN];
/* temp buffer */
CW_UINT8 akey[SESSION_KEY_LEN];
/* clients' session key */
CW_UINT8 hash[SHA256_DIGEST_LEN];
R_RANDOM_STRUCT s_rnd;
time_t c_time;
CW_TEST_PACKET test_c = {PCKT_TEST_STRING}, test_s;
CWERROR err = CW_ER_OK;

mlock(tbuf,
sizeof(tbuf));
mlock(akey,
sizeof(akey));
mlock(&login1
.skey_a, sizeof(login1.skey_a));
mlock(&login1_resp
.skey_s, sizeof(login1_resp.skey_s));

/* LOGIN 1 */

login1.
version = CURRENT_PROTOCOL_VERSION;
cli->
sid = login1.sid = sid;
cli->
uid = login1.uid = uid;
login1.a_info.
l_port = l_port;
login1.a_info.
kbps = kbps;

rnd_getbytes(&login1
.r_a, sizeof(login1.r_a));
r_a = login1.r_a;

rnd_getbytes(akey,
sizeof(akey));
memcpy(login1
.skey_a, akey, sizeof(akey));

/* get packet hash */
SHA256_GET_HASH(sha256, &login1
.version, sizeof(login1) -
sizeof(login1.e_skey) - sizeof(login1.sgn_a), hash);

RSAPrivateEncrypt(login1
.sgn_a.data, (unsigned int *)&login1.sgn_a.len, hash, sizeof(hash), &cli->kr);

t = 1;
R_RandomInit(&s_rnd);
while (t != 0) {
rnd_getbytes(tbuf,
sizeof(tbuf));
R_RandomUpdate(&s_rnd, tbuf,
sizeof(tbuf));
R_GetRandomBytesNeeded((
unsigned int *)&t, &s_rnd);
}

/* generate session key */
rnd_getbytes(tbuf, SESSION_KEY_LEN
);

/* encrypt packet */
BLOWFISH_ENCRYPT(bf, tbuf, &login1
.sgn_a, sizeof(login1) - sizeof(login1.e_skey));

RSAPublicEncrypt(login1
.e_skey.data, (unsigned int *)&login1.e_skey.len, tbuf, SESSION_KEY_LEN, &cli->serv_cert.ku, &s_rnd);
R_RandomFinal(&s_rnd);

memset(tbuf,
0, sizeof(tbuf));

if ((
err = packet_send_raw(&cli->srv_pctx, &login1, sizeof(login1), PT_CLI_LOGIN1)
) != CW_ER_OK) {
DEBUG_ERROR();

return
err;
}

/* LOGIN 1 RESP */
if ((
err = packet_recv_raw(&cli->srv_pctx, &login1_resp, sizeof(login1_resp), &pckt_len, &pckt_t)
) != CW_ER_OK) {
DEBUG_ERROR();

return
err;
}
if ((pckt_t == PT_ERROR) && (pckt_len == sizeof(CW_ERROR_PACKET))) {
DEBUG_ERROR();

return
pterr_to_cwerr(((CW_ERROR_PACKET
*)(&login1_resp))->code);
}
if ((pckt_t != PT_CLI_LOGIN1_RESP) || (pckt_len != sizeof(CW_LOGIN1_RESP_PACKET))) {
DEBUG_ERROR();

return
CW_ER_WRONG_PCKT;
}

RSAPrivateDecrypt(tbuf, &t, login1_resp
.e_skey.data, login1_resp.e_skey.len, &cli->kr);
if (t != SESSION_KEY_LEN) {
DEBUG_ERROR();

return
CW_ER_WRONG_PCKT;
}

/* decrypt packet */
BLOWFISH_DECRYPT(bf, tbuf, &login1_resp
.sgn_s, sizeof(login1_resp) - sizeof(login1_resp.e_skey));

/* get packet hash */
SHA256_GET_HASH(sha256, &login1_resp
.r_a, sizeof(login1_resp) -
sizeof(login1_resp.e_skey) - sizeof(login1_resp.sgn_s), hash);

RSAPublicDecrypt(tbuf, &t, login1_resp
.sgn_s.data, login1_resp.sgn_s.len, &cli->serv_cert.ku);
if (t != SHA256_DIGEST_LEN) {
DEBUG_ERROR();

return
CW_ER_WRONG_PCKT;
}

if (
memcmp(hash, tbuf,
sizeof(hash)) != 0) {
DEBUG_ERROR();

return
CW_ER_WRONG_PCKT;
}

/* check r_a */
if (login1_resp.r_a != r_a) {
DEBUG_ERROR();

return
CW_ER_WRONG_PCKT;
}

/* set max message size */
cli->
max_msg_sz = *max_msg_sz = login1_resp.a_info.max_msg_sz;
cli->
max_file_sz = *max_file_sz = login1_resp.a_info.max_file_sz;

cli->
kbps = login1_resp.a_info.kbps;

c_time = time(NULL);

if (
abs(difftime(c_time, login1_resp.a_info.c_time))
> TIME_DIFF) {
if ( !
on_time_col(login1_resp
.a_info.c_time)) {
DEBUG_ERROR();

return
CW_ER_INTERNAL;
}
}

/* LOGIN 2 */

RSAPrivateEncrypt(login2
.r_s.data, (unsigned int *)&login2.r_s.len, (char *)&login1_resp.r_s, sizeof(login1_resp.r_s), &cli->kr);

if ((
err = packet_send_raw(&cli->srv_pctx, &login2, sizeof(login2), PT_CLI_LOGIN2)
) != CW_ER_OK) {
DEBUG_ERROR();

return
err;
}

memcpy(tbuf, akey,
sizeof(akey));
bufs_xor(tbuf, login1_resp
.skey_s, sizeof(login1_resp.skey_s));

packet_set_crypto(&cli
->srv_pctx, tbuf, &(login1_resp.skey_s[BLOWFISH_KEY_LEN]), &akey[BLOWFISH_KEY_LEN]);

memset(akey,
0, sizeof(akey));
memset(tbuf,
0, sizeof(tbuf));
memset(&login1
.skey_a, 0, sizeof(login1.skey_a));
memset(&login1_resp
.skey_s, 0, sizeof(login1_resp.skey_s));

/* recv test packet */
if ((
err = packet_recv_crypted(&cli->srv_pctx, &test_s, sizeof(test_s), &pckt_len, &pckt_t)
) != CW_ER_OK) {
DEBUG_ERROR();

return
err;
}
if ((pckt_t == PT_ERROR) && (pckt_len == sizeof(CW_ERROR_PACKET))) {
DEBUG_ERROR();

return
pterr_to_cwerr(((CW_ERROR_PACKET
*)&test_s)->code);
}
/* check test packet */
if ((pckt_t != PT_TEST) || (pckt_len != sizeof(CW_TEST_PACKET))) {
DEBUG_ERROR();

return
CW_ER_WRONG_PCKT;
}
if (
memcmp(&test_s, &test_c,
sizeof(test_c)) != 0) {
DEBUG_ERROR();

return
CW_ER_WRONG_PCKT;
}

/* send test packet */
if ((
err = packet_send_crypted(&cli->srv_pctx, &test_c, sizeof(test_c), PT_TEST)
) != CW_ER_OK) {
DEBUG_ERROR();

return
err;
}

if ( !
THREAD_SUCCESS(CREATE_THREAD(cli->ping_thrd, _ping_thrd_proc, cli))
) {
DEBUG_ERROR();

return
CW_ER_CREATE_THREAD;
}
pthread_detach(cli
->ping_thrd);

err_exit:

    memset(tbuf, 0, sizeof(tbuf));
memset(akey,
0, sizeof(akey));
memset(&login1,
0, sizeof(login1));
memset(&login1_resp,
0, sizeof(login1_resp));

munlock(tbuf,
sizeof(tbuf));
munlock(akey,
sizeof(akey));
munlock(&login1
.skey_a, sizeof(login1.skey_a));
munlock(&login1_resp
.skey_s, sizeof(login1_resp.skey_s));

return
err;
}

DLLEXPORT
    CWERROR

DLLCALL client_logout(void) {
  CW_UINT32 tmp = QRND();
  CWERROR err = CW_ER_OK;

  pthread_mutex_lock(&cli->api_mtx);

  if ((err = packet_send_crypted(&cli->srv_pctx, &tmp, sizeof(tmp), PT_LOGOUT)) != CW_ER_OK) {
    pthread_mutex_unlock(&cli->api_mtx);
    DEBUG_ERROR();
    return err;
  }

  pthread_mutex_unlock(&cli->api_mtx);

  return CW_ER_OK;
}

DLLEXPORT
void DLLCALL
client_get_stat(CW_UINT64
*in_bytes,
CW_UINT64 *out_bytes
)
{
packet_get_stat(&cli
->srv_pctx, in_bytes, out_bytes);
}

DLLEXPORT
    CWERROR

DLLCALL client_get_info(CW_INFO_BLOCK **info, CW_UINT32 *info_cnt) {
  CW_UINT32 tmp = QRND();
  CW_LIST_HEAD_PACKET info_head;
  CW_INFO_BLOCK *pinfo = NULL;
  CW_UINT32 k = 0;
  CW_PACKET_TYPE pckt_t;
  int pckt_len;
  CWERROR err = CW_ER_OK;

  pthread_mutex_lock(&cli->api_mtx);

  if ((err = packet_send_crypted(&cli->srv_pctx, &tmp, sizeof(tmp), PT_GET_INFO)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  if ((err = packet_recv_crypted(&cli->srv_pctx, &info_head, sizeof(info_head), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_t != PT_GET_INFO_RESP) || (pckt_len != sizeof(info_head))) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }

  if ((*info_cnt = info_head.cnt) == 0) {
    err = CW_ER_OK;
    goto err_exit;
  }

  if ((pinfo = *info = DLL_MALLOC(sizeof(CW_INFO_BLOCK) * info_head.cnt)) == NULL) {
    DEBUG_ERROR();
    err = CW_ER_MEMORY;
    goto err_exit;
  }

  while (info_head.cnt--) {
    if ((err = packet_recv_crypted(&cli->srv_pctx, &(pinfo[k].pckt), sizeof(CW_INFO_PACKET), &pckt_len, &pckt_t)) !=
        CW_ER_OK) {
      DEBUG_ERROR();
      goto err_exit;
    }
    if ((pckt_t != PT_GET_INFO_RESP) || (pckt_len != sizeof(CW_INFO_PACKET))) {
      DEBUG_ERROR();
      err = CW_ER_WRONG_PCKT;
      goto err_exit;
    }
    if (pinfo[k].pckt.text_sz > 0) {
      if ((err = packet_recv_crypted(&cli->srv_pctx, pinfo[k].text, pinfo[k].pckt.text_sz, &pckt_len, &pckt_t)) !=
          CW_ER_OK) {
        DEBUG_ERROR();
        goto err_exit;
      }
      if ((pckt_t != PT_GET_INFO_RESP) || (pckt_len != pinfo[k].pckt.text_sz)) {
        DEBUG_ERROR();
        err = CW_ER_WRONG_PCKT;
        goto err_exit;
      }
    }
    ++k;
  }

  err_exit:

  pthread_mutex_unlock(&cli->api_mtx);

  if (err != CW_ER_OK) {
    if (pinfo != NULL) {
      DLL_FREE(pinfo);
    }
  }

  return err;
}

DLLEXPORT
    CWERROR

DLLCALL client_get_user_status(CW_BOOL *res,
                               const CW_UINT32 sid,
                               const CW_UINT32 uid) {
  CW_UINT32 sid_uid[2] = {sid, uid};
  int pckt_len;
  CW_PACKET_TYPE pckt_t;
  CW_UINT8 resp[max(sizeof(CW_BOOL), sizeof(CW_ERROR_PACKET))];
  CWERROR err = CW_ER_OK;

  pthread_mutex_lock(&cli->api_mtx);

  if ((err = packet_send_crypted(&cli->srv_pctx, &sid_uid, sizeof(sid_uid), PT_GET_ONLINE_STATUS)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = packet_recv_crypted(&cli->srv_pctx, resp, sizeof(resp), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_t == PT_ERROR) && (pckt_len == sizeof(CW_ERROR_PACKET)) && (((CW_ERROR_PACKET * )
  resp)->code == PE_NO_QUERIED_INFO)) {
    err = CW_ER_NO_QUERIED_INFO;
    goto err_exit;
  } else if ((pckt_t != PT_GET_ONLINE_STATUS_RESP) || (pckt_len != sizeof(CW_BOOL))) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }

  *res = *((CW_BOOL *) resp);

  err_exit:

  pthread_mutex_unlock(&cli->api_mtx);

  return err;
}

DLLEXPORT
    CWERROR

DLLCALL client_request_cert(void) {
  CW_UINT32 tmp = QRND();
  CW_PACKET_TYPE pckt_t;
  CW_ERROR_PACKET serv_err;
  int pckt_len;
  CWERROR err = CW_ER_OK;

  pthread_mutex_lock(&cli->api_mtx);

  if ((err = packet_send_crypted(&cli->srv_pctx, &tmp, sizeof(tmp), PT_MK_CERT)) != CW_ER_OK) {
    pthread_mutex_unlock(&cli->api_mtx);
    DEBUG_ERROR();
    return err;
  }
  if ((err = packet_recv_crypted(&cli->srv_pctx, &serv_err, sizeof(serv_err), &pckt_len, &pckt_t)) != CW_ER_OK) {
    pthread_mutex_unlock(&cli->api_mtx);
    DEBUG_ERROR();
    return err;
  }
  if ((pckt_t != PT_ERROR) || (pckt_len != sizeof(serv_err))) {
    pthread_mutex_unlock(&cli->api_mtx);
    DEBUG_ERROR();
    return CW_ER_WRONG_PCKT;
  }

  pthread_mutex_unlock(&cli->api_mtx);

  switch (serv_err.code) {
    case PE_OK:
      break;
    case PE_HAS_CERT:
      err = CW_ER_HAS_CERT;
      break;
    case PE_MK_CERT:
      err = CW_ER_MAKE_CERT;
      break;
    default:
      err = CW_ER_WRONG_PCKT;
      break;
  }

  return err;
}

DLLEXPORT
    CWERROR

DLLCALL client_get_user_info(CW_USER_INFO *u_info,
                             const CW_UINT32 sid,
                             const CW_UINT32 uid) {
  CW_EXTERNAL_USER_INFO u_dinfo;
  CWERROR err = CW_ER_OK;

  if ((err = _get_user_info(&u_dinfo, sid, uid)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  u_info->online = u_dinfo.online;
  u_info->locked = u_dinfo.locked;
  u_info->l_port = u_dinfo.l_port;
  memcpy(&u_info->ip, &u_dinfo.ip, sizeof(u_dinfo.ip));
  strcpy(u_info->name, u_dinfo.name);
  strcpy(u_info->email, u_dinfo.email);

  if (u_dinfo.has_cert) {
    if ((err = cert_check(&u_dinfo.cert, &cli->root_cert.ku, CT_USER)) != CW_ER_OK) {
      if (err == CW_ER_MEMORY) {
        DEBUG_ERROR();
        return err;
      }
      u_info->has_cert = FALSE;
    } else {
      u_info->has_cert = TRUE;

      u_info->cert_info.valid_from = u_dinfo.cert.valid_from;
      u_info->cert_info.valid_until = u_dinfo.cert.valid_until;
      u_info->cert_info.type = u_dinfo.cert.ext.type;
      memcpy(&u_info->cert_info.flags, &u_dinfo.cert.ext.flags, sizeof(u_dinfo.cert.ext.flags));

      memcpy(&u_info->cert_info.sn, &u_dinfo.cert.sn, sizeof(u_dinfo.cert.sn));

      if (strcpy_s(u_info->cert_info.subj_name, u_dinfo.cert.subj_name, sizeof(u_info->cert_info.subj_name)) == NULL) {
        DEBUG_ERROR();
        return CW_ER_INTERNAL;
      }
      if (strcpy_s(u_info->cert_info.subj_email, u_dinfo.cert.ext.subj_email, sizeof(u_info->cert_info.subj_email)) ==
          NULL) {
        DEBUG_ERROR();
        return CW_ER_INTERNAL;
      }
      if (strcpy_s(u_info->cert_info.issr_name, u_dinfo.cert.issr_name, sizeof(u_info->cert_info.issr_name)) == NULL) {
        DEBUG_ERROR();
        return CW_ER_INTERNAL;
      }
    }
  } else {
    u_info->has_cert = FALSE;
  }

  return CW_ER_OK;
}

DLLEXPORT
    CWERROR

DLLCALL client_get_storage_info(CW_STORAGE_INFO *mb_info) {
  CW_UINT32 tmp = QRND();
  CW_PACKET_TYPE pckt_t;
  int pckt_len;
  CWERROR err = CW_ER_OK;

  pthread_mutex_lock(&cli->api_mtx);

  if ((err = packet_send_crypted(&cli->srv_pctx, &tmp, sizeof(tmp), PT_GET_STORAGE_INFO)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = packet_recv_crypted(&cli->srv_pctx, mb_info, sizeof(CW_STORAGE_INFO), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_t != PT_GET_STORAGE_INFO_RESP) || (pckt_len != sizeof(CW_STORAGE_INFO))) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
  }

  err_exit:

  pthread_mutex_unlock(&cli->api_mtx);

  return err;
}

DLLEXPORT
    CWERROR

DLLCALL client_get_messages(SET_PROGRESS set_progr,
                            UPDATE_PROGRESS updt_progr,
                            SET_SUB_PROGRESS set_sub_progr,
                            UPDATE_SUB_PROGRESS updt_sub_progr) {
  CW_UINT32 tmp = QRND();
  BLOWFISH_CTX bf;
  CW_MSGS_STREAM_HEADER msg_info;
  CW_MSG_PACKET_HEADER msg_head;
  CW_REPORT_PACKET report;
  CW_PACKET_TYPE pckt_t;
  CW_DB_CONNECTION *db_conn = NULL;
  CW_UINT8 *buf = NULL;
  FILE *file = NULL;
  char fname[MSG_FILE_NAME_LEN + 1], fpath[MAX_PATH + 1];
  CW_UINT64 blck_cnt;
  int tail_sz, pckt_len;
  CW_UINT32 t, rep_count;
  CWERROR err = CW_ER_OK;

  pthread_mutex_lock(&cli->api_mtx);

  if ((buf = malloc(cli->kbps)) == NULL) {
    DEBUG_ERROR();
    err = CW_ER_MEMORY;
    goto err_exit;
  }

  if ((err = packet_send_crypted(&cli->srv_pctx, &tmp, sizeof(tmp), PT_GET_MESSAGES)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = packet_recv_crypted(&cli->srv_pctx, &msg_info, sizeof(msg_info), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_t != PT_GET_MESSAGES_RESP) || (pckt_len != sizeof(msg_info))) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }

  /* open database */
  if ((err = db_open(&db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  set_progr(msg_info.msg_cnt);

  while ((msg_info.msg_cnt)--) {
    if ((err = packet_recv_crypted(&cli->srv_pctx, &msg_head, sizeof(msg_head), &pckt_len, &pckt_t)) != CW_ER_OK) {
      DEBUG_ERROR();
      goto err_exit;
    }
    if ((pckt_len != sizeof(msg_head)) || (pckt_t != PT_MESSAGE)) {
      DEBUG_ERROR();
      err = CW_ER_WRONG_PCKT;
      goto err_exit;
    }

    if ((msg_head.e_hdr.rcpt.sid != cli->sid) || (msg_head.e_hdr.rcpt.uid != cli->uid)) {
      DEBUG_ERROR();
      err = CW_ER_WRONG_PCKT;
      goto err_exit;
    }

    /* write message to file */
    if ((err = rnd_getchars(fname, MSG_FILE_NAME_LEN)) != CW_ER_OK) {
      DEBUG_ERROR();
      goto err_exit;
    }

    /* make full file path */
    sprintf(fpath, "%s%s", cli->work_dir, fname);

    if ((file = fopen(fpath, "wb")) == NULL) {
      DEBUG_ERROR();
      err = CW_ER_CREATE_FILE;
      goto err_exit;
    }
    if (fwrite(&msg_head, sizeof(msg_head), 1, file) != 1) {
      DEBUG_ERROR();
      err = CW_ER_WRITE_FILE;
      goto err_exit;
    }

    blck_cnt = (msg_head.e_hdr.size - sizeof(msg_head)) / cli->kbps;
    tail_sz = (msg_head.e_hdr.size - sizeof(msg_head)) % cli->kbps;

    set_sub_progr(blck_cnt + ((tail_sz > 0) ? 1 : 0));

    while (blck_cnt--) {
      if ((err = packet_recv_mixed(&cli->srv_pctx, buf, cli->kbps, &pckt_len, &pckt_t)) != CW_ER_OK) {
        DEBUG_ERROR();
        goto err_exit;
      }
      if ((pckt_len != cli->kbps) || (pckt_t != PT_MESSAGE)) {
        DEBUG_ERROR();
        err = CW_ER_WRONG_PCKT;
        goto err_exit;
      }
      if (fwrite(buf, cli->kbps, 1, file) != 1) {
        DEBUG_ERROR();
        err = CW_ER_WRITE_FILE;
        goto err_exit;
      }
      updt_sub_progr();
    }
    if (tail_sz > 0) {
      if ((err = packet_recv_mixed(&cli->srv_pctx, buf, tail_sz, &pckt_len, &pckt_t)) != CW_ER_OK) {
        DEBUG_ERROR();
        goto err_exit;
      }
      if ((pckt_len != tail_sz) || (pckt_t != PT_MESSAGE)) {
        DEBUG_ERROR();
        err = CW_ER_WRONG_PCKT;
        goto err_exit;
      }
      if (fwrite(buf, tail_sz, 1, file) != 1) {
        DEBUG_ERROR();
        err = CW_ER_WRITE_FILE;
        goto err_exit;
      }
      updt_sub_progr();
    }

    fflush(file);
    fclose(file);

    if ((err = db_inbox_add(db_conn,
                            msg_head.e_hdr.from.sid,
                            msg_head.e_hdr.from.uid,
                            msg_head.e_hdr.size,
                            fname)) != CW_ER_OK) {
      DEBUG_ERROR();
      goto err_exit;
    }

    updt_progr();
  }

  if ((err = packet_recv_crypted(&cli->srv_pctx, &rep_count, sizeof(rep_count), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_t != PT_GET_MESSAGES_RESP) || (pckt_len != sizeof(rep_count))) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }

  while (rep_count--) {
    if ((err = packet_recv_crypted(&cli->srv_pctx, &report, sizeof(report), &pckt_len, &pckt_t)) != CW_ER_OK) {
      DEBUG_ERROR();
      goto err_exit;
    }
    if ((pckt_t != PT_REPORT) || (pckt_len != sizeof(report))) {
      DEBUG_ERROR();
      err = CW_ER_WRONG_PCKT;
      goto err_exit;
    }
    if ((err = db_report_add(db_conn, report.rcpt_sid, report.rcpt_uid, report.code)) != CW_ER_OK) {
      DEBUG_ERROR();
      goto err_exit;
    }
  }

  if ((err = db_close(db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  FREE(buf);

  err_exit:

  pthread_mutex_unlock(&cli->api_mtx);

  if (err != CW_ER_OK) {
    if (file != NULL) {
      fclose(file);
    }
    if (buf != NULL) {
      FREE(buf);
    }
    db_close(db_conn);
  }

  return err;
}

DLLEXPORT
    CWERROR

DLLCALL client_send_messages(const CW_INT64 mid,
                             SET_PROGRESS set_progr,
                             UPDATE_PROGRESS updt_progr,
                             SET_SUB_PROGRESS set_sub_progr,
                             UPDATE_SUB_PROGRESS updt_sub_progr) {
  CW_DB_CONNECTION *db_conn = NULL;
  CW_MSG_DESC *mlist = NULL, msg;
  FILE *file = NULL;
  CW_MSGS_STREAM_HEADER msg_info;
  CW_MSG_PACKET_HEADER msg_head;
  CW_ERROR_PACKET serv_err;
  CW_PACKET_TYPE pckt_t;
  CW_UINT64 blck_cnt;
  CW_UINT32 m_cnt, i;
  int pckt_len, tail_sz;
  char fpath[MAX_PATH + 1];
  CW_UINT8 *buf = NULL;
  CWERROR err = CW_ER_OK;

  if ((err = db_open(&db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  if (mid == 0) {
    if ((err = db_outbox_get_list(db_conn, &mlist, &m_cnt)) != CW_ER_OK) {
      DEBUG_ERROR();
      return err;
    }
    if (m_cnt == 0) {
      if ((err = db_close(db_conn)) != CW_ER_OK) {
        DEBUG_ERROR();
        return err;
      }
      return CW_ER_OK;
    }
  } else {
    if ((err = db_outbox_get_by_id(db_conn, &msg, mid)) != CW_ER_OK) {
      DEBUG_ERROR();
      return err;
    }
    mlist = &msg;
    m_cnt = 1;
  }

  msg_info.msg_cnt = 0;
  msg_info.total_sz = 0;
  for (i = 0; i < m_cnt; i++) {
    if (mlist[i].sz <= cli->max_msg_sz) {
      msg_info.total_sz += mlist[i].sz;
      ++msg_info.msg_cnt;
    }
  }

  if (msg_info.msg_cnt == 0) {
    return CW_ER_OK;
  }

  pthread_mutex_lock(&cli->api_mtx);

  if ((buf = malloc(cli->kbps)) == NULL) {
    DEBUG_ERROR();
    err = CW_ER_MEMORY;
    goto err_exit;
  }

  set_progr(msg_info.msg_cnt);

  if ((err = packet_send_crypted(&cli->srv_pctx, &msg_info, sizeof(msg_info), PT_MESSAGE)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  for (i = 0; i < m_cnt; i++) {
    sprintf(fpath, "%s%s", cli->work_dir, mlist[i].file);
    if ((file = fopen(fpath, "rb")) == NULL) {
      DEBUG_ERROR();
      err = CW_ER_OPEN_FILE;
      goto err_exit;
    }
    if (fread(&msg_head, sizeof(msg_head), 1, file) != 1) {
      DEBUG_ERROR();
      err = CW_ER_READ_FILE;
      goto err_exit;
    }
    if (msg_head.e_hdr.size > cli->max_msg_sz) {
      fclose(file);
      continue;
    }
    rnd_getbytes(&msg_head._e_skey, sizeof(msg_head._e_skey));
    if ((err = packet_send_crypted(&cli->srv_pctx, &msg_head, sizeof(msg_head), PT_MESSAGE)) != CW_ER_OK) {
      DEBUG_ERROR();
      goto err_exit;
    }
    if ((err = packet_recv_crypted(&cli->srv_pctx,
                                   &serv_err,
                                   sizeof(serv_err),
                                   &pckt_len,
                                   &pckt_t)) != CW_ER_OK) {
      DEBUG_ERROR();
      goto err_exit;
    }
    if ((pckt_len != sizeof(serv_err)) || (pckt_t != PT_ERROR)) {
      DEBUG_ERROR();
      err = CW_ER_WRONG_PCKT;
      goto err_exit;
    }
    if (serv_err.code != PE_OK) {
      continue;
    }
    blck_cnt = (mlist[i].sz - sizeof(msg_head)) / cli->kbps;
    tail_sz = (mlist[i].sz - sizeof(msg_head)) % cli->kbps;

    set_sub_progr(blck_cnt + ((tail_sz > 0) ? 1 : 0));

    while (blck_cnt--) {
      if (fread(buf, cli->kbps, 1, file) != 1) {
        DEBUG_ERROR();
        err = CW_ER_READ_FILE;
        goto err_exit;
      }
      if ((err = packet_send_mixed(&cli->srv_pctx, buf, cli->kbps, PT_MESSAGE)) != CW_ER_OK) {
        DEBUG_ERROR();
        goto err_exit;
      }
      updt_sub_progr();
    }
    if (tail_sz > 0) {
      if (fread(buf, tail_sz, 1, file) != 1) {
        DEBUG_ERROR();
        err = CW_ER_READ_FILE;
        goto err_exit;
      }
      if ((err = packet_send_mixed(&cli->srv_pctx, buf, tail_sz, PT_MESSAGE)) != CW_ER_OK) {
        DEBUG_ERROR();
        goto err_exit;
      }
      updt_sub_progr();
    }
    fclose(file);

    if ((err = db_outbox_delete(db_conn, &mlist[i])) != CW_ER_OK) {
      DEBUG_ERROR();
      goto err_exit;
    }
    if ((err = db_sent_add(db_conn, mlist[i].sid, mlist[i].uid, mlist[i].sz, mlist[i].file)) != CW_ER_OK) {
      DEBUG_ERROR();
      goto err_exit;
    }

    updt_progr();
  }

  if ((err = packet_recv_crypted(&cli->srv_pctx,
                                 &serv_err,
                                 sizeof(serv_err),
                                 &pckt_len,
                                 &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_len != sizeof(serv_err)) || (pckt_t != PT_ERROR)) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }
  if (serv_err.code != PE_OK) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }

  if ((err = db_close(db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  FREE(buf);

  err_exit:

  pthread_mutex_unlock(&cli->api_mtx);

  if (mlist != &msg) {
    DLL_FREE(mlist);
  }

  if (err != CW_ER_OK) {
    if (file != NULL) {
      fclose(file);
    }
    if (buf != NULL) {
      FREE(buf);
    }
    db_close(db_conn);
  }

  return err;
}

DLLEXPORT
    CWERROR

DLLCALL client_outbox_put(CW_INT64 *mid,
                          const CW_UINT32 sid,
                          const CW_UINT32 uid,
                          const wchar_t *text,
                          const CW_UINT32 text_len, /* in wchar_t-s */
                          const CW_MSG_FILE *files,
                          const CW_UINT32 f_cnt,
                          SET_PROGRESS set_progr,
                          UPDATE_PROGRESS updt_progr) {
  BLOWFISH_CTX bf;
  SHA256_CTX sha256;
  RSA_RANDOM_STRUCT s_rnd;
  CW_EXTERNAL_USER_INFO u_dinfo;
  CW_MSG_PACKET_HEADER msg_head;
  CW_MSG_TEXT_HEADER text_head;
  CW_DB_CONNECTION *db_conn = NULL;
  CW_FILE_HEADER *file_heads = NULL;
  CW_UINT64 blck_cnt;
  CW_UINT8 hash[SHA256_DIGEST_LEN], skey[SESSION_KEY_LEN],
      tbuf[SHA512_DIGEST_LEN], buf[FILE_BUF_SZ],
      cbuf[Z_COMP_GET_BOUND(FILE_BUF_SZ)];
  CW_UINT32 i, text_sz, pckd_sz, file_heads_sz, pckd_text_sz;
  FILE *fmsg = NULL, *file = NULL;
  int len, done, tail_sz, zerr;
  wchar_t *t_text = NULL;
  char fname[MSG_FILE_NAME_LEN + 1], fpath[MAX_PATH + 1];
  z_stream zcomp;
  CW_BOOL comp_done = TRUE;
  CWERROR err = CW_ER_OK;

  mlock(tbuf, sizeof(tbuf));
  mlock(buf, sizeof(buf));
  mlock(cbuf, sizeof(cbuf));
  mlock(skey, sizeof(skey));

  set_progr(f_cnt + 2);

  /* get rcpt info */
  if ((err = _get_user_info(&u_dinfo, sid, uid)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }
  if (u_dinfo.locked) {
    DEBUG_ERROR();
    return CW_ER_LOCKED;
  }

  /* alloc memory for temp text */
  text_sz = text_head.sz.upckd = text_len * sizeof(wchar_t);
  if (text_len > 0) {
    pckd_sz = Z_COMP_GET_BOUND(text_sz);
    if ((t_text = sec_malloc(pckd_sz)) == NULL) {
      DEBUG_ERROR();
      err = CW_ER_MEMORY;
      goto err_exit;
    }
    /* compress text */
    zcomp.zalloc = Z_NULL;
    zcomp.zfree = Z_NULL;
    zcomp.opaque = Z_NULL;
    zcomp.next_in = (Bytef *) text;
    zcomp.avail_in = (uInt) text_sz;
    zcomp.next_out = (Bytef *) t_text;
    zcomp.avail_out = (uInt) pckd_sz;
    if (deflateInit(&zcomp, cli->comp_level) != Z_OK) {
      DEBUG_ERROR();
      err = CW_ER_COMPRESS;
      goto err_exit;
    }
    if (deflate(&zcomp, Z_FINISH) != Z_STREAM_END) {
      deflateEnd(&zcomp);
      DEBUG_ERROR();
      err = CW_ER_COMPRESS;
      goto err_exit;
    }
    if (deflateEnd(&zcomp) != Z_OK) {
      DEBUG_ERROR();
      err = CW_ER_COMPRESS;
      goto err_exit;
    }
  }
  pckd_text_sz = text_head.sz.pckd = zcomp.total_out;

  /* alloc memory for files headers */
  file_heads_sz = sizeof(CW_FILE_HEADER) * f_cnt;
  if (f_cnt > 0) {
    if ((file_heads = sec_malloc(file_heads_sz)) == NULL) {
      DEBUG_ERROR();
      err = CW_ER_MEMORY;
      goto err_exit;
    }
  }

  /* create message file */
  if ((err = rnd_getchars(fname, MSG_FILE_NAME_LEN)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }
  sprintf(fpath, "%s%s", cli->work_dir, fname);
  if ((fmsg = fopen(fpath, "wb")) == NULL) {
    DEBUG_ERROR();
    return CW_ER_CREATE_FILE;
  }

  /* write stub header */
  if (fwrite(&msg_head, sizeof(msg_head), 1, fmsg) != 1) {
    DEBUG_ERROR();
    err = CW_ER_WRITE_FILE;
    goto err_exit;
  }
  /* write stub text header */
  if (fwrite(&text_head, sizeof(text_head), 1, fmsg) != 1) {
    DEBUG_ERROR();
    err = CW_ER_WRITE_FILE;
    goto err_exit;
  }
  if (text_len > 0) {
    /* write stub text */
    if (fwrite(t_text, text_head.sz.pckd, 1, fmsg) != 1) {
      DEBUG_ERROR();
      err = CW_ER_WRITE_FILE;
      goto err_exit;
    }
  }
  if (f_cnt > 0) {
    /* write stub files headers */
    if (fwrite(file_heads, file_heads_sz, 1, fmsg) != 1) {
      DEBUG_ERROR();
      err = CW_ER_WRITE_FILE;
      goto err_exit;
    }
  }

  /* make file headers */
  for (i = 0; i < f_cnt; i++) {
    /* generate session IV */
    rnd_getbytes(file_heads[i].siv, sizeof(file_heads[i].siv));
    /* initialize CRC32 */
    CRC32_INIT(file_heads[i].crc);
    /* set file size */
    file_heads[i].sz.upckd = files[i].size;
    /* get file name */
    if (get_fname(file_heads[i].name, files[i].name) == NULL) {
      DEBUG_ERROR();
      err = CW_ER_INTERNAL;
      goto err_exit;
    }
  }

  /* set message size in header */
  msg_head.e_hdr.size = sizeof(msg_head) + sizeof(text_head) +
                        ((text_len > 0) ? text_head.sz.pckd : 0) + ((f_cnt > 0) ? file_heads_sz : 0);

  /* generate session key */
  rnd_getbytes(skey, SESSION_KEY_LEN);

  updt_progr();

  for (i = 0; i < f_cnt; i++) {
    blck_cnt = files[i].size / sizeof(buf);
    tail_sz = files[i].size % sizeof(buf);

    if ((file = fopen(files[i].name, "rb")) == NULL) {
      DEBUG_ERROR();
      err = CW_ER_OPEN_FILE;
      goto err_exit;
    }

    blowfish_init(&bf, skey, BLOWFISH_KEY_LEN, file_heads[i].siv);

    zcomp.zalloc = Z_NULL;
    zcomp.zfree = Z_NULL;
    zcomp.opaque = Z_NULL;
    zcomp.next_out = (Bytef *) cbuf;
    zcomp.avail_out = (uInt)
    sizeof(cbuf);

    if (deflateInit(&zcomp, cli->comp_level) != Z_OK) {
      DEBUG_ERROR();
      err = CW_ER_COMPRESS;
      goto err_exit;
    }
    comp_done = FALSE;
    done = FALSE;

    while (blck_cnt--) {
      /* read block */
      if (fread(buf, sizeof(buf), 1, file) != 1) {
        DEBUG_ERROR();
        err = CW_ER_READ_FILE;
        goto err_exit;
      }
      /* get block crc32 */
      my_crc32(&file_heads[i].crc, buf, sizeof(buf));
      /* compress block*/
      zcomp.next_in = (Bytef *) buf;
      zcomp.avail_in = (uInt)
      sizeof(buf);
      while (zcomp.avail_in != 0) {
        if (zcomp.avail_out == 0) {
          blowfish_encrypt(&bf, cbuf, cbuf, sizeof(cbuf));
          if (fwrite(cbuf, sizeof(cbuf), 1, fmsg) != 1) {
            DEBUG_ERROR();
            err = CW_ER_WRITE_FILE;
            goto err_exit;
          }
          zcomp.next_out = cbuf;
          zcomp.avail_out = (uInt)
          sizeof(cbuf);
        }
        if (deflate(&zcomp, Z_NO_FLUSH) != Z_OK) {
          deflateEnd(&zcomp);
          DEBUG_ERROR();
          err = CW_ER_COMPRESS;
          goto err_exit;
        }
      }
    }
    if (tail_sz > 0) {
      if (fread(buf, tail_sz, 1, file) != 1) {
        DEBUG_ERROR();
        err = CW_ER_READ_FILE;
        goto err_exit;
      }
      /* get block crc32 */
      my_crc32(&file_heads[i].crc, buf, tail_sz);
      /* compress block*/
      zcomp.next_in = (Bytef *) buf;
      zcomp.avail_in = (uInt) tail_sz;
      while (zcomp.avail_in != 0) {
        if (zcomp.avail_out == 0) {
          blowfish_encrypt(&bf, cbuf, cbuf, sizeof(cbuf));
          if (fwrite(cbuf, sizeof(cbuf), 1, fmsg) != 1) {
            DEBUG_ERROR();
            err = CW_ER_WRITE_FILE;
            goto err_exit;
          }
          zcomp.next_out = cbuf;
          zcomp.avail_out = (uInt)
          sizeof(cbuf);
        }
        if (deflate(&zcomp, Z_NO_FLUSH) != Z_OK) {
          deflateEnd(&zcomp);
          DEBUG_ERROR();
          err = CW_ER_COMPRESS;
          goto err_exit;
        }
      }
    }
    while (TRUE) {
      if ((len = sizeof(cbuf) - zcomp.avail_out) != 0) {
        blowfish_encrypt(&bf, cbuf, cbuf, len);
        if (fwrite(cbuf, len, 1, fmsg) != 1) {
          DEBUG_ERROR();
          err = CW_ER_WRITE_FILE;
          goto err_exit;
        }
        zcomp.next_out = cbuf;
        zcomp.avail_out = (uInt)
        sizeof(cbuf);
      }

      if (done)
        break;

      zerr = deflate(&zcomp, Z_FINISH);
      if ((len == 0) && (zerr == Z_BUF_ERROR))
        zerr = Z_OK;
      done = ((zcomp.avail_out != 0) || (zerr == Z_STREAM_END));
      if ((zerr != Z_OK) && (zerr != Z_STREAM_END))
        break;
    }
    if (zerr != Z_STREAM_END) {
      DEBUG_ERROR();
      err = CW_ER_COMPRESS;
      goto err_exit;
    }
    if (deflateEnd(&zcomp) != Z_OK) {
      DEBUG_ERROR();
      err = CW_ER_COMPRESS;
      goto err_exit;
    }
    comp_done = TRUE;

    fclose(file);
    blowfish_final(&bf);

    CRC32_FINAL(file_heads[i].crc);

    file_heads[i].sz.pckd = zcomp.total_out;
    msg_head.e_hdr.size += file_heads[i].sz.pckd;

    updt_progr();
  }

  /* seek to file beggining */
  if (fseek(fmsg, 0L, SEEK_SET) != 0) {
    DEBUG_ERROR();
    err = CW_ER_SEEK_FILE;
    goto err_exit;
  }

  /* set header fields */
  msg_head.e_hdr.s_time = 0;
  msg_head.i_hdr.version = CURRENT_MESSAGE_FORMAT_VERSION;
  msg_head.e_hdr.rcpt.sid = msg_head.i_hdr.rcpt.sid = sid;
  msg_head.e_hdr.rcpt.uid = msg_head.i_hdr.rcpt.uid = uid;
  msg_head.e_hdr.from.sid = msg_head.i_hdr.from.sid = cli->sid;
  msg_head.e_hdr.from.uid = msg_head.i_hdr.from.uid = cli->uid;
  msg_head.i_hdr.mk_time = time(NULL);
  msg_head.i_hdr.attach_cnt = f_cnt;

  /* get message hash */
  sha256_init(&sha256);
  sha256_update(&sha256, &msg_head.i_hdr, sizeof(msg_head.i_hdr));
  sha256_update(&sha256, &text_head, sizeof(text_head));
  if (text_sz > 0)
    sha256_update(&sha256, text, text_sz);
  if (file_heads_sz > 0)
    sha256_update(&sha256, file_heads, file_heads_sz);
  sha256_final(&sha256, hash);

  /* sign message header */
  RSAPrivateEncrypt(msg_head.sgn.data, (unsigned int *) &msg_head.sgn.len, hash, sizeof(hash), &cli->kr);

  /* init blowfish with session key */
  blowfish_init(&bf, skey, BLOWFISH_KEY_LEN, &skey[BLOWFISH_KEY_LEN]);

  /* encrypt message header part */
  blowfish_encrypt(&bf, &msg_head.sgn, &msg_head.sgn, sizeof(msg_head) -
                                                      sizeof(msg_head._e_skey) - sizeof(msg_head.arbitr_sgn) -
                                                      sizeof(msg_head.e_hdr) - sizeof(msg_head.e_skey));

  /* encrypt session key for rcpt */

  /* get random data for RSA */
  i = 1;
  R_RandomInit(&s_rnd);
  while (i != 0) {
    rnd_getbytes(tbuf, sizeof(tbuf));
    R_RandomUpdate(&s_rnd, tbuf, sizeof(tbuf));
    R_GetRandomBytesNeeded((unsigned int *) &i, &s_rnd);
  }

  /* encrypt session key with rcpts' key */
  RSAPublicEncrypt(msg_head.e_skey.data, (unsigned int *) &msg_head.e_skey.len, skey, SESSION_KEY_LEN,
                   (u_dinfo.has_cert) ? &u_dinfo.cert.ku : &u_dinfo.ku, &s_rnd);
  R_RandomFinal(&s_rnd);

  /* encrypt session key for author */

  i = 1;
  R_RandomInit(&s_rnd);
  while (i != 0) {
    rnd_getbytes(tbuf, sizeof(tbuf));
    R_RandomUpdate(&s_rnd, tbuf, sizeof(tbuf));
    R_GetRandomBytesNeeded((unsigned int *) &i, &s_rnd);
  }

  /* encrypt session key with rcpts' key */
  RSAPublicEncrypt(msg_head._e_skey.data, (unsigned int *) &msg_head._e_skey.len, skey, SESSION_KEY_LEN,
                   &cli->ku, &s_rnd);
  R_RandomFinal(&s_rnd);

  /* wipe session key */
  memset(skey, 0, sizeof(skey));

  /* arbitration signature */
  SHA256_GET_HASH(sha256, &msg_head.e_hdr, sizeof(msg_head) - sizeof(msg_head._e_skey) - sizeof(msg_head.arbitr_sgn),
                  hash);
  RSAPrivateEncrypt(msg_head.arbitr_sgn.data, (unsigned int *) &msg_head.arbitr_sgn.len, hash, sizeof(hash), &cli->kr);

  /* write message header */
  if (fwrite(&msg_head, sizeof(msg_head), 1, fmsg) != 1) {
    DEBUG_ERROR();
    err = CW_ER_WRITE_FILE;
    goto err_exit;
  }
  /* encrypt and write text header */
  blowfish_encrypt(&bf, &text_head, &text_head, sizeof(text_head));
  if (fwrite(&text_head, sizeof(text_head), 1, fmsg) != 1) {
    DEBUG_ERROR();
    err = CW_ER_WRITE_FILE;
    goto err_exit;
  }
  /* encrypt text and write to file */
  if (text_len > 0) {
    /* encrypt text */
    blowfish_encrypt(&bf, t_text, t_text, pckd_text_sz);
    /* write text */
    if (fwrite(t_text, pckd_text_sz, 1, fmsg) != 1) {
      DEBUG_ERROR();
      err = CW_ER_WRITE_FILE;
      goto err_exit;
    }
  }
  /* encrypt and write files headers */
  if (f_cnt > 0) {
    blowfish_encrypt(&bf, file_heads, file_heads, file_heads_sz);
    if (fwrite(file_heads, file_heads_sz, 1, fmsg) != 1) {
      DEBUG_ERROR();
      err = CW_ER_WRITE_FILE;
      goto err_exit;
    }
  }

  blowfish_final(&bf);

  fflush(fmsg);
  fclose(fmsg);

  if ((err = db_open(&db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = db_outbox_add(db_conn, mid, sid, uid, msg_head.e_hdr.size, fname)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = db_close(db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  updt_progr();

  err_exit:

  if (err != CW_ER_OK) {
    if (file != NULL) {
      fclose(file);
    }
    if (fmsg != NULL) {
      fclose(fmsg);
      rm_file(fpath);
    }
    if (comp_done == FALSE) {
      deflateEnd(&zcomp);
    }
  }

  if (t_text != NULL) {
    sec_free(t_text, text_sz);
  }
  if (file_heads != NULL) {
    sec_free(file_heads, file_heads_sz);
  }

  memset(tbuf, 0, sizeof(tbuf));
  memset(skey, 0, sizeof(skey));

  munlock(tbuf, sizeof(tbuf));
  munlock(buf, sizeof(buf));
  munlock(cbuf, sizeof(cbuf));
  munlock(skey, sizeof(skey));

  return err;
}

DLLEXPORT
    CWERROR

DLLCALL client_mailbox_read(CW_MSG_DESC **inbox,
                            CW_UINT32 *inbox_cnt,
                            CW_MSG_DESC **outbox,
                            CW_UINT32 *outbox_cnt,
                            CW_MSG_DESC **sent,
                            CW_UINT32 *sent_cnt,
                            CW_REPORT **reports,
                            CW_UINT32 *rep_cnt) {
  CW_DB_CONNECTION *db_conn = NULL;
  CWERROR err = CW_ER_OK;

  *inbox_cnt = *outbox_cnt = *sent_cnt = *rep_cnt = 0;

  if ((err = db_open(&db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_inbox_get_list(db_conn, inbox, inbox_cnt)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = db_outbox_get_list(db_conn, outbox, outbox_cnt)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = db_sent_get_list(db_conn, sent, sent_cnt)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = db_reports_get_list(db_conn, reports, rep_cnt)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = db_close(db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  err_exit:

  if (err != CW_ER_OK) {
    if (*inbox_cnt > 0) {
      DLL_FREE(*inbox);
    }
    if (*outbox_cnt > 0) {
      DLL_FREE(*outbox);
    }
    if (*sent_cnt > 0) {
      DLL_FREE(*sent);
    }
    if (*rep_cnt > 0) {
      DLL_FREE(*reports);
    }
  }

  return err;
}

DLLEXPORT
    CWERROR

DLLCALL client_inbox_set_read(CW_MSG_DESC *msg) {
  CW_DB_CONNECTION *db_conn = NULL;
  CWERROR err = CW_ER_OK;

  if ((err = db_open(&db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_inbox_set_read(db_conn, msg)) != CW_ER_OK) {
    db_close(db_conn);
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_close(db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  return CW_ER_OK;
}

DLLEXPORT
    CWERROR

DLLCALL client_inbox_delete(CW_MSG_DESC *msg) {
  CW_DB_CONNECTION *db_conn = NULL;
  char fpath[MAX_PATH + 1];
  CWERROR err = CW_ER_OK;

  if ((err = db_open(&db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_inbox_delete(db_conn, msg)) != CW_ER_OK) {
    db_close(db_conn);
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_close(db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  sprintf(fpath, "%s%s", cli->work_dir, msg->file);

  if ((err = rm_file(fpath)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  return CW_ER_OK;
}

DLLEXPORT
    CWERROR

DLLCALL client_outbox_delete(CW_MSG_DESC *msg) {
  CW_DB_CONNECTION *db_conn = NULL;
  char fpath[MAX_PATH + 1];
  CWERROR err = CW_ER_OK;

  if ((err = db_open(&db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_outbox_delete(db_conn, msg)) != CW_ER_OK) {
    db_close(db_conn);
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_close(db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  sprintf(fpath, "%s%s", cli->work_dir, msg->file);

  if ((err = rm_file(fpath)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  return CW_ER_OK;
}

DLLEXPORT
    CWERROR

DLLCALL client_sent_delete(CW_MSG_DESC *msg) {
  CW_DB_CONNECTION *db_conn = NULL;
  char fpath[MAX_PATH + 1];
  CWERROR err = CW_ER_OK;

  if ((err = db_open(&db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_sent_delete(db_conn, msg)) != CW_ER_OK) {
    db_close(db_conn);
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_close(db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  sprintf(fpath, "%s%s", cli->work_dir, msg->file);

  if ((err = rm_file(fpath)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  return CW_ER_OK;
}

DLLEXPORT
    CWERROR

DLLCALL client_report_delete(CW_REPORT *report) {
  CW_DB_CONNECTION *db_conn = NULL;
  CWERROR err = CW_ER_OK;

  if ((err = db_open(&db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_report_delete(db_conn, report)) != CW_ER_OK) {
    db_close(db_conn);
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_close(db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  return CW_ER_OK;
}

DLLEXPORT
    CWERROR

DLLCALL client_msgview_create(CW_MSGVIEW_HANDLE *hview,
                              CW_MSG_DESC *msg,
                              const CW_BOOL local_view) {
  CW_MSGVIEW *mview = NULL;
  BLOWFISH_CTX bf;
  SHA256_CTX sha256;
  CW_SERVER_INFO s_info;
  CW_UINT8 my_hash[SHA256_DIGEST_LEN], hash[MAX_RSA_BLOCK_LEN];
  CW_UINT32 n, text_sz = 0, file_heads_sz = 0, upckd_sz;
  char fpath[MAX_PATH + 1];
  wchar_t *t_text = NULL;
  z_stream zcomp;
  int zerr;
  CWERROR err = CW_ER_OK;

  if ((*hview = mview = sec_malloc(sizeof(CW_MSGVIEW))) == NULL) {
    DEBUG_ERROR();
    return CW_ER_MEMORY;
  }

  mview->fmsg = NULL;
  mview->text = NULL;
  mview->file_heads = NULL;
  mlock(mview->skey, sizeof(mview->skey));

  sprintf(fpath, "%s%s", cli->work_dir, msg->file);

  if ((mview->fmsg = fopen(fpath, "rb")) == NULL) {
    DEBUG_ERROR();
    return CW_ER_OPEN_FILE;
  }
  if (fread(&mview->msg_head, sizeof(mview->msg_head), 1, mview->fmsg) != 1) {
    DEBUG_ERROR();
    err = CW_ER_READ_FILE;
    goto err_exit;
  }

  if (!local_view) {
    if (mview->msg_head.e_hdr.from.sid != cli->sid) {
      if ((err = _get_server_info(&s_info, mview->msg_head.e_hdr.from.sid)) != CW_ER_OK) {
        DEBUG_ERROR();
        goto err_exit;
      }
    }

    /* check arbitration signature */
    RSAPublicDecrypt(hash, (unsigned int *) &n,
                     mview->msg_head.arbitr_sgn.data, mview->msg_head.arbitr_sgn.len,
                     (mview->msg_head.e_hdr.from.sid == cli->sid) ? &cli->serv_cert.ku : &s_info.cert.ku);
    if (n != SHA256_DIGEST_LEN) {
      DEBUG_ERROR();
      err = CW_ER_WRONG_MAIL_FILE;
      goto err_exit;
    }
    SHA256_GET_HASH(sha256, &mview->msg_head.e_hdr, sizeof(mview->msg_head) -
                                                    sizeof(mview->msg_head._e_skey) -
                                                    sizeof(mview->msg_head.arbitr_sgn), my_hash);
    if (memcmp(my_hash, hash, SHA256_DIGEST_LEN) != 0) {
      DEBUG_ERROR();
      err = CW_ER_WRONG_SIGN;
      goto err_exit;
    }
    /* decrypt session key */
    RSAPrivateDecrypt(mview->skey, (unsigned int *) &n, mview->msg_head.e_skey.data, mview->msg_head.e_skey.len,
                      &cli->kr);
  } else {
    RSAPrivateDecrypt(mview->skey, (unsigned int *) &n, mview->msg_head._e_skey.data, mview->msg_head._e_skey.len,
                      &cli->kr);
  }
  if (n != SESSION_KEY_LEN) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_MAIL_FILE;
    goto err_exit;
  }

  blowfish_init(&bf, mview->skey, BLOWFISH_KEY_LEN, &(mview->skey[BLOWFISH_KEY_LEN]));
  blowfish_decrypt(&bf, &mview->msg_head.sgn, &mview->msg_head.sgn,
                   sizeof(mview->msg_head) - sizeof(mview->msg_head._e_skey) -
                   sizeof(mview->msg_head.arbitr_sgn) - sizeof(mview->msg_head.e_hdr) -
                   sizeof(mview->msg_head.e_skey));

  if (mview->msg_head.i_hdr.version != CURRENT_MESSAGE_FORMAT_VERSION) {
    DEBUG_ERROR();
    err = CW_ER_VERSION;
    goto err_exit;
  }

  if ((mview->msg_head.i_hdr.from.sid != mview->msg_head.e_hdr.from.sid) ||
      (mview->msg_head.i_hdr.from.uid != mview->msg_head.e_hdr.from.uid) ||
      (mview->msg_head.i_hdr.rcpt.sid != mview->msg_head.e_hdr.rcpt.sid) ||
      (mview->msg_head.i_hdr.rcpt.uid != mview->msg_head.e_hdr.rcpt.uid)) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_MAIL_FILE;
    goto err_exit;
  }

  if (fread(&mview->text_head, sizeof(mview->text_head), 1, mview->fmsg) != 1) {
    DEBUG_ERROR();
    err = CW_ER_READ_FILE;
    goto err_exit;
  }
  blowfish_decrypt(&bf, &mview->text_head, &mview->text_head, sizeof(mview->text_head));

  if ((mview->text_head.sz.upckd > 0) && (mview->text_head.sz.upckd <= MAX_TEXT_IN_MAIL_LEN)) {
    text_sz = mview->text_head.sz.upckd;
    if ((mview->text = sec_malloc(text_sz + sizeof(wchar_t))) == NULL) {
      DEBUG_ERROR();
      err = CW_ER_MEMORY;
      goto err_exit;
    }
    if ((t_text = sec_malloc(mview->text_head.sz.pckd)) == NULL) {
      DEBUG_ERROR();
      err = CW_ER_MEMORY;
      goto err_exit;
    }
    if (fread(t_text, mview->text_head.sz.pckd, 1, mview->fmsg) != 1) {
      DEBUG_ERROR();
      err = CW_ER_READ_FILE;
      goto err_exit;
    }
    blowfish_decrypt(&bf, t_text, t_text, mview->text_head.sz.pckd);
    /* decompress text */
    memset(mview->text, 0, text_sz + sizeof(wchar_t));
    zcomp.zalloc = Z_NULL;
    zcomp.zfree = Z_NULL;
    zcomp.opaque = Z_NULL;
    zcomp.next_in = (Bytef *) t_text;
    zcomp.avail_in = (uInt) mview->text_head.sz.pckd;
    zcomp.next_out = (Bytef *) mview->text;
    zcomp.avail_out = (uInt) mview->text_head.sz.upckd;
    if (inflateInit(&zcomp) != Z_OK) {
      DEBUG_ERROR();
      err = CW_ER_DECOMPRESS;
      goto err_exit;
    }
    if ((zerr = inflate(&zcomp, Z_FINISH)) != Z_STREAM_END) {
      inflateEnd(&zcomp);
      DEBUG_ERROR();
      err = CW_ER_DECOMPRESS;
      goto err_exit;
    }
    if (zcomp.total_out != mview->text_head.sz.upckd) {
      inflateEnd(&zcomp);
      DEBUG_ERROR();
      err = CW_ER_DECOMPRESS;
      goto err_exit;
    }
    if (inflateEnd(&zcomp) != Z_OK) {
      DEBUG_ERROR();
      err = CW_ER_DECOMPRESS;
      goto err_exit;
    }
  }

  file_heads_sz = sizeof(CW_FILE_HEADER) * mview->msg_head.i_hdr.attach_cnt;
  if ((mview->msg_head.i_hdr.attach_cnt > 0) && (mview->msg_head.i_hdr.attach_cnt <= MAX_ATTACHED_FILES_CNT)) {
    if ((mview->file_heads = sec_malloc(file_heads_sz)) == NULL) {
      DEBUG_ERROR();
      err = CW_ER_MEMORY;
      goto err_exit;
    }
    if (fread(mview->file_heads, file_heads_sz, 1, mview->fmsg) != 1) {
      DEBUG_ERROR();
      err = CW_ER_READ_FILE;
      goto err_exit;
    }
    blowfish_decrypt(&bf, mview->file_heads, mview->file_heads, file_heads_sz);
  }

  blowfish_final(&bf);

  if (!local_view) {
    RSAPublicDecrypt(hash, (unsigned int *) &n, mview->msg_head.sgn.data, mview->msg_head.sgn.len,
                     (mview->msg_head.e_hdr.has_cert == TRUE) ? &mview->msg_head.e_hdr.u_cert.ku
                                                              : &mview->msg_head.e_hdr.u_ku);
  } else {
    RSAPublicDecrypt(hash, (unsigned int *) &n, mview->msg_head.sgn.data, mview->msg_head.sgn.len, &cli->ku);
  }
  if (n != SHA256_DIGEST_LEN) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_MAIL_FILE;
    goto err_exit;
  }

  sha256_init(&sha256);
  sha256_update(&sha256, &mview->msg_head.i_hdr, sizeof(mview->msg_head.i_hdr));
  sha256_update(&sha256, &mview->text_head, sizeof(mview->text_head));
  if (text_sz > 0)
    sha256_update(&sha256, mview->text, text_sz);
  if (mview->msg_head.i_hdr.attach_cnt > 0)
    sha256_update(&sha256, mview->file_heads, file_heads_sz);
  sha256_final(&sha256, my_hash);

  if (memcmp(my_hash, hash, SHA256_DIGEST_LEN) != 0) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_SIGN;
    goto err_exit;
  }

  err_exit:

  if (err != CW_ER_OK) {
    if (mview->fmsg != NULL) {
      fclose(mview->fmsg);
    }
    if (mview->file_heads != NULL) {
      sec_free(mview->file_heads, file_heads_sz);
    }
    if (mview->text != NULL) {
      sec_free(mview->text, text_sz + sizeof(wchar_t));
    }
    sec_free(mview, sizeof(CW_MSGVIEW));
  }

  return err;
}

DLLEXPORT
void DLLCALL
client_msgview_free(CW_MSGVIEW_HANDLE
hview)
{
CW_MSGVIEW *mview = (CW_MSGVIEW *) hview;

fclose(mview
->fmsg);

if (mview->text_head.sz.upckd > 0) {
sec_free(mview
->text, mview->text_head.sz.upckd + sizeof(wchar_t));
}
if (mview->msg_head.i_hdr.attach_cnt > 0) {
sec_free(mview
->file_heads, mview->msg_head.i_hdr.attach_cnt * sizeof(CW_FILE_HEADER));
}

sec_free(mview,
sizeof(CW_MSGVIEW));
}

DLLEXPORT
    CWERROR

DLLCALL client_msgview_qinfo(CW_MSGVIEW_HANDLE hview, CW_MSG_DATA *mdata) {
  CW_MSGVIEW *mview = (CW_MSGVIEW *) hview;
  CW_UINT32 i;

  mdata->from_sid = mview->msg_head.i_hdr.from.sid;
  mdata->from_uid = mview->msg_head.i_hdr.from.uid;
  mdata->rcpt_sid = mview->msg_head.i_hdr.rcpt.sid;
  mdata->rcpt_uid = mview->msg_head.i_hdr.rcpt.uid;
  mdata->s_time = mview->msg_head.e_hdr.s_time;
  mdata->mk_time = mview->msg_head.i_hdr.mk_time;
  mdata->size = mview->msg_head.e_hdr.size;

  if (mdata->has_cert = mview->msg_head.e_hdr.has_cert) {
    memcpy(&mdata->cert_sn, &mview->msg_head.e_hdr.u_cert.sn, sizeof(mdata->cert_sn));
  }

  if ((mdata->text_len = mview->text_head.sz.upckd / sizeof(wchar_t)) > 0) {
    mdata->text = mview->text;
  } else {
    mdata->text = NULL;
  }

  if ((mdata->files_cnt = mview->msg_head.i_hdr.attach_cnt) > 0) {
    if ((mdata->files = malloc(mdata->files_cnt * sizeof(CW_MSG_FILE_INFO))) == NULL) {
      DEBUG_ERROR();
      return CW_ER_MEMORY;
    }
  } else {
    mdata->files = NULL;
  }

  for (i = 0; i < mdata->files_cnt; i++) {
    mdata->files[i].upckd_sz = mview->file_heads[i].sz.upckd;
    mdata->files[i].pckd_sz = mview->file_heads[i].sz.pckd;
    mdata->files[i].name = mview->file_heads[i].name;
  }

  return CW_ER_OK;
}

DLLEXPORT
    CWERROR

DLLCALL client_msgview_extract(CW_MSGVIEW_HANDLE hview,
                               CW_MSG_DATA *mdata,
                               const CW_UINT32 index,
                               const char *fpath,
                               SET_PROGRESS set_progr,
                               UPDATE_PROGRESS updt_progr) {
  CW_MSGVIEW *mview = (CW_MSGVIEW *) hview;
  BLOWFISH_CTX bf;
  CRC32 crc;
  FILE *file = NULL;
  char fname[MAX_PATH];
  CW_UINT64 blck_cnt, offset_blcks;
  CW_UINT32 i, tail_sz;
  long offset, offset_tail;
  CW_UINT8 buf[FILE_BUF_SZ], cbuf[FILE_BUF_SZ];
  z_stream zcomp;
  int zerr;
  CWERROR err = CW_ER_OK;

  CRC32_INIT(crc);

  offset = sizeof(mview->msg_head) + sizeof(mview->text_head) +
           (mview->msg_head.i_hdr.attach_cnt * sizeof(CW_FILE_HEADER)) +
           mview->text_head.sz.pckd;
  if (fseek(mview->fmsg, offset, SEEK_SET) != 0) {
    DEBUG_ERROR();
    err = CW_ER_SEEK_FILE;
    goto err_exit;
  }

  for (i = 0; i < index; i++) {
    if (mview->file_heads[i].sz.pckd <= LONG_MAX) {
      offset = mview->file_heads[i].sz.pckd;
      if (fseek(mview->fmsg, offset, SEEK_CUR) != 0) {
        DEBUG_ERROR();
        err = CW_ER_SEEK_FILE;
        goto err_exit;
      }
    } else {
      offset_blcks = mview->file_heads[i].sz.pckd / LONG_MAX;
      offset_tail = mview->file_heads[i].sz.pckd % LONG_MAX;
      while (offset_blcks--) {
        if (fseek(mview->fmsg, LONG_MAX, SEEK_CUR) != 0) {
          DEBUG_ERROR();
          err = CW_ER_SEEK_FILE;
          goto err_exit;
        }
      }
      if (offset_tail > 0) {
        if (fseek(mview->fmsg, offset_tail, SEEK_CUR) != 0) {
          DEBUG_ERROR();
          err = CW_ER_SEEK_FILE;
          goto err_exit;
        }
      }
    }
  }

  /* create output file */
  sprintf(fname, "%s%s", fpath, mview->file_heads[index].name);
  if ((file = fopen(fname, "wb")) == NULL) {
    DEBUG_ERROR();
    err = CW_ER_CREATE_FILE;
    goto err_exit;
  }

  blowfish_init(&bf, mview->skey, BLOWFISH_KEY_LEN, mview->file_heads[index].siv);

  zcomp.zalloc = Z_NULL;
  zcomp.zfree = Z_NULL;
  zcomp.opaque = Z_NULL;
  zcomp.next_out = (Bytef *) buf;
  zcomp.avail_out = (uInt)
  sizeof(buf);
  if (inflateInit(&zcomp) != Z_OK) {
    DEBUG_ERROR();
    err = CW_ER_DECOMPRESS;
    goto err_exit;
  }

  blck_cnt = mview->file_heads[index].sz.pckd / sizeof(cbuf);
  tail_sz = mview->file_heads[index].sz.pckd % sizeof(cbuf);

  set_progr(blck_cnt + ((tail_sz > 0) ? 1 : 0));

  while (blck_cnt--) {
    if (fread(cbuf, sizeof(cbuf), 1, mview->fmsg) != 1) {
      DEBUG_ERROR();
      err = CW_ER_READ_FILE;
      goto err_exit;
    }
    blowfish_decrypt(&bf, cbuf, cbuf, sizeof(cbuf));
    /* decompress block*/
    zcomp.next_in = (Bytef *) cbuf;
    zcomp.avail_in = (uInt)
    sizeof(cbuf);
    while (zcomp.avail_in != 0) {
      if (zcomp.avail_out == 0) {
        zcomp.next_out = buf;
        zcomp.avail_out = (uInt)
        sizeof(buf);
        my_crc32(&crc, buf, sizeof(buf));
        if (fwrite(buf, sizeof(buf), 1, file) != 1) {
          DEBUG_ERROR();
          err = CW_ER_WRITE_FILE;
          goto err_exit;
        }
      }
      if (inflate(&zcomp, Z_NO_FLUSH) != Z_OK) {
        inflateEnd(&zcomp);
        DEBUG_ERROR();
        err = CW_ER_DECOMPRESS;
        goto err_exit;
      }
    }
    updt_progr();
  }
  if (tail_sz > 0) {
    if (fread(cbuf, tail_sz, 1, mview->fmsg) != 1) {
      DEBUG_ERROR();
      err = CW_ER_READ_FILE;
      goto err_exit;
    }
    blowfish_decrypt(&bf, cbuf, cbuf, tail_sz);
    /* decompress block*/
    zcomp.next_in = (Bytef *) cbuf;
    zcomp.avail_in = (uInt) tail_sz;
    while (zcomp.avail_in != 0) {
      if (zcomp.avail_out == 0) {
        zcomp.next_out = buf;
        zcomp.avail_out = (uInt)
        sizeof(buf);
        my_crc32(&crc, buf, sizeof(buf));
        if (fwrite(buf, sizeof(buf), 1, file) != 1) {
          DEBUG_ERROR();
          err = CW_ER_WRITE_FILE;
          goto err_exit;
        }
      }
      zerr = inflate(&zcomp, Z_NO_FLUSH);
      if ((zerr != Z_OK) && (zerr != Z_STREAM_END)) {
        inflateEnd(&zcomp);
        DEBUG_ERROR();
        err = CW_ER_DECOMPRESS;
        goto err_exit;
      }
    }
    updt_progr();
  }
  while ((zerr = inflate(&zcomp, Z_FINISH)) != Z_STREAM_END) {
    if (zerr == Z_OK) {
      zcomp.next_out = buf;
      zcomp.avail_out = (uInt)
      sizeof(buf);
      my_crc32(&crc, buf, sizeof(buf));
      if (fwrite(buf, sizeof(buf), 1, file) != 1) {
        DEBUG_ERROR();
        err = CW_ER_WRITE_FILE;
        goto err_exit;
      }
    } else {
      inflateEnd(&zcomp);
      DEBUG_ERROR();
      err = CW_ER_DECOMPRESS;
      goto err_exit;
    }
  }
  my_crc32(&crc, buf, sizeof(buf) - zcomp.avail_out);
  if (fwrite(buf, sizeof(buf) - zcomp.avail_out, 1, file) != 1) {
    DEBUG_ERROR();
    err = CW_ER_WRITE_FILE;
    goto err_exit;
  }

  if (zcomp.total_out != mview->file_heads[index].sz.upckd) {
    DEBUG_ERROR();
    err = CW_ER_DECOMPRESS;
    goto err_exit;
  }

  if (inflateEnd(&zcomp) != Z_OK) {
    DEBUG_ERROR();
    err = CW_ER_DECOMPRESS;
    goto err_exit;
  }

  blowfish_final(&bf);
  fflush(file);
  fclose(file);

  CRC32_FINAL(crc);

  if (crc != mview->file_heads[index].crc) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_HASH;
  }

  err_exit:

  if (err != CW_ER_OK) {
    if (file != NULL) {
      fclose(file);
    }
  }

  return err;
}

DLLEXPORT
void DLLCALL
client_msgview_qfinish(CW_MSG_DATA
*mdata)
{
if (mdata->files_cnt > 0) {
FREE(mdata
->files);
}
memset(mdata,
0, sizeof(CW_MSG_DATA));
}

DLLEXPORT
    CWERROR

DLLCALL client_cont_add(CW_CONTACT *cont) {
  CW_DB_CONNECTION *db_conn = NULL;
  CWERROR err = CW_ER_OK;

  if ((err = db_open(&db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_cont_add(db_conn, cont)) != CW_ER_OK) {
    db_close(db_conn);
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_close(db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  return CW_ER_OK;
}

DLLEXPORT
    CWERROR

DLLCALL client_cont_update(CW_CONTACT *cont) {
  CW_DB_CONNECTION *db_conn = NULL;
  CWERROR err = CW_ER_OK;

  if ((err = db_open(&db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_cont_update(db_conn, cont)) != CW_ER_OK) {
    db_close(db_conn);
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_close(db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  return CW_ER_OK;
}

DLLEXPORT
    CWERROR

DLLCALL client_cont_read(CW_CONTACT **cont, CW_UINT32 *cont_cnt) {
  CW_DB_CONNECTION *db_conn = NULL;
  CWERROR err = CW_ER_OK;

  if ((err = db_open(&db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_cont_get_list(db_conn, cont, cont_cnt)) != CW_ER_OK) {
    db_close(db_conn);
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_close(db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  return CW_ER_OK;
}

DLLEXPORT
    CWERROR

DLLCALL client_cont_read_by_id(CW_CONTACT *cont,
                               CW_BOOL *exists,
                               const CW_UINT32 sid,
                               const CW_UINT32 uid) {
  CW_DB_CONNECTION *db_conn = NULL;
  CWERROR err = CW_ER_OK;

  if ((err = db_open(&db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_cont_get_by_id(db_conn, cont, exists, sid, uid)) != CW_ER_OK) {
    db_close(db_conn);
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_close(db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  return CW_ER_OK;
}

DLLEXPORT
    CWERROR

DLLCALL client_cont_delete(CW_CONTACT *cont) {
  CW_DB_CONNECTION *db_conn = NULL;
  CWERROR err = CW_ER_OK;

  if ((err = db_open(&db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_cont_delete(db_conn, cont)) != CW_ER_OK) {
    db_close(db_conn);
    DEBUG_ERROR();
    return err;
  }
  if ((err = db_close(db_conn)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  return CW_ER_OK;
}

DLLEXPORT
    CWERROR

DLLCALL client_efs_cd(const CW_EFS_FILE_INFO_PACKET *fi) {
  CW_ERROR_PACKET serv_err;
  CW_PACKET_TYPE pckt_t;
  int pckt_len;
  CWERROR err = CW_ER_OK;

  pthread_mutex_lock(&cli->api_mtx);

  if ((err = packet_send_crypted(&cli->srv_pctx, &fi->fid, sizeof(fi->fid), PT_EFS_CD)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = packet_recv_crypted(&cli->srv_pctx, &serv_err, sizeof(serv_err), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_t != PT_ERROR) || (pckt_len != sizeof(serv_err))) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }
  if (serv_err.code != PE_OK) {
    DEBUG_ERROR();
    err = pterr_to_cwerr(serv_err.code);
    goto err_exit;
  }

  err_exit:

  pthread_mutex_unlock(&cli->api_mtx);

  return err;
}

DLLEXPORT
    CWERROR

DLLCALL client_efs_cdup(void) {
  CW_UINT32 tmp = QRND();
  CW_ERROR_PACKET serv_err;
  CW_PACKET_TYPE pckt_t;
  int pckt_len;
  CWERROR err = CW_ER_OK;

  pthread_mutex_lock(&cli->api_mtx);

  if ((err = packet_send_crypted(&cli->srv_pctx, &tmp, sizeof(tmp), PT_EFS_CDUP)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = packet_recv_crypted(&cli->srv_pctx, &serv_err, sizeof(serv_err), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_t != PT_ERROR) || (pckt_len != sizeof(serv_err))) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }
  if (serv_err.code != PE_OK) {
    DEBUG_ERROR();
    err = pterr_to_cwerr(serv_err.code);
    goto err_exit;
  }

  err_exit:

  pthread_mutex_unlock(&cli->api_mtx);

  return err;
}

DLLEXPORT
    CWERROR

DLLCALL client_efs_cdroot(void) {
  CW_UINT32 tmp = QRND();
  CW_ERROR_PACKET serv_err;
  CW_PACKET_TYPE pckt_t;
  int pckt_len;
  CWERROR err = CW_ER_OK;

  pthread_mutex_lock(&cli->api_mtx);

  if ((err = packet_send_crypted(&cli->srv_pctx, &tmp, sizeof(tmp), PT_EFS_CDROOT)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = packet_recv_crypted(&cli->srv_pctx, &serv_err, sizeof(serv_err), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_t != PT_ERROR) || (pckt_len != sizeof(serv_err))) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }
  if (serv_err.code != PE_OK) {
    DEBUG_ERROR();
    err = pterr_to_cwerr(serv_err.code);
    goto err_exit;
  }

  err_exit:

  pthread_mutex_unlock(&cli->api_mtx);

  return err;
}

DLLEXPORT
    CWERROR

DLLCALL client_efs_mkdir(const char *dname) {
  BLOWFISH_CTX bf;
  CW_EFS_FILE_NAME efs_n;
  CW_ERROR_PACKET serv_err;
  CW_PACKET_TYPE pckt_t;
  int pckt_len;
  CWERROR err = CW_ER_OK;

  pthread_mutex_lock(&cli->api_mtx);

  if (strcpy_s(efs_n.name, dname, sizeof(efs_n.name)) == NULL) {
    DEBUG_ERROR();
    err = CW_ER_INTERNAL;
    goto err_exit;
  }
  rnd_getbytes(efs_n.pad, sizeof(efs_n.pad));
  BLOWFISH_ENCRYPT(bf, cli->efs_key, &efs_n, sizeof(efs_n));

  if ((err = packet_send_crypted(&cli->srv_pctx, &efs_n, sizeof(efs_n), PT_EFS_MKDIR)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = packet_recv_crypted(&cli->srv_pctx, &serv_err, sizeof(serv_err), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_t != PT_ERROR) || (pckt_len != sizeof(serv_err))) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }
  if (serv_err.code != PE_OK) {
    DEBUG_ERROR();
    err = pterr_to_cwerr(serv_err.code);
    goto err_exit;
  }

  err_exit:

  pthread_mutex_unlock(&cli->api_mtx);

  return err;
}

DLLEXPORT
    CWERROR

DLLCALL client_efs_addfile(const char *fpath,
                           const CW_UINT64 fsize,
                           SET_PROGRESS set_progr,
                           UPDATE_PROGRESS updt_progr) {
  BLOWFISH_CTX bf;
  SHA256_CTX sha256;
  FILE *file = NULL;
  CW_UINT8 *buf = NULL, s_key[SESSION_KEY_LEN];
  CW_EFS_FILE_INFO_PACKET f_info;
  CW_EFS_FILE_BEGIN_HEAD b_head;
  CW_EFS_FILE_END_HEAD e_head;
  CW_PACKET_TYPE pckt_t;
  CW_ERROR_PACKET serv_err;
  int pckt_len;
  char fname[MAX_PATH + 1];
  CW_UINT32 blck_cnt, tail_sz;
  CWERROR err = CW_ER_OK;

  if (fsize > cli->max_file_sz) {
    return CW_ER_SIZE_LIMIT;
  }

  mlock(s_key, sizeof(s_key));
  mlock(&b_head, sizeof(b_head));

  pthread_mutex_lock(&cli->api_mtx);

  /* fill f_info struct */
  if (get_fname(fname, (char *) fpath) == NULL) {
    DEBUG_ERROR();
    err = CW_ER_INTERNAL;
    goto err_exit;
  }
  if (strcpy_s(f_info.fname.name, fname, sizeof(f_info.fname.name)) == NULL) {
    DEBUG_ERROR();
    err = CW_ER_INTERNAL;
    goto err_exit;
  }
  rnd_getbytes(f_info.fname.pad, sizeof(f_info.fname.pad));
  BLOWFISH_ENCRYPT(bf, cli->efs_key, &f_info.fname, sizeof(f_info.fname));
  f_info.sz = sizeof(CW_EFS_FILE_BEGIN_HEAD) + fsize + sizeof(CW_EFS_FILE_END_HEAD);

  /* fill b_head struct */
  b_head.version = CURRENT_EFS_FORMAT_VERSION;
  b_head.sz.pckd = 0;
  b_head.sz.upckd = fsize;
  rnd_getbytes(s_key, sizeof(s_key));
  memcpy(b_head.s_key, s_key, sizeof(s_key));

  /* encrypt session key with EFS key */
  BLOWFISH_ENCRYPT(bf, cli->efs_key, b_head.s_key, sizeof(b_head.s_key));

  /* send f_info */
  if ((err = packet_send_crypted(&cli->srv_pctx, &f_info, sizeof(f_info), PT_EFS_ADDFILE)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  /* receve error */
  if ((err = packet_recv_crypted(&cli->srv_pctx, &serv_err, sizeof(serv_err), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_t != PT_ERROR) || (pckt_len != sizeof(serv_err))) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }
  if (serv_err.code != PE_OK) {
    DEBUG_ERROR();
    err = pterr_to_cwerr(serv_err.code);
    goto err_exit;
  }

  /* init hash */
  sha256_init(&sha256);

  /* init blowfish with session key */
  blowfish_init(&bf, s_key, BLOWFISH_KEY_LEN, &s_key[BLOWFISH_KEY_LEN]);

  /* hash and encrypt b_head */
  sha256_update(&sha256, &b_head.version, sizeof(b_head) - sizeof(b_head.s_key));
  blowfish_encrypt(&bf, &b_head.version, &b_head.version, sizeof(b_head) - sizeof(b_head.s_key));

  /* send b_head */
  if ((err = packet_send_mixed(&cli->srv_pctx, &b_head, sizeof(b_head), PT_EFS_ADDFILE)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  if ((buf = malloc(cli->kbps)) == NULL) {
    DEBUG_ERROR();
    err = CW_ER_MEMORY;
    goto err_exit;
  }

  blck_cnt = fsize / cli->kbps;
  tail_sz = fsize % cli->kbps;

  set_progr(blck_cnt + (tail_sz ? 1 : 0));

  if ((file = fopen(fpath, "rb")) == NULL) {
    DEBUG_ERROR();
    err = CW_ER_OPEN_FILE;
    goto err_exit;
  }
  while (blck_cnt--) {
    if (fread(buf, cli->kbps, 1, file) != 1) {
      DEBUG_ERROR();
      err = CW_ER_READ_FILE;
      goto err_exit;
    }
    sha256_update(&sha256, buf, cli->kbps);
    blowfish_encrypt(&bf, buf, buf, cli->kbps);
    if ((err = packet_send_mixed(&cli->srv_pctx, buf, cli->kbps, PT_EFS_ADDFILE)) != CW_ER_OK) {
      DEBUG_ERROR();
      goto err_exit;
    }
    updt_progr();
  }
  if (tail_sz > 0) {
    if (fread(buf, tail_sz, 1, file) != 1) {
      DEBUG_ERROR();
      err = CW_ER_READ_FILE;
      goto err_exit;
    }
    sha256_update(&sha256, buf, tail_sz);
    blowfish_encrypt(&bf, buf, buf, tail_sz);
    if ((err = packet_send_mixed(&cli->srv_pctx, buf, tail_sz, PT_EFS_ADDFILE)) != CW_ER_OK) {
      DEBUG_ERROR();
      goto err_exit;
    }
    updt_progr();
  }
  fclose(file);
  FREE(buf);

  /* fill e_head struct */
  sha256_final(&sha256, e_head.hash);
  blowfish_encrypt(&bf, &e_head, &e_head, sizeof(e_head));
  blowfish_final(&bf);

  /* send e_head */
  if ((err = packet_send_mixed(&cli->srv_pctx, &e_head, sizeof(e_head), PT_EFS_ADDFILE)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  /* receve error */
  if ((err = packet_recv_crypted(&cli->srv_pctx, &serv_err, sizeof(serv_err), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_t != PT_ERROR) || (pckt_len != sizeof(serv_err))) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }
  if (serv_err.code != PE_OK) {
    DEBUG_ERROR();
    err = pterr_to_cwerr(serv_err.code);
    goto err_exit;
  }

  err_exit:

  pthread_mutex_unlock(&cli->api_mtx);

  memset(s_key, 0, sizeof(s_key));
  memset(&b_head, 0, sizeof(b_head));
  munlock(s_key, sizeof(s_key));
  munlock(&b_head, sizeof(b_head));

  if (err != CW_ER_OK) {
    if (buf != NULL) {
      FREE(buf);
    }
    if (file != NULL) {
      fclose(file);
    }
  }

  return err;
}

DLLEXPORT
    CWERROR

DLLCALL client_efs_list(CW_EFS_FILE_INFO_PACKET **list,
                        CW_UINT32 *cnt,
                        SET_PROGRESS set_progr,
                        UPDATE_PROGRESS updt_progr) {
  BLOWFISH_CTX bf;
  CW_UINT32 tmp = QRND();
  CW_LIST_HEAD_PACKET head;
  CW_EFS_FILE_INFO_PACKET *flist = NULL;
  CW_PACKET_TYPE pckt_t;
  int pckt_len;
  CW_UINT32 n, k = 0;
  CWERROR err = CW_ER_OK;

  pthread_mutex_lock(&cli->api_mtx);

  if ((err = packet_send_crypted(&cli->srv_pctx, &tmp, sizeof(tmp), PT_EFS_LIST)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = packet_recv_crypted(&cli->srv_pctx, &head, sizeof(head), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_t != PT_EFS_LIST_RESP) || (pckt_len != sizeof(head))) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }

  if (head.cnt == 0) {
    *cnt = 0;
    goto err_exit;
  }

  *cnt = n = head.cnt;
  set_progr(n);

  if ((*list = flist = DLL_MALLOC(sizeof(CW_EFS_FILE_INFO_PACKET) * n)) == NULL) {
    DEBUG_ERROR();
    err = CW_ER_MEMORY;
    goto err_exit;
  }

  while (n--) {
    if ((err = packet_recv_crypted(&cli->srv_pctx, &flist[k], sizeof(CW_EFS_FILE_INFO_PACKET), &pckt_len, &pckt_t)) !=
        CW_ER_OK) {
      DEBUG_ERROR();
      goto err_exit;
    }
    if ((pckt_t != PT_EFS_LIST_RESP) || (pckt_len != sizeof(CW_EFS_FILE_INFO_PACKET))) {
      DEBUG_ERROR();
      err = CW_ER_WRONG_PCKT;
      goto err_exit;
    }

    BLOWFISH_DECRYPT(bf, cli->efs_key, &flist[k].fname, sizeof(flist[k].fname));

    updt_progr();
    ++k;
  }

  err_exit:

  pthread_mutex_unlock(&cli->api_mtx);

  if (err != CW_ER_OK) {
    if (flist != NULL) {
      DLL_FREE(flist);
    }
  }

  return err;
}

DLLEXPORT
    CWERROR

DLLCALL client_efs_delete(const CW_EFS_FILE_INFO_PACKET *fi) {
  CW_ERROR_PACKET serv_err;
  CW_PACKET_TYPE pckt_t;
  int pckt_len;
  CWERROR err = CW_ER_OK;

  pthread_mutex_lock(&cli->api_mtx);

  if ((err = packet_send_crypted(&cli->srv_pctx, &fi->fid, sizeof(fi->fid), PT_EFS_DELETE)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = packet_recv_crypted(&cli->srv_pctx, &serv_err, sizeof(serv_err), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_t != PT_ERROR) || (pckt_len != sizeof(serv_err))) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }
  if (serv_err.code != PE_OK) {
    DEBUG_ERROR();
    err = pterr_to_cwerr(serv_err.code);
    goto err_exit;
  }

  err_exit:

  pthread_mutex_unlock(&cli->api_mtx);

  return err;
}

DLLEXPORT
    CWERROR

DLLCALL client_efs_get(const CW_EFS_FILE_INFO_PACKET *fi,
                       const char *path,
                       SET_PROGRESS set_progr,
                       UPDATE_PROGRESS updt_progr) {
  BLOWFISH_CTX bf;
  SHA256_CTX sha256;
  FILE *file = NULL;
  CW_UINT8 *buf = NULL, hash[SHA256_DIGEST_LEN];
  CW_EFS_FILE_INFO_PACKET f_info;
  CW_EFS_FILE_BEGIN_HEAD b_head;
  CW_EFS_FILE_END_HEAD e_head;
  CW_PACKET_TYPE pckt_t;
  int pckt_len;
  char fpath[MAX_PATH + 1];
  CW_UINT32 blck_cnt, tail_sz;
  CWERROR err = CW_ER_OK;

  mlock(&b_head, sizeof(b_head));

  pthread_mutex_lock(&cli->api_mtx);

  if ((err = packet_send_crypted(&cli->srv_pctx, &fi->fid, sizeof(fi->fid), PT_EFS_GET)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  /* receve f_info */
  if ((err = packet_recv_crypted(&cli->srv_pctx, &f_info, sizeof(f_info), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_t != PT_EFS_GET_RESP) || (pckt_len != sizeof(f_info))) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }
  /* decrypt file name */
  BLOWFISH_DECRYPT(bf, cli->efs_key, &f_info.fname, sizeof(f_info.fname));

  /* receve b_head */
  if ((err = packet_recv_mixed(&cli->srv_pctx, &b_head, sizeof(b_head), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_t != PT_EFS_GET_RESP) || (pckt_len != sizeof(b_head))) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }
  /* decrypt session key with EFS key */
  BLOWFISH_DECRYPT(bf, cli->efs_key, b_head.s_key, sizeof(b_head.s_key));

  /* init hash */
  sha256_init(&sha256);

  /* init blowfish with session key */
  blowfish_init(&bf, b_head.s_key, BLOWFISH_KEY_LEN, &b_head.s_key[BLOWFISH_KEY_LEN]);

  /* hash and encrypt b_head */
  blowfish_decrypt(&bf, &b_head.version, &b_head.version, sizeof(b_head) - sizeof(b_head.s_key));
  sha256_update(&sha256, &b_head.version, sizeof(b_head) - sizeof(b_head.s_key));

  if ((buf = malloc(cli->kbps)) == NULL) {
    DEBUG_ERROR();
    err = CW_ER_MEMORY;
    goto err_exit;
  }

  blck_cnt = (f_info.sz - sizeof(CW_EFS_FILE_BEGIN_HEAD) - sizeof(CW_EFS_FILE_END_HEAD)) / cli->kbps;
  tail_sz = (f_info.sz - sizeof(CW_EFS_FILE_BEGIN_HEAD) - sizeof(CW_EFS_FILE_END_HEAD)) % cli->kbps;

  set_progr(blck_cnt + (tail_sz ? 1 : 0));

  sprintf(fpath, "%s%s", path, f_info.fname.name);
  if ((file = fopen(fpath, "wb")) == NULL) {
    DEBUG_ERROR();
    err = CW_ER_OPEN_FILE;
    goto err_exit;
  }
  while (blck_cnt--) {
    if ((err = packet_recv_mixed(&cli->srv_pctx, buf, cli->kbps, &pckt_len, &pckt_t)) != CW_ER_OK) {
      DEBUG_ERROR();
      goto err_exit;
    }
    if ((pckt_t != PT_EFS_GET_RESP) || (pckt_len != cli->kbps)) {
      DEBUG_ERROR();
      err = CW_ER_WRONG_PCKT;
      goto err_exit;
    }
    blowfish_decrypt(&bf, buf, buf, cli->kbps);
    sha256_update(&sha256, buf, cli->kbps);
    if (fwrite(buf, cli->kbps, 1, file) != 1) {
      DEBUG_ERROR();
      err = CW_ER_WRITE_FILE;
      goto err_exit;
    }
    updt_progr();
  }
  if (tail_sz > 0) {
    if ((err = packet_recv_mixed(&cli->srv_pctx, buf, tail_sz, &pckt_len, &pckt_t)) != CW_ER_OK) {
      DEBUG_ERROR();
      goto err_exit;
    }
    if ((pckt_t != PT_EFS_GET_RESP) || (pckt_len != tail_sz)) {
      DEBUG_ERROR();
      err = CW_ER_WRONG_PCKT;
      goto err_exit;
    }
    blowfish_decrypt(&bf, buf, buf, tail_sz);
    sha256_update(&sha256, buf, tail_sz);
    if (fwrite(buf, tail_sz, 1, file) != 1) {
      DEBUG_ERROR();
      err = CW_ER_WRITE_FILE;
      goto err_exit;
    }
    updt_progr();
  }
  fflush(file);
  fclose(file);

  /* receve e_head */
  if ((err = packet_recv_mixed(&cli->srv_pctx, &e_head, sizeof(e_head), &pckt_len, &pckt_t)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((pckt_t != PT_EFS_GET_RESP) || (pckt_len != sizeof(e_head))) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_PCKT;
    goto err_exit;
  }
  blowfish_decrypt(&bf, &e_head, &e_head, sizeof(e_head));
  blowfish_final(&bf);

  sha256_final(&sha256, hash);

  if (memcmp(hash, e_head.hash, sizeof(hash)) != 0) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_HASH;
    goto err_exit;
  }

  err_exit:

  pthread_mutex_unlock(&cli->api_mtx);

  memset(&b_head, 0, sizeof(b_head));
  munlock(&b_head, sizeof(b_head));

  if (err != CW_ER_OK) {
    if (buf != NULL) {
      FREE(buf);
    }
    if (file != NULL) {
      fclose(file);
    }
  }

  return err;
}

static CWERROR __inline _wipe_round(FILE *file,
                                    CW_UINT8 *buf,
                                    CW_UINT64 blck_cnt,
                                    int tail_sz,
                                    UPDATE_PROGRESS updt_progr) {
  if (fseek(file, 0L, SEEK_SET) != 0) {
    DEBUG_ERROR();
    return CW_ER_WRITE_FILE;
  }

  while (blck_cnt--) {
    if (fwrite(buf, WIPE_BUF_SZ, 1, file) != 1) {
      DEBUG_ERROR();
      return CW_ER_WRITE_FILE;
    }
    updt_progr();
  }
  if (tail_sz) {
    if (fwrite(buf, tail_sz, 1, file) != 1) {
      DEBUG_ERROR();
      return CW_ER_WRITE_FILE;
    }
    updt_progr();
  }

  if (fflush(file) != 0) {
    DEBUG_ERROR();
    return CW_ER_WRITE_FILE;
  }

  return CW_ER_OK;
}

DLLEXPORT
    CWERROR

DLLCALL client_efs_wipefile(const char *fpath,
                            const CW_UINT64 fsize,
                            SET_PROGRESS set_progr,
                            UPDATE_PROGRESS updt_progr) {
  FILE *file = NULL;
  CW_UINT8 buf[WIPE_BUF_SZ];
  CW_UINT64 blck_cnt = fsize / WIPE_BUF_SZ;
  int tail_sz = fsize % WIPE_BUF_SZ;
  CW_UINT8 rnd_byte;
  CWERROR err = CW_ER_OK;

  do {
    rnd_getbytes(&rnd_byte, sizeof(CW_UINT8));
  }while ((rnd_byte == 0x00) || (rnd_byte == 0xFF));

  if ((file = fopen(fpath, "wb")) == NULL) {
    DEBUG_ERROR();
    return CW_ER_OPEN_FILE;
  }

  set_progr((blck_cnt + ((tail_sz) ? 1 : 0)) * 3);

  memset(buf, WIPE_BYTE_1, sizeof(buf));
  if ((err = _wipe_round(file, buf, blck_cnt, tail_sz, updt_progr)) != CW_ER_OK) {
    fclose(file);
    DEBUG_ERROR();
    return err;
  }
  memset(buf, WIPE_BYTE_2, sizeof(buf));
  if ((err = _wipe_round(file, buf, blck_cnt, tail_sz, updt_progr)) != CW_ER_OK) {
    fclose(file);
    DEBUG_ERROR();
    return err;
  }
  memset(buf, rnd_byte, sizeof(buf));
  if ((err = _wipe_round(file, buf, blck_cnt, tail_sz, updt_progr)) != CW_ER_OK) {
    fclose(file);
    DEBUG_ERROR();
    return err;
  }

  fclose(file);

  if ((err = rm_file(fpath)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  return CW_ER_OK;
}
