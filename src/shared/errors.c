#include "errors.h"

static const char *err_tbl[] = {
    "no error",
    "wrong version",
    "unknown internal error",
    /*---*/
    "not enaugh memory",
    /*---*/
    "wrong configuration file",
    /*---*/
    "can not create file",
    "can not open file",
    "can not read data from file",
    "can not write data to file",
    "can not seek file position",
    "can not change current directory",
    "can not delete file",
    /*---*/
    "wrong mail file structure",
    "wrong public key file structure",
    "wrong private key file structure",
    /*---*/
    "socket error",
    "wrong packet content",
    "wrong packet HMAC",
    "can not send() data",
    "can not recv() data",
    "recv() timeout",
    "not all data sent",
    /*---*/
    "wrong certificate version",
    "wrong public key version",
    "wrong private key version",
    "wrong certifcate",
    "certificate is expired",
    "wrong signature",
    "wrong checksum",
    "can not generate RSA keypair",
    /*---*/
    "can not create thread",
    /*---*/
    "shared list is corrupted",
    /*---*/
    "connection to server is denied",
    "message or file size overrides server limit",
    "inbox is full",
    "wrong IP address",
    "no queried information",
    "server or user is locked",
    "no recepienist",
    "user with specified registration information already exists",
    "user already has certificate",
    "can not create certificate",
    "maximum number of incoming connections",
    "maximum number of outcoming connections",
    "can not open database",
    "can not close database",
    "can not query database",
    "administrator command from simple user",
    /*---*/
    "can not compress data",
    "can not decompress data",
    /*---*/
    "proxy error",
    /*---*/
    "random seed generator error",
    /*---*/
    "EFS error"
};

const char *err2str(const CWERROR err) {
  return err_tbl[err];
}
