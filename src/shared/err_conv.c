#include "general.h"
#include "errors.h"
#include "crypto.h"
#include "cert_struct.h"
#include "packets_struct.h"

#include "err_conv.h"

CWERROR pterr_to_cwerr(const CW_PE_CODE err) {
  CWERROR res;

  switch (err) {
    case PE_OK:
      res = CW_ER_OK;
      break;
    case PE_VERSION:
      res = CW_ER_VERSION;
      break;
    case PE_LOCKED:
      res = CW_ER_LOCKED;
      break;
    case PE_CERT_VERSION:
      res = CW_ER_WRONG_CERT_VERSION;
      break;
    case PE_WRONG_CERT:
      res = CW_ER_WRONG_CERT;
      break;
    case PE_CERT_TIMEOUT:
      res = CW_ER_CERT_TIMEOUT;
      break;
    case PE_PCKT_CONTENT:
      res = CW_ER_WRONG_PCKT;
      break;
    case PE_REG_USER_EXISTS:
      res = CW_ER_USER_EXISTS;
      break;
    case PE_NO_QUERIED_INFO:
      res = CW_ER_NO_QUERIED_INFO;
      break;
    case PE_SIZE_LIMIT:
      res = CW_ER_SIZE_LIMIT;
      break;
    case PE_QUOTA:
      res = CW_ER_QUOTA;
      break;
    case PE_EFS:
      res = CW_ER_EFS;
      break;
    default:
      res = CW_ER_INTERNAL;
      break;
  }

  return res;
}

CW_PE_CODE cwerr_to_pterr(const CWERROR err) {
  CW_PE_CODE res;

  switch (err) {
    case CW_ER_OK:
      res = PE_OK;
      break;
    case CW_ER_VERSION:
      res = PE_VERSION;
      break;
    case CW_ER_LOCKED:
      res = PE_LOCKED;
      break;
    case CW_ER_WRONG_CERT_VERSION:
      res = PE_CERT_VERSION;
      break;
    case CW_ER_WRONG_CERT:
      res = PE_WRONG_CERT;
      break;
    case CW_ER_CERT_TIMEOUT:
      res = PE_CERT_TIMEOUT;
      break;
    case CW_ER_WRONG_PCKT:
      res = PE_PCKT_CONTENT;
      break;
    case CW_ER_USER_EXISTS:
      res = PE_REG_USER_EXISTS;
      break;
    case CW_ER_NO_QUERIED_INFO:
      res = PE_NO_QUERIED_INFO;
      break;
    case CW_ER_QUOTA:
      res = PE_QUOTA;
      break;
    case CW_ER_SIZE_LIMIT:
      res = PE_SIZE_LIMIT;
      break;
    case CW_ER_EFS:
      res = PE_EFS;
      break;
    default:
      res = PE_INTERNAL;
      break;
  }

  return res;
}
