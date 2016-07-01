#ifndef _CERT_CHK_H_
#define _CERT_CHK_H_

CWERROR cert_check(const CW_CERT *cert, 
				   RSA_PUBLIC_KEY *ku,
				   const CW_CERT_TYPE chk_type);

#endif
