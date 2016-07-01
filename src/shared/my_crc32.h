#ifndef _CRC32_H_
#define _CRC32_H_

typedef unsigned long CRC32;

#define CRC32_INIT(crc)   (crc) = 0xFFFFFFFFUL
#define CRC32_FINAL(crc)  (crc) ^= 0xFFFFFFFFUL

void my_crc32(CRC32 *crc, const void *buf, const unsigned long len);

#endif
