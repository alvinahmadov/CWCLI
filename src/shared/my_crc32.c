#include "general.h"

#include "crc32.inc"
#include "my_crc32.h"

void my_crc32(CRC32 *crc, const void *buf, const unsigned long len)
{
	register unsigned char *pb = (unsigned char *)buf;
	register unsigned long r = *crc, n = len;

	while (n--)
		r = (r >> 8) ^ crc_table[*pb++ ^ (r & 0x000000FFUL)];
}
